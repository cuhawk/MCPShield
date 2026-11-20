"""Rank policy-filtered MCP tool schemas for inclusion in the model context."""

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from heapq import nsmallest
from math import log1p

_CAMEL_CASE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_WORD = re.compile(r"[^\W_]+")
_K1 = 1.2
_B = 0.75
_TAG_WEIGHT = 2.0


def _tokens(text):
    return _WORD.findall(_CAMEL_CASE.sub(" ", text).casefold())


def _schema_terms(schema):
    pending = [schema]
    words = []
    tags = set()
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for field in ("title", "description"):
                if isinstance(item.get(field), str):
                    words.extend(_tokens(item[field]))
            labels = item.get("x-tags")
            if isinstance(labels, list):
                for tag in labels:
                    if isinstance(tag, str):
                        tags.update(_tokens(tag))
            properties = item.get("properties")
            if isinstance(properties, dict):
                for name in properties:
                    words.extend(_tokens(name))
                pending.extend(properties.values())
            for key in ("items", "additionalProperties", "oneOf", "anyOf", "allOf"):
                pending.append(item.get(key))
        elif isinstance(item, list):
            pending.extend(item)
    return words, tags


class ToolPruner:
    """Index an MCP tools/list snapshot and select a dynamic top-k for each query."""

    def __init__(self, tools: Iterable[Mapping]):
        self._entries = {}
        document_frequency = Counter()
        total_length = 0
        for tool in tools:
            name = tool["name"]
            if not isinstance(name, str) or not name or name in self._entries:
                raise ValueError("tools must have unique nonempty names")
            words, tags = _schema_terms(tool.get("inputSchema"))
            description = tool.get("description")
            if isinstance(description, str):
                words.extend(_tokens(description))
            words.extend(_tokens(name))
            counts = Counter(words)
            length = len(words)
            self._entries[name] = (tool, counts, tags, length)
            document_frequency.update(counts.keys() | tags)
            total_length += length
        count = len(self._entries)
        self._average_length = (total_length / max(1, count)) or 1
        self._idf = {
            term: log1p((count - frequency + 0.5) / (frequency + 0.5))
            for term, frequency in document_frequency.items()
        }

    def select(self, query: str, k: int) -> list[Mapping]:
        """Rank by BM25 plus IDF-weighted schema tags, breaking ties by tool name."""
        if type(k) is not int or k < 0:
            raise ValueError("k must be a non-negative integer")
        terms = sorted(set(_tokens(query)) & self._idf.keys())

        def rank(name):
            _, counts, tags, length = self._entries[name]
            normalization = _K1 * (1 - _B + _B * length / self._average_length)
            score = 0.0
            for term in terms:
                tf = counts[term]
                weight = tf * (_K1 + 1) / (tf + normalization)
                score += self._idf[term] * (weight + _TAG_WEIGHT * (term in tags))
            return -score, name

        return [self._entries[name][0] for name in nsmallest(k, self._entries, key=rank)]
