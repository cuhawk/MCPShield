"""Default-deny tool authorization using already-verified OAuth scopes."""

from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Denied(ValueError):
    pass


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scopes: set[str] = Field(default_factory=set)
    tier: str = "read"
    arguments: dict = Field(default_factory=lambda: {"type": "object"})
    untrusted_output: bool = False

    @field_validator("tier")
    @classmethod
    def valid_tier(cls, value):
        if value not in {"read", "write", "privileged"}:
            raise ValueError("unknown capability tier")
        return value

    @field_validator("arguments")
    @classmethod
    def valid_schema(cls, value):
        Draft202012Validator.check_schema(value)
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if "$ref" in item or "$dynamicRef" in item:
                    raise ValueError("schema references are unsupported")
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        return value


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: dict[str, ToolPolicy]
    deny: list[str] = Field(default_factory=list)

    @classmethod
    def load(cls, path):
        return cls.model_validate(yaml.safe_load(Path(path).read_text()))

    def rule(self, name):
        if name not in self.tools or any(fnmatchcase(name, p) for p in self.deny):
            raise Denied("tool is not permitted")
        return self.tools[name]

    def authorize(self, name, arguments, scopes):
        rule = self.rule(name)
        required = rule.scopes | ({f"mcp:{rule.tier}"} if rule.tier != "read" else set())
        if not required <= scopes:
            raise Denied("insufficient scope")
        if not isinstance(arguments, dict) or not Draft202012Validator(
            rule.arguments
        ).is_valid(arguments):
            raise Denied("invalid tool arguments")
        for value in strings(arguments):
            decoded = value
            for _ in range(8):
                next_value = unquote(decoded)
                if next_value == decoded:
                    break
                decoded = next_value
            else:
                raise Denied("excessive argument encoding")
            if ".." in decoded.replace(chr(92), "/").split("/") or chr(0) in decoded:
                raise Denied("unsafe path segment")
        return rule, frozenset(required)


def strings(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
