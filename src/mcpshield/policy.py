"""Default-deny tool authorization using already-verified OAuth scopes."""

import asyncio
import logging
from contextlib import asynccontextmanager
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
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
        seen = set()
        while pending:
            item = pending.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
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
        return cls.parse(Path(path).read_bytes())

    @classmethod
    def parse(cls, content):
        return cls.model_validate(yaml.safe_load(content))

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


class PolicyReloader:
    """One watcher publishes snapshots. Requests read the current reference directly."""

    def __init__(self, path):
        self.path = Path(path)
        self._content = self.path.read_bytes()
        self._current = Policy.parse(self._content)
        self._last_read_error = None
        self._reloading = False

    @property
    def current(self):
        return self._current

    def _candidate(self):
        content = self.path.read_bytes()
        if content == self._content:
            return None
        try:
            return content, Policy.parse(content), None
        except (ValueError, TypeError, SchemaError, yaml.YAMLError, RecursionError) as exc:
            return content, None, exc

    async def reload(self):
        """Check for an update from the watcher task and publish only a validated policy."""
        if self._reloading:
            return False
        self._reloading = True
        logger = logging.getLogger(__name__)
        try:
            candidate = await asyncio.to_thread(self._candidate)
        except OSError as exc:
            if str(exc) != self._last_read_error:
                self._last_read_error = str(exc)
                logger.warning("Policy reload failed for %s: %s", self.path, exc)
            return False
        finally:
            self._reloading = False

        self._last_read_error = None
        if candidate is None:
            return False
        self._content, policy, error = candidate
        if error is not None:
            logger.warning("Policy reload rejected for %s: %s", self.path, error)
            return False
        self._current = policy
        return True

    @asynccontextmanager
    async def watch(self, interval):
        async def poll():
            while True:
                await self.reload()
                await asyncio.sleep(interval)

        task = asyncio.create_task(poll())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


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
