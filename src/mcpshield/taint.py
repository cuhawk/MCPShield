"""Conservative session taint tracking and literal canary detection."""

import re
import unicodedata
from urllib.parse import unquote

from .policy import Denied, strings

INSTRUCTIONS = re.compile(
    r"<\s*/?\s*(?:important|system|developer)\b|"
    r"\b(?:ignore|override|disregard)\b.{0,60}\b(?:instructions?|policy|rules)\b|"
    r"\b(?:send|upload|reveal|exfiltrate)\b.{0,60}\b(?:secret|token|credential|password)s?\b",
    re.I | re.S,
)


def normalize(value):
    return unicodedata.normalize("NFKC", unquote(value)).casefold()


class SessionTaint:
    def __init__(self, canaries=()):
        self.canaries = tuple(normalize(x) for x in canaries if x)
        self.untrusted = False

    def check_canaries(self, payload):
        contents = (normalize(x) for x in strings(payload))
        if any(secret in value for value in contents for secret in self.canaries):
            raise Denied("canary detected")

    def observe(self, payload, untrusted=False):
        self.untrusted |= untrusted or any(
            INSTRUCTIONS.search(normalize(x)) for x in strings(payload)
        )
        self.check_canaries(payload)
        if any(INSTRUCTIONS.search(normalize(x)) for x in strings(payload)):
            raise Denied("instructional content detected")

    def check_call(self, arguments, tier):
        self.check_canaries(arguments)
        if tier != "read" and self.untrusted:
            raise Denied("side effect blocked in tainted session")
