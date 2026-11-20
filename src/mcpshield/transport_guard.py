"""Validation and resource limits for Streamable HTTP."""

import re
from ipaddress import IPv6Address
from urllib.parse import urlsplit

import httpx

MAX_MESSAGE = 1024 * 1024
PROTOCOL_HEADER = "MCP-Protocol-Version"
LEGACY_VERSION = "2025-03-26"
SUPPORTED_VERSIONS = frozenset({LEGACY_VERSION, "2025-06-18", "2025-11-25"})
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]")
CREDENTIAL_HEADERS = ("Authorization", "Cookie", "X-API-Key")
DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", re.ASCII
)


class TransportViolation(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def authority(value):
    value = value.lower()
    if value.startswith("["):
        host, bracket, suffix = value[1:].partition("]")
        if not bracket or "%" in host or (suffix and not suffix.startswith(":")):
            raise ValueError("invalid IPv6 authority")
        host = f"[{IPv6Address(host)}]"
        port = suffix[1:] if suffix else None
    else:
        host, colon, port = value.partition(":")
        if len(host) > 253 or not DNS_NAME.fullmatch(host):
            raise ValueError("invalid host")
        port = port if colon else None
    if port is not None and (
        not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535
    ):
        raise ValueError("invalid port")
    return host, int(port) if port is not None else None


def origin(value):
    if not re.fullmatch(r"https?://[^/?#\s]+", value, re.IGNORECASE | re.ASCII):
        raise ValueError("invalid origin")
    parsed = urlsplit(value)
    host, port = authority(parsed.netloc)
    return parsed.scheme, host, port or (443 if parsed.scheme == "https" else 80)


def validate_version(version):
    if not isinstance(version, str) or version not in SUPPORTED_VERSIONS:
        raise TransportViolation("Unsupported MCP protocol version")
    return version


class TransportGuard:
    def __init__(self, *, allowed_hosts=LOOPBACK_HOSTS, allowed_origins=(), max_batch_size=16):
        if type(max_batch_size) is not int or max_batch_size < 1:
            raise ValueError("max_batch_size must be a positive integer")
        self.allowed_hosts = frozenset(map(authority, allowed_hosts))
        self.allowed_origins = frozenset(map(origin, allowed_origins))
        self.max_batch_size = max_batch_size

    def validate_headers(self, headers, negotiated_version=None):
        hosts = headers.getlist("host")
        origins = headers.getlist("origin")
        try:
            if len(hosts) != 1 or authority(hosts[0]) not in self.allowed_hosts:
                raise ValueError("host is not allowlisted")
            if len(origins) > 1 or (origins and origin(origins[0]) not in self.allowed_origins):
                raise ValueError("origin is not allowlisted")
        except ValueError as exc:
            raise TransportViolation("Invalid Host or Origin", 403) from exc
        versions = headers.getlist(PROTOCOL_HEADER)
        if len(versions) > 1:
            raise TransportViolation("Multiple MCP protocol versions")
        version = validate_version(versions[0]) if versions else negotiated_version or LEGACY_VERSION
        if negotiated_version is not None and version != negotiated_version:
            raise TransportViolation("MCP protocol version differs from negotiated version")
        return version

    def validate_batch(self, message, version):
        if not isinstance(message, list):
            return
        if len(message) > self.max_batch_size:
            raise TransportViolation("JSON-RPC batch exceeds limit", 413)
        if not message or version != LEGACY_VERSION:
            raise TransportViolation("JSON-RPC batch is invalid for this protocol version")


def guard_redirect(previous, following):
    """Strip credentials on every cross-origin hop and reject unsafe destinations."""
    source, target = previous.url, following.url
    if (target.scheme not in {"http", "https"} or not target.host
            or target.userinfo or (source.scheme == "https" and target.scheme != "https")):
        raise TransportViolation("Unsafe HTTP redirect")
    if (source.scheme, source.host, source.port) != (target.scheme, target.host, target.port):
        for header in CREDENTIAL_HEADERS:
            following.headers.pop(header, None)
    else:
        # HTTPX may repopulate Cookie from its jar when it builds a redirect.
        following.headers.pop("Cookie", None)
        if "Cookie" in previous.headers:
            following.headers["Cookie"] = previous.headers["Cookie"]


async def bounded_chunks(response, max_response_bytes):
    # Identity encoding avoids decompression allocating before the cap is checked.
    if response.headers.get("content-encoding", "identity").lower() != "identity":
        raise TransportViolation("Unsupported upstream content encoding")
    remaining = max_response_bytes
    try:
        # HTTPX mock transports and custom transports can return preloaded bodies.
        if response.is_stream_consumed:
            if len(response.content) > remaining:
                raise TransportViolation("Upstream response exceeds byte limit")
            yield response.content
            return
        async for chunk in response.aiter_raw():
            remaining -= len(chunk)
            if remaining < 0:
                raise TransportViolation("Upstream response exceeds byte limit")
            yield chunk
    except httpx.StreamError as exc:
        raise TransportViolation("Invalid upstream response stream") from exc
