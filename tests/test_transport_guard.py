import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from mcpshield.policy import Policy
from mcpshield.proxy import HTTPUpstream, Proxy, http_app
from mcpshield.transport_guard import PROTOCOL_HEADER, TransportGuard, guard_redirect

PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
AUTH = {"Authorization": "Bearer test"}
VERSION = "2025-11-25"


def rpc_reply(message, **result):
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


@pytest.fixture
def endpoint():
    calls = []

    async def verify(token):
        return set() if token == "test" else None

    async def upstream(message, scopes):
        calls.append(message)
        if "id" in message:
            return rpc_reply(message)

    guard = TransportGuard(
        allowed_hosts=("shield.example:8443", "[::1]:8443"),
        allowed_origins=("https://client.example",), max_batch_size=2,
    )
    app = http_app(Proxy(Policy(tools={}), upstream), verify, guard=guard)
    with TestClient(app, base_url="https://shield.example:8443") as client:
        yield client, calls


@pytest.mark.parametrize("headers", [
    [("Host", "shield.example")],
    [("Host", "other.example:8443")],
    [("Host", "shield.example:8443"), ("Host", "shield.example:8443")],
    [("Origin", "null")],
    [("Origin", "https://client.example/path")],
    [("Origin", "https://client.example:444")],
    [("Origin", "http://client.example")],
    [("Origin", "https://other.example")],
    [("Origin", "https://client.example"), ("Origin", "https://client.example")],
])
def test_non_allowlisted_or_ambiguous_headers(endpoint, headers):
    client, calls = endpoint
    assert client.post("/mcp", json=PING, headers=[*AUTH.items(), *headers]).status_code == 403
    assert calls == []


@pytest.mark.parametrize("headers", [
    {},
    {"Host": "SHIELD.EXAMPLE:8443", "Origin": "HTTPS://CLIENT.EXAMPLE:443"},
    {"Host": "[0:0:0:0:0:0:0:1]:8443"},
])
def test_valid_authorities(endpoint, headers):
    client, calls = endpoint
    assert client.post("/mcp", json=PING, headers=AUTH | headers).status_code == 200
    assert len(calls) == 1


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_unsupported_streamable_methods_still_validate_origin(endpoint, method):
    client, calls = endpoint
    assert client.request(method, "/mcp", headers={"Origin": "https://other.example"}).status_code == 403
    assert client.request(method, "/mcp").status_code == 405
    assert calls == []


@pytest.mark.parametrize("versions", [[""], ["2020-01-01"], [VERSION, VERSION]])
def test_invalid_version_headers(endpoint, versions):
    client, calls = endpoint
    headers = [*AUTH.items(), *((PROTOCOL_HEADER, value) for value in versions)]
    assert client.post("/mcp", json=PING, headers=headers).status_code == 400
    assert calls == []


def test_batch_limits_and_notifications(endpoint):
    client, calls = endpoint
    notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert client.post("/mcp", json=[PING] * 3, headers=AUTH).status_code == 413
    assert client.post("/mcp", json=[], headers=AUTH).status_code == 400
    assert client.post("/mcp", json=[PING], headers=AUTH | {
        PROTOCOL_HEADER: VERSION,
    }).status_code == 400
    assert calls == []
    reply = client.post("/mcp", json=[PING, notification], headers=AUTH)
    assert reply.json() == [rpc_reply(PING)]
    assert len(calls) == 2
    assert client.post("/mcp", json=[notification], headers=AUTH).status_code == 202


def mock_upstream(monkeypatch, handler):
    client_type = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_type(
        transport=httpx.MockTransport(handler), **kwargs
    ))


def test_redirect_strips_credentials_on_cross_origin_and_keeps_body(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        redirects = {
            "/mcp": "/same",
            "/same": "https://other.example/remote",
            "/remote": "/done",
        }
        if request.url.path in redirects:
            return httpx.Response(307, headers={
                "Location": redirects[request.url.path], "Set-Cookie": "session=test",
            })
        return httpx.Response(200, json=rpc_reply(PING))

    mock_upstream(monkeypatch, handler)

    async def token(scopes):
        return "test"

    proxy = Proxy(Policy(tools={}), HTTPUpstream("https://upstream.example/mcp", token))
    assert asyncio.run(proxy.handle(PING)) == rpc_reply(PING)
    assert len(requests) == 4
    assert [r.headers.get("Authorization") for r in requests] == [
        "Bearer test", "Bearer test", None, None,
    ]
    assert all("Cookie" not in request.headers for request in requests)
    assert all(json.loads(request.content)["method"] == "ping" for request in requests)


@pytest.mark.parametrize(("target", "kept"), [
    ("https://upstream.example/next", True),
    ("https://other.example/next", False),
    ("https://upstream.example:8443/next", False),
])
def test_redirect_credential_headers(target, kept):
    sensitive = {"AUTHORIZATION": "test", "cookie": "a=b", "X-Api-Key": "test"}
    previous = httpx.Request("POST", "https://upstream.example/mcp", headers=sensitive)
    following = httpx.Request("POST", target, headers=sensitive | {"Accept": "application/json"})
    guard_redirect(previous, following)
    assert all((name in following.headers) == kept for name in sensitive)
    assert following.headers["Accept"] == "application/json"


def test_redirect_downgrade_does_not_send_followup(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(308, headers={"Location": "http://upstream.example/next"})

    mock_upstream(monkeypatch, handler)
    proxy = Proxy(Policy(tools={}), HTTPUpstream("https://upstream.example/mcp"))
    assert asyncio.run(proxy.handle(PING))["error"]["code"] == -32002
    assert len(requests) == 1


class Chunks(httpx.AsyncByteStream):
    def __init__(self, parts):
        self.parts = parts
        self.read = 0
        self.closed = False

    async def __aiter__(self):
        for part in self.parts:
            self.read += 1
            yield part

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize("sse", [False, True])
@pytest.mark.parametrize("over_limit", [False, True])
def test_stream_cap_is_cumulative_and_closes_response(monkeypatch, sse, over_limit):
    data = json.dumps(rpc_reply(PING)).encode()
    parts = [data[:6], data[6:]]
    if sse:
        parts = [b": first\r\n\r\n", b": second\n\n", b"data: " + data + b"\n\n"]
    cap = sum(map(len, parts)) - over_limit
    chunks = Chunks([*parts, b"unread"] if over_limit else parts)
    mock_upstream(monkeypatch, lambda request: httpx.Response(
        200, stream=chunks, headers={
            "Content-Type": "text/event-stream" if sse else "application/json",
        },
    ))
    transport = HTTPUpstream("https://upstream.example/mcp", max_response_bytes=cap)
    result = asyncio.run(Proxy(Policy(tools={}), transport).handle(PING))
    if over_limit:
        assert result["error"]["code"] == -32002
    else:
        assert result == rpc_reply(PING)
    assert chunks.read == len(parts)
    assert chunks.closed


def test_compressed_response_is_rejected_before_read(monkeypatch):
    chunks = Chunks([b"unused"])
    mock_upstream(monkeypatch, lambda request: httpx.Response(
        200, stream=chunks, headers={"Content-Encoding": "gzip"},
    ))
    proxy = Proxy(Policy(tools={}), HTTPUpstream("https://upstream.example/mcp"))
    assert asyncio.run(proxy.handle(PING))["error"]["code"] == -32002
    assert chunks.read == 0
    assert chunks.closed


@pytest.mark.parametrize("selected", [VERSION, "2020-01-01", None])
def test_protocol_negotiation(monkeypatch, selected):
    requests = []

    def handler(request):
        requests.append(request)
        message = json.loads(request.content)
        result = {"protocolVersion": selected} if message["method"] == "initialize" else {}
        return httpx.Response(200, json=rpc_reply(message, **result))

    mock_upstream(monkeypatch, handler)

    async def verify(token):
        return set()

    app = http_app(Proxy(Policy(tools={}), HTTPUpstream("https://upstream.example/mcp")), verify)
    initialize = PING | {"method": "initialize", "params": {"protocolVersion": "2025-06-18"}}
    with TestClient(app, base_url="http://localhost") as client:
        invalid = initialize | {"params": {"protocolVersion": ""}}
        assert client.post("/mcp", json=invalid, headers=AUTH).status_code == 400
        assert requests == []
        assert client.post("/mcp", json=PING, headers=AUTH | {
            PROTOCOL_HEADER: "2025-06-18",
        }).json() == rpc_reply(PING)
        assert requests.pop().headers[PROTOCOL_HEADER] == "2025-06-18"
        response = client.post("/mcp", json=initialize, headers=AUTH)
        assert PROTOCOL_HEADER not in requests[0].headers
        if selected != VERSION:
            assert response.json()["error"]["code"] == -32002
            return
        assert response.json()["result"]["protocolVersion"] == VERSION
        assert client.post("/mcp", json=PING, headers=AUTH | {
            PROTOCOL_HEADER: "2025-06-18",
        }).status_code == 400
        assert len(requests) == 1
        assert client.post("/mcp", json=PING, headers=AUTH | {
            PROTOCOL_HEADER: VERSION,
        }).json() == rpc_reply(PING)
        assert requests[-1].headers[PROTOCOL_HEADER] == VERSION
