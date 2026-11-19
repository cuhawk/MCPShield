import asyncio
import json
import sys

import httpx

from mcpshield.policy import Policy
from mcpshield.proxy import HTTPUpstream, Proxy, StdioUpstream

PING = {"jsonrpc": "2.0", "method": "ping", "id": 1}


def test_stdio_subprocess(monkeypatch):
    monkeypatch.setenv("MCPSHIELD_CANARIES", "test-only-canary")

    async def run():
        code = """
import json, os, sys
for line in sys.stdin:
    message = json.loads(line)
    reply = {"jsonrpc": "2.0", "id": message["id"],
             "result": {"private_env": "MCPSHIELD_CANARIES" in os.environ}}
    print(json.dumps(reply), flush=True)
"""
        transport = await StdioUpstream.spawn([sys.executable, "-u", "-c", code])
        try:
            result = await Proxy(Policy(tools={}), transport).handle(PING)
            assert result["result"] == {"private_env": False}
        finally:
            await transport.close()

    asyncio.run(run())


def test_http_upstream_stream(monkeypatch):
    original = httpx.AsyncClient
    captured = []

    class Chunks(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in (b": comment\r", b"\n\r\n", b"data: {",
                          b'"jsonrpc":"2.0","id":1,"result":{}}\r\n\r', b"\n"):
                yield chunk

    def handler(request):
        captured.append(request)
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"},
                              stream=Chunks())

    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))

    async def token(scopes):
        assert scopes == {"read"}
        return "scoped-token"

    transport = HTTPUpstream("https://upstream.example/mcp", token)
    assert asyncio.run(transport(PING, {"read"}))["result"] == {}
    assert captured[0].headers["Authorization"] == "Bearer scoped-token"
    assert json.loads(captured[0].content) == PING
