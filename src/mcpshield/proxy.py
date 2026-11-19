"""Intercept MCP requests before they reach a configured upstream."""

import asyncio
import json
import sys

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .policy import Denied
from .taint import SessionTaint
from .telemetry import Audit

MAX_MESSAGE = 1024 * 1024
METHODS = {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call"}


class UpstreamError(Exception):
    pass


def error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


class Proxy:
    def __init__(self, policy, upstream, canaries=(), audit=None):
        self.policy = policy
        self.upstream = upstream
        self.taint = SessionTaint(canaries)
        self.audit = audit or Audit()
        self.lock = asyncio.Lock()

    async def handle(self, message, scopes=frozenset()):
        if not isinstance(message, dict):
            return error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if (message.get("jsonrpc") != "2.0" or not isinstance(method, str)
                or not isinstance(params, dict)
                or type(request_id) not in {str, int, type(None)}):
            return error(None, -32600, "Invalid Request")
        notification = "id" not in message
        async with self.lock:
            try:
                if method not in METHODS:
                    raise Denied("method is not permitted")
                if notification and method != "notifications/initialized":
                    raise Denied("notification is not permitted")
                rule = None
                attenuated = frozenset()
                if method == "tools/call":
                    name = params.get("name")
                    if not isinstance(name, str):
                        raise Denied("tool name is required")
                    arguments = params.get("arguments", {})
                    rule, attenuated = self.policy.authorize(name, arguments, scopes)
                    self.taint.check_call(arguments, rule.tier)
                outbound = {"jsonrpc": "2.0", "method": method, "params": params}
                if not notification:
                    outbound["id"] = request_id
                self.taint.check_canaries(outbound)
                reply = await asyncio.wait_for(self.upstream(outbound, attenuated), 30)
                if notification:
                    return None
                if not isinstance(reply, dict) or reply.get("id") != request_id:
                    raise UpstreamError
                if method == "tools/list" and isinstance(reply.get("result"), dict):
                    result = reply["result"]
                    tools = []
                    for tool in result.get("tools", []):
                        try:
                            self.policy.authorize(
                                tool["name"], {}, scopes
                            )
                        except Denied as exc:
                            if str(exc) != "invalid tool arguments":
                                continue
                        tools.append(tool)
                    result["tools"] = tools
                self.taint.observe(reply, rule is not None and rule.untrusted_output)
                self.audit.record("allowed")
                return reply
            except Denied as exc:
                self.audit.record("denied")
                return None if notification else error(request_id, -32001, str(exc))
            except (ValueError, KeyError, TypeError, OSError, TimeoutError,
                    httpx.HTTPError, UpstreamError):
                self.audit.record("upstream_error")
                return None if notification else error(request_id, -32002, "Upstream failure")


class HTTPUpstream:
    def __init__(self, url, token_for_scopes=None):
        self.url = url
        self.token_for_scopes = token_for_scopes

    async def __call__(self, message, scopes):
        headers = {"Accept": "application/json, text/event-stream"}
        if self.token_for_scopes is not None:
            headers["Authorization"] = f"Bearer {await self.token_for_scopes(scopes)}"
        async with httpx.AsyncClient(trust_env=False) as client:
            async with client.stream("POST", self.url, json=message, headers=headers) as reply:
                reply.raise_for_status()
                if reply.status_code == 202:
                    return None
                body = bytearray()
                sse = "text/event-stream" in reply.headers.get("content-type", "")
                async for chunk in reply.aiter_bytes():
                    body.extend(chunk.replace(b"\r\n", b"\n") if sse else chunk)
                    if len(body) > MAX_MESSAGE:
                        raise UpstreamError
                    while sse and b"\n\n" in body:
                        frame, _, remainder = body.partition(b"\n\n")
                        body = bytearray(remainder)
                        data = b"\n".join(line[5:].lstrip(b" ") for line in frame.splitlines()
                                          if line.startswith(b"data:"))
                        if data:
                            event = json.loads(data)
                            if isinstance(event, dict) and event.get("id") == message.get("id"):
                                return event
                if sse:
                    raise UpstreamError
                return json.loads(body)


def http_app(proxy, verify_bearer):
    app = FastAPI()

    @app.post("/mcp")
    async def serve(request: Request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        scopes = await verify_bearer(token) if scheme.lower() == "bearer" and token else None
        if scopes is None:
            return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_MESSAGE:
                return Response(status_code=413)
        try:
            message = json.loads(body)
        except ValueError:
            return JSONResponse(error(None, -32700, "Parse error"), status_code=400)
        reply = await proxy.handle(message, frozenset(scopes))
        if reply is None:
            return Response(status_code=202)
        if "text/event-stream" in request.headers.get("accept", ""):
            return StreamingResponse(iter([f"event: message\ndata: {json.dumps(reply)}\n\n"]),
                                     media_type="text/event-stream")
        return JSONResponse(reply)

    return app


async def stdio(proxy, scopes):
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_MESSAGE)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    while True:
        try:
            line = await reader.readline()
        except ValueError:
            print(json.dumps(error(None, -32700, "Message too large")), flush=True)
            return
        if not line:
            return
        try:
            reply = await proxy.handle(json.loads(line), scopes)
        except ValueError:
            reply = error(None, -32700, "Parse error")
        if reply is not None:
            print(json.dumps(reply), flush=True)


class StdioUpstream:
    def __init__(self, process):
        self.process = process
        self.failed = False

    @classmethod
    async def spawn(cls, command):
        return cls(await asyncio.create_subprocess_exec(
            *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            limit=MAX_MESSAGE,
        ))

    async def __call__(self, message, scopes):
        if self.failed:
            raise UpstreamError
        try:
            self.process.stdin.write(json.dumps(message).encode() + b"\n")
            await self.process.stdin.drain()
            if "id" not in message:
                return None
            while line := await self.process.stdout.readline():
                reply = json.loads(line)
                if isinstance(reply, dict) and reply.get("id") == message["id"]:
                    return reply
            raise UpstreamError
        except BaseException:
            self.failed = True
            raise

    async def close(self):
        if self.process.returncode is None:
            self.process.kill()
        await self.process.wait()
