"""Intercept MCP requests before they reach a configured upstream."""

import asyncio
import json
import os
import re
import sys

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .policy import Denied
from .taint import SessionTaint
from .telemetry import Audit
from .transport_guard import (
    MAX_MESSAGE,
    PROTOCOL_HEADER,
    TransportGuard,
    TransportViolation,
    bounded_chunks,
    guard_redirect,
    validate_version,
)

SSE_BOUNDARY = re.compile(rb"(?:\r\n|\n)(?:\r\n|\n)")
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

    async def handle(self, message, scopes=frozenset(), *, protocol_version=None):
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
                    params = {"name": name, "arguments": arguments}
                outbound = {"jsonrpc": "2.0", "method": method, "params": params}
                if not notification:
                    outbound["id"] = request_id
                self.taint.check_canaries(outbound)
                if isinstance(self.upstream, HTTPUpstream):
                    call = self.upstream(outbound, attenuated, protocol_version=protocol_version)
                else:
                    call = self.upstream(outbound, attenuated)
                reply = await asyncio.wait_for(call, 30)
                if notification:
                    return None
                if (not isinstance(reply, dict) or reply.get("jsonrpc") != "2.0"
                        or "id" not in reply or type(reply["id"]) is not type(request_id)
                        or reply["id"] != request_id
                        or ("result" in reply) == ("error" in reply)):
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
            except (ValueError, KeyError, TypeError, OSError, TimeoutError, RecursionError,
                    httpx.HTTPError, UpstreamError):
                self.audit.record("upstream_error")
                return None if notification else error(request_id, -32002, "Upstream failure")


class HTTPUpstream:
    def __init__(self, url, token_for_scopes=None, *, max_response_bytes=MAX_MESSAGE):
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        self.url = url
        self.token_for_scopes = token_for_scopes
        self.max_response_bytes = max_response_bytes
        self.negotiated_version = None

    async def __call__(self, message, scopes, *, protocol_version=None):
        initializing = message["method"] == "initialize"
        headers = {"Accept": "application/json, text/event-stream", "Accept-Encoding": "identity"}
        if initializing:
            validate_version(message["params"].get("protocolVersion"))
        else:
            if (protocol_version is not None and self.negotiated_version is not None
                    and protocol_version != self.negotiated_version):
                raise TransportViolation("MCP protocol version differs from negotiated version")
            version = protocol_version or self.negotiated_version
            if version is not None:
                headers[PROTOCOL_HEADER] = validate_version(version)
        if self.token_for_scopes is not None:
            headers["Authorization"] = f"Bearer {await self.token_for_scopes(scopes)}"
        async with httpx.AsyncClient(trust_env=False) as client:
            request = client.build_request("POST", self.url, json=message, headers=headers)
            for hop in range(client.max_redirects + 1):
                reply = await client.send(request, stream=True, follow_redirects=False)
                try:
                    if reply.next_request is None:
                        result = await self.read_reply(reply, message)
                        break
                    if hop == client.max_redirects:
                        raise UpstreamError
                    following = reply.next_request
                    guard_redirect(request, following)
                    request = following
                finally:
                    await reply.aclose()
        if initializing and isinstance(result, dict) and "result" in result:
            if (result.get("jsonrpc") != "2.0" or "error" in result
                    or "id" not in message or "id" not in result
                    or type(result["id"]) is not type(message["id"])
                    or result["id"] != message["id"] or not isinstance(result["result"], dict)):
                raise UpstreamError
            self.negotiated_version = validate_version(result["result"].get("protocolVersion"))
        return result

    async def read_reply(self, reply, message):
        reply.raise_for_status()
        if reply.status_code == 202:
            return None
        body = bytearray()
        sse = reply.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        sse = sse == "text/event-stream"
        search_start = 0
        async for chunk in bounded_chunks(reply, self.max_response_bytes):
            body.extend(chunk)
            while sse and (end := SSE_BOUNDARY.search(body, search_start)):
                frame = body[:end.start()]
                del body[:end.end()]
                search_start = 0
                data = b"\n".join(line[5:].lstrip(b" ") for line in frame.splitlines()
                                  if line.startswith(b"data:"))
                if data:
                    event = json.loads(data)
                    if (isinstance(event, dict) and "id" in message and "id" in event
                            and type(event["id"]) is type(message["id"])
                            and event["id"] == message["id"]):
                        return event
            search_start = max(0, len(body) - 3)
        if sse:
            raise UpstreamError
        return json.loads(body)


def http_app(proxy, verify_bearer, *, guard=None):
    app = FastAPI()
    guard = guard if guard is not None else TransportGuard()

    @app.api_route("/mcp", methods=["POST", "GET", "DELETE"])
    async def serve(request: Request):
        try:
            version = guard.validate_headers(
                request.headers, getattr(proxy.upstream, "negotiated_version", None)
            )
        except TransportViolation as exc:
            return JSONResponse(error(None, -32600, str(exc)), status_code=exc.status)
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        scopes = await verify_bearer(token) if scheme.lower() == "bearer" and token else None
        if scopes is None:
            return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
        body = bytearray()
        async for chunk in request.stream():
            if len(chunk) > MAX_MESSAGE - len(body):
                return Response(status_code=413)
            body.extend(chunk)
        try:
            message = json.loads(body)
        except (ValueError, RecursionError):
            return JSONResponse(error(None, -32700, "Parse error"), status_code=400)
        try:
            guard.validate_batch(message, version)
            entries = message if isinstance(message, list) else [message]
            for entry in entries:
                if isinstance(entry, dict) and entry.get("method") == "initialize":
                    params = entry.get("params")
                    validate_version(params.get("protocolVersion") if isinstance(params, dict) else None)
                    if isinstance(message, list):
                        raise TransportViolation("Initialize must be a standalone request")
        except TransportViolation as exc:
            return JSONResponse(error(None, -32600, str(exc)), status_code=exc.status)
        scopes = frozenset(scopes)
        if isinstance(message, list):
            replies = [await proxy.handle(entry, scopes, protocol_version=version)
                       for entry in message]
            reply = [item for item in replies if item is not None] or None
        else:
            reply = await proxy.handle(message, scopes, protocol_version=version)
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
            env={name: value for name, value in os.environ.items()
                 if not name.startswith("MCPSHIELD_")},
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
