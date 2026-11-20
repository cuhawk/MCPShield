import argparse
import asyncio
import hmac
import json
import os
import sys
from pathlib import Path

import uvicorn
import yaml

from .oauth import JWTBearer
from .policy import Policy
from .proxy import HTTPUpstream, Proxy, StdioUpstream, http_app, stdio
from .sandbox import kubernetes, seccomp
from .telemetry import Audit
from .transport_guard import LOOPBACK_HOSTS, MAX_MESSAGE, TransportGuard


def main():
    parser = argparse.ArgumentParser(prog="mcpshield")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check").add_argument("policy")
    generate = commands.add_parser("gen-seccomp")
    generate.add_argument("--network", action="store_true")
    generate.add_argument("--kubernetes", nargs=3, metavar=("NAME", "IMAGE", "NAMESPACE"))
    commands.add_parser("demo-report")
    serve = commands.add_parser("proxy")
    serve.add_argument("policy")
    upstream = serve.add_mutually_exclusive_group(required=True)
    upstream.add_argument("--upstream-url")
    upstream.add_argument("--upstream-command", nargs="+")
    serve.add_argument("--listen", type=int)
    serve.add_argument("--allow-host", action="append")
    serve.add_argument("--allow-origin", action="append", default=[])
    serve.add_argument("--max-response-bytes", type=int, default=MAX_MESSAGE)
    serve.add_argument("--max-batch-size", type=int, default=16)
    serve.add_argument("--scope", action="append", default=[])
    serve.add_argument("--oauth-public-key", type=Path)
    serve.add_argument("--oauth-issuer")
    serve.add_argument("--oauth-audience")
    args = parser.parse_args()
    if args.command == "gen-seccomp":
        print(yaml.safe_dump_all(kubernetes(*args.kubernetes)) if args.kubernetes else
              json.dumps(seccomp(args.network), indent=2))
    elif args.command == "demo-report":
        Audit(sys.stdout).record("demo")
    elif args.command == "check":
        Policy.load(args.policy)
    else:
        policy = Policy.load(args.policy)
        canaries = os.environ.get("MCPSHIELD_CANARIES", "").split()
        audit = Audit(sys.stderr)
        scopes = frozenset(args.scope)
        if args.max_response_bytes < 1:
            parser.error("--max-response-bytes must be positive")
        if args.listen is not None:
            if not args.upstream_url:
                parser.error("HTTP mode requires --upstream-url")
            if args.oauth_public_key:
                if not args.oauth_issuer or not args.oauth_audience:
                    parser.error("OAuth mode requires --oauth-issuer and --oauth-audience")
                verify = JWTBearer(
                    args.oauth_public_key.read_bytes(), args.oauth_issuer, args.oauth_audience
                )
            else:
                token = os.environ.get("MCPSHIELD_BEARER", "")
                if not token:
                    parser.error("set MCPSHIELD_BEARER or configure OAuth verification")

                async def verify(value):
                    return scopes if hmac.compare_digest(value.encode(), token.encode()) else None

            try:
                guard = TransportGuard(
                    allowed_hosts=args.allow_host or tuple(
                        f"{host}:{args.listen}" for host in LOOPBACK_HOSTS
                    ),
                    allowed_origins=args.allow_origin,
                    max_batch_size=args.max_batch_size,
                )
            except ValueError as exc:
                parser.error(str(exc))
            transport = HTTPUpstream(args.upstream_url, max_response_bytes=args.max_response_bytes)
            proxy = Proxy(policy, transport, canaries, audit)
            uvicorn.run(http_app(proxy, verify, guard=guard), host="127.0.0.1", port=args.listen)
        else:
            async def run():
                if args.upstream_url:
                    transport = HTTPUpstream(
                        args.upstream_url, max_response_bytes=args.max_response_bytes
                    )
                    await stdio(Proxy(policy, transport, canaries, audit), scopes)
                else:
                    transport = await StdioUpstream.spawn(args.upstream_command)
                    try:
                        await stdio(Proxy(policy, transport, canaries, audit), scopes)
                    finally:
                        await transport.close()

            asyncio.run(run())
