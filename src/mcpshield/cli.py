import argparse
import asyncio
import hmac
import json
import os
import sys

import uvicorn
import yaml

from .policy import Policy
from .proxy import HTTPUpstream, Proxy, StdioUpstream, http_app, stdio
from .sandbox import kubernetes, seccomp
from .telemetry import Audit


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
    serve.add_argument("--scope", action="append", default=[])
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
        if args.listen is not None:
            token = os.environ.get("MCPSHIELD_BEARER", "")
            if not token or not args.upstream_url:
                parser.error("HTTP mode requires MCPSHIELD_BEARER and --upstream-url")

            async def verify(value):
                return scopes if hmac.compare_digest(value.encode(), token.encode()) else None

            proxy = Proxy(policy, HTTPUpstream(args.upstream_url), canaries, audit)
            uvicorn.run(http_app(proxy, verify), host="127.0.0.1", port=args.listen)
        else:
            async def run():
                if args.upstream_url:
                    await stdio(Proxy(policy, HTTPUpstream(args.upstream_url),
                                      canaries, audit), scopes)
                else:
                    transport = await StdioUpstream.spawn(args.upstream_command)
                    try:
                        await stdio(Proxy(policy, transport, canaries, audit), scopes)
                    finally:
                        await transport.close()

            asyncio.run(run())
