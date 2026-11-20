import argparse
import asyncio
import hmac
import json
import math
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
import yaml

from .mtls_verifier import MTLSConfig
from .oauth import JWTBearer
from .policy import Policy, PolicyReloader
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
    serve.add_argument("--upstream-ca")
    serve.add_argument("--upstream-cert")
    serve.add_argument("--upstream-key")
    serve.add_argument("--upstream-spiffe-id", action="append")
    serve.add_argument("--policy-reload-interval", type=float, default=1.0,
                       help="Seconds between policy file checks")
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
        if not math.isfinite(args.policy_reload_interval) or args.policy_reload_interval <= 0:
            parser.error("--policy-reload-interval must be finite and positive")
        policy = PolicyReloader(args.policy)

        @asynccontextmanager
        async def policy_lifespan(_app):
            async with policy.watch(args.policy_reload_interval):
                yield

        mtls = None
        ssl_options = (args.upstream_ca, args.upstream_cert, args.upstream_key,
                       args.upstream_spiffe_id)
        if any(value is not None for value in ssl_options):
            if not args.upstream_url or not all(ssl_options):
                parser.error("mTLS requires --upstream-url, --upstream-ca, --upstream-cert, "
                             "--upstream-key and --upstream-spiffe-id")
            mtls = MTLSConfig(*ssl_options[:3], tuple(args.upstream_spiffe_id))
        canaries = os.environ.get("MCPSHIELD_CANARIES", "").split()
        audit = Audit(sys.stderr)
        scopes = frozenset(args.scope)
        if args.max_response_bytes < 1:
            parser.error("--max-response-bytes must be positive")
        if args.upstream_url:
            try:
                transport = HTTPUpstream(args.upstream_url,
                                         max_response_bytes=args.max_response_bytes, mtls=mtls)
            except (OSError, ValueError) as exc:
                parser.error(str(exc))
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
            proxy = Proxy(policy, transport, canaries, audit)
            uvicorn.run(http_app(proxy, verify, guard=guard, lifespan=policy_lifespan),
                        host="127.0.0.1", port=args.listen)
        else:
            async def run():
                async with policy.watch(args.policy_reload_interval):
                    if args.upstream_url:
                        await stdio(Proxy(policy, transport, canaries, audit), scopes)
                    else:
                        stdio_upstream = await StdioUpstream.spawn(args.upstream_command)
                        try:
                            await stdio(Proxy(policy, stdio_upstream, canaries, audit), scopes)
                        finally:
                            await stdio_upstream.close()

            asyncio.run(run())
