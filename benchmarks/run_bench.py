"""Measure the in-process MCPShield HTTP interception pipeline."""

import argparse
import asyncio
from math import ceil
from platform import machine, python_version
from time import perf_counter_ns

import httpx

from mcpshield.policy import Policy
from mcpshield.proxy import Proxy, http_app
from mcpshield.transport_guard import PROTOCOL_HEADER, TransportGuard

TOKEN = "benchmark"
CANARY = "benchmark-canary"
BASE_HEADERS = {"Authorization": f"Bearer {TOKEN}", "Origin": "https://client.example"}
CALL = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}


def tool_call(name, **arguments):
    return CALL | {"params": {"name": name, "arguments": arguments}}


# Fixed workload and order across runs. Each case defines its expected outcome.
CASES = (
    ("Allowed read", tool_call("read", query="weather"), {}, 200, None),
    ("Allowed write", tool_call("write", title="Note"), {}, 200, None),
    ("Guard / Origin", tool_call("read"), {"Origin": "https://other.example"}, 403, -32600),
    ("Guard / version", tool_call("read"), {PROTOCOL_HEADER: "2020-01-01"}, 400, -32600),
    ("Policy / tool", tool_call("unknown"), {}, 200, -32001),
    ("Taint / canary", tool_call("read", query=CANARY), {}, 200, -32001),
)


def percentile(samples, percent):
    return sorted(samples)[ceil(len(samples) * percent / 100) - 1] / 1_000_000


async def run(iterations, warmup):
    policy = Policy(tools={"read": {}, "write": {"tier": "write"}})
    upstream_calls = 0

    async def upstream(message, scopes):
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def verify(token):
        return {"mcp:write"} if token == TOKEN else None

    proxy = Proxy(policy, upstream, canaries=(CANARY,))
    guard = TransportGuard(allowed_origins=("https://client.example",))
    app = http_app(proxy, verify, guard=guard)
    samples = [[] for _ in CASES]
    intercepted = [0 for _ in CASES]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost",
    ) as client:
        for round_index in range(warmup + iterations):
            for index, (name, body, headers, status, code) in enumerate(CASES):
                before = upstream_calls
                start = perf_counter_ns()
                response = await client.post("/mcp", json=body, headers=BASE_HEADERS | headers)
                elapsed = perf_counter_ns() - start
                reply = response.json()
                actual_code = reply.get("error", {}).get("code")
                blocked = before == upstream_calls and actual_code is not None
                expected_calls = int(code is None)
                if ((response.status_code, actual_code, upstream_calls - before)
                        != (status, code, expected_calls)
                        or (code is None and reply.get("result") != {"ok": True})):
                    raise RuntimeError(f"Unexpected outcome for {name}")
                if round_index >= warmup:
                    samples[index].append(elapsed)
                    intercepted[index] += blocked

    print("# MCPShield benchmark results")
    print()
    print(f"Python {python_version()} on {machine()}. "
          f"{iterations} measured requests and {warmup} warm-up requests per case.")
    print("Sequential in-process ASGI requests with a stub upstream. "
          "Timing includes request encoding, authentication, interception and response handling.")
    print()
    print("| Case | Requests | Intercepted | Rate | p50 (ms) | p95 (ms) | p99 (ms) |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for index, (name, *_) in enumerate(CASES):
        print_row(name, samples[index], intercepted[index])
    for name, noncompliant in (("All compliant", False), ("All non-compliant", True)):
        indices = [i for i, case in enumerate(CASES) if (case[-1] is not None) == noncompliant]
        print_row(name, [sample for i in indices for sample in samples[i]],
                  sum(intercepted[i] for i in indices))


def print_row(name, samples, intercepted):
    p50, p95, p99 = (percentile(samples, percent) for percent in (50, 95, 99))
    print(f"| {name} | {len(samples)} | {intercepted} | "
          f"{intercepted / len(samples):.1%} | {p50:.3f} | {p95:.3f} | {p99:.3f} |")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    args = parser.parse_args()
    if args.iterations < 1 or args.warmup < 0:
        parser.error("--iterations must be positive and --warmup must be non-negative")
    asyncio.run(run(args.iterations, args.warmup))
