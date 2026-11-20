# MCPShield

**Zero-Trust Security Firewall & Capability Proxy for Model Context Protocol (MCP) & Autonomous AI Agents.**

## Architecture Targets
1. **JSON-RPC / HTTP-SSE MCP Proxy (`mcpshield`):** Sits inline between MCP hosts/agents and downstream MCP servers.
2. **OAuth 2.1 Capability Attenuation:** Validates tool-call scopes, enforces read/write/privileged policy tiers, and strips over-privileged tokens before tool invocation.
3. **Indirect Prompt-Injection & Canary Taint Tracking:** Tags untrusted external data returned by MCP tools (`fetch`, `search`, `read_file`) and blocks downstream exfiltration or unauthorized side-effect calls carrying tainted parameters or canary secrets.
4. **Container / gVisor Seccomp Policy Generator:** Generates least-privilege seccomp & Docker/Kubernetes isolation profiles per MCP tool manifest.
5. **OpenTelemetry + SARIF/JSONL Audit Logs:** Deterministic trace recording for compliance & CI regression gates.

## Run locally

Install with `pip install -e '.[test]'` and run `pytest -q`. Python 3.12 or
later is required. A policy names every permitted tool. Stronger tiers require
the matching `mcp:write` or `mcp:privileged` scope.

```yaml
tools:
  search:
    scopes: [search]
    untrusted_output: true
  save:
    scopes: [documents]
    tier: write
    arguments:
      type: object
      required: [name]
      properties:
        name: {type: string}
      additionalProperties: false
```

Run `mcpshield check policy.yml` to validate configuration and
`mcpshield proxy policy.yml --scope search --upstream-command python server.py`
for a subprocess server. HTTP mode uses `--listen 8000 --upstream-url URL` and
supports either a static `MCPSHIELD_BEARER` with explicitly configured scopes
or signed OAuth access tokens via `--oauth-public-key PUBLIC_KEY.pem
--oauth-issuer ISSUER --oauth-audience RESOURCE`. OAuth mode checks RS256
signatures, issuer, resource audience, token validity and scope syntax.
One proxy instance shares a conservative taint context. Run separate
instances for independent trust domains. Configure `HTTPUpstream` with a
scoped token provider if the upstream server requires credentials. Incoming Authorization headers are never forwarded.
The proxy supports newline-delimited stdio and HTTP POST with JSON or SSE
responses. It implements a restricted tools-only MCP profile.

### Policy hot reload

Both proxy modes poll the YAML or JSON policy file every second by default.
Set the interval with `--policy-reload-interval SECONDS`. Publish changes by
writing a complete file and atomically renaming it over the policy path.
The proxy validates the replacement before publishing it. Invalid updates
leave the active policy in place and emit a diagnostic on stderr.
In-flight requests finish using the policy they started with.

### Streamable HTTP security

The listener accepts loopback Host authorities on the configured port by
default. Behind a reverse proxy, repeat `--allow-host` for each exact authority
the proxy forwards, including its port when present. Requests without an
Origin header are accepted. Browser clients need an explicit `--allow-origin`
entry for each scheme, host and port they use. Duplicate or unlisted Host
and Origin values receive HTTP 403.

The proxy supports MCP protocol versions `2025-03-26`, `2025-06-18` and
`2025-11-25`. It validates initialization and checks subsequent version
headers against the upstream selection. Before negotiation, requests without
a version header use `2025-03-26`. Only that legacy version accepts JSON-RPC
batches, with up to 16 entries by default (`--max-batch-size`).

To authenticate an HTTPS upstream by SPIFFE identity, provide the trust
bundle and client certificate chain and key. Repeat `--upstream-spiffe-id`
for each exact allowed workload ID.

```sh
mcpshield proxy policy.yml --listen 8000 --upstream-url https://mcp.example.org/mcp \
  --upstream-ca trust-bundle.pem --upstream-cert client-chain.pem \
  --upstream-key client-key.pem --upstream-spiffe-id spiffe://example.org/mcp
```

The upstream must require and validate the client certificate. The proxy
validates the upstream chain against the supplied bundle, then verifies its
SPIFFE URI SAN as the server identity before sending any MCP request.
In mTLS mode, upstream redirects must stay on the same origin.

Upstream redirects strip Authorization, Cookie and X-API-Key on any origin
change. HTTPS-to-HTTP redirects are rejected. Upstream response reads use
identity encoding and enforce a cumulative 1 MiB limit by default
(`--max-response-bytes`), including SSE frames consumed before the reply.
See the upstream [Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http)
and [MCP security guidance](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices).

Set `MCPSHIELD_CANARIES` to a space-separated list of synthetic canaries.
Responses flagged as instructional are blocked and writes are disabled for the
remainder of a tainted context. Canary matching is textual and the injection
detector uses heuristics. Audit events go to stderr without request payloads.

Generate an offline seccomp baseline with `mcpshield gen-seccomp`, or generate
a restricted namespace, gVisor pod and deny-all network policy with
`mcpshield gen-seccomp --kubernetes NAME IMAGE NAMESPACE`. Test the profile
against the actual upstream runtime and configure permitted network flows
before deploying network-dependent servers.

## Tests and benchmarks

Run `pytest -q` and `python benchmarks/run_bench.py` after installing the
package with its test dependencies. The Python 3.12.14 run intercepted all
4,000 non-compliant requests and allowed all 2,000 compliant requests.

`pytest -q` reported `109 passed, 1 warning in 0.74s`.

| Operation | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: |
| YAML reload | 0.252 | 0.322 | 0.397 |
| JSON reload | 0.229 | 0.311 | 0.411 |
| Peer verification | 0.038 | 0.059 | 0.097 |

Reload measurements cover file reads, validation and publication. Peer
verification measures the SVID check after TLS chain validation.
[Full benchmark results](benchmarks/RESULTS.md)
