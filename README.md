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

Set `MCPSHIELD_CANARIES` to a space-separated list of synthetic canaries.
Responses flagged as instructional are blocked and writes are disabled for the
remainder of a tainted context. Canary matching is textual and the injection
detector uses heuristics. Audit events go to stderr without request payloads.

Generate an offline seccomp baseline with `mcpshield gen-seccomp`, or generate
a restricted namespace, gVisor pod and deny-all network policy with
`mcpshield gen-seccomp --kubernetes NAME IMAGE NAMESPACE`. Test the profile
against the actual upstream runtime and configure permitted network flows
before deploying network-dependent servers.
