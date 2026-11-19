# Codex Cloud Implementation Specification: MCPShield
Build a complete, production-shaped, well-tested Python 3.12+ package (`pyproject.toml` using standard `setuptools` or `hatchling`, `pytest`, `pydantic>=2`, `httpx`, `pyyaml`, `opentelemetry-api`, `fastapi`, `uvicorn`) in `src/mcpshield/`:
- `src/mcpshield/proxy.py`: Async JSON-RPC 2.0 stdio + HTTP/SSE MCP intercepting proxy.
- `src/mcpshield/policy.py`: Declarative YAML capability policy engine + OAuth 2.1 scope attenuation & argument schema validator.
- `src/mcpshield/taint.py`: Indirect prompt-injection detector (structural/instructional payload heuristics + taint label propagation across session context) + canary secret leak blocker.
- `src/mcpshield/sandbox.py`: Generator for Docker/gVisor seccomp JSON profiles + Kubernetes PodSecurity/NetworkPolicy manifests per MCP tool server.
- `src/mcpshield/telemetry.py`: Structured JSONL + OpenTelemetry-compatible span emitter.
- `src/mcpshield/cli.py`: CLI (`mcpshield check`, `mcpshield proxy`, `mcpshield gen-seccomp`, `mcpshield demo-report`).
- `tests/`: Comprehensive `pytest` suite (30+ tests covering prompt injection across tool responses, canary exfiltration, OAuth scope escalation, path traversal in tool args, policy deny/allow, seccomp generation) passing offline with zero API keys.
- `.github/workflows/ci.yml`: Automated pytest + ruff/lint workflow on push/PR.
