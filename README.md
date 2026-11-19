# MCPShield

**Zero-Trust Security Firewall & Capability Proxy for Model Context Protocol (MCP) & Autonomous AI Agents.**

## Architecture Targets
1. **JSON-RPC / HTTP-SSE MCP Proxy (`mcpshield`):** Sits inline between MCP hosts/agents and downstream MCP servers.
2. **OAuth 2.1 Capability Attenuation:** Validates tool-call scopes, enforces read/write/privileged policy tiers, and strips over-privileged tokens before tool invocation.
3. **Indirect Prompt-Injection & Canary Taint Tracking:** Tags untrusted external data returned by MCP tools (`fetch`, `search`, `read_file`) and blocks downstream exfiltration or unauthorized side-effect calls carrying tainted parameters or canary secrets.
4. **Container / gVisor Seccomp Policy Generator:** Generates least-privilege seccomp & Docker/Kubernetes isolation profiles per MCP tool manifest.
5. **OpenTelemetry + SARIF/JSONL Audit Logs:** Deterministic trace recording for compliance & CI regression gates.
