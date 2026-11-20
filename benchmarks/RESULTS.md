# MCPShield benchmark results

Python 3.12.14 on x86_64. Measured iterations per case: 1000. Warm-up iterations per case: 100.
Sequential in-process ASGI requests with a stub upstream. Timing includes request encoding, authentication, interception and response handling.

| Case | Requests | Intercepted | Rate | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Allowed read | 1000 | 0 | 0.0% | 0.301 | 0.423 | 0.533 |
| Allowed write | 1000 | 0 | 0.0% | 0.302 | 0.449 | 0.525 |
| Guard / Origin | 1000 | 1000 | 100.0% | 0.222 | 0.322 | 0.380 |
| Guard / version | 1000 | 1000 | 100.0% | 0.216 | 0.374 | 0.457 |
| Policy / tool | 1000 | 1000 | 100.0% | 0.238 | 0.331 | 0.399 |
| Taint / canary | 1000 | 1000 | 100.0% | 0.271 | 0.426 | 0.502 |
| All compliant | 2000 | 0 | 0.0% | 0.302 | 0.438 | 0.533 |
| All non-compliant | 4000 | 4000 | 100.0% | 0.241 | 0.368 | 0.473 |

Reload timing covers reading, parsing, schema validation and publication. File writes and watcher polling are outside the timed interval.
Peer timing covers DER decoding, SVID checks and the SPIFFE allowlist lookup after TLS chain validation. The TLS handshake is outside the timed interval.

| Operation | Samples | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| YAML reload | 1000 | 0.252 | 0.322 | 0.397 |
| JSON reload | 1000 | 0.229 | 0.311 | 0.411 |
| Peer verification | 1000 | 0.038 | 0.059 | 0.097 |

`pytest -q`: `109 passed, 1 warning in 0.74s`
