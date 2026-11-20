# MCPShield benchmark results

Python 3.12.14 on x86_64. Measured iterations per case: 1000. Warm-up iterations per case: 100.
Sequential in-process ASGI requests with a stub upstream. Timing includes request encoding, authentication, interception and response handling.

| Case | Requests | Intercepted | Rate | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Allowed read | 1000 | 0 | 0.0% | 0.310 | 0.460 | 0.648 |
| Allowed write | 1000 | 0 | 0.0% | 0.312 | 0.523 | 0.714 |
| Guard / Origin | 1000 | 1000 | 100.0% | 0.233 | 0.354 | 0.495 |
| Guard / version | 1000 | 1000 | 100.0% | 0.229 | 0.403 | 0.557 |
| Policy / tool | 1000 | 1000 | 100.0% | 0.251 | 0.407 | 0.559 |
| Taint / canary | 1000 | 1000 | 100.0% | 0.287 | 0.471 | 0.602 |
| All compliant | 2000 | 0 | 0.0% | 0.311 | 0.486 | 0.656 |
| All non-compliant | 4000 | 4000 | 100.0% | 0.252 | 0.425 | 0.559 |

Reload timing covers reading, parsing, schema validation and publication. File writes and watcher polling are outside the timed interval.
Peer timing covers DER decoding, SVID checks and the SPIFFE allowlist lookup after TLS chain validation. The TLS handshake is outside the timed interval.

| Operation | Samples | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| YAML reload | 1000 | 0.274 | 0.375 | 0.517 |
| JSON reload | 1000 | 0.249 | 0.338 | 0.481 |
| Peer verification | 1000 | 0.041 | 0.063 | 0.079 |

## Wave 5 tool pruning and sandbox execution

Six labelled synthetic queries against 60 tools with k=5. Schema tokens are estimated from compact JSON word, number and punctuation counts.

| Metric | Result |
| --- | ---: |
| Estimated schema token reduction | 91.6% |
| Recall@5 | 100.0% (12/12) |
| Sandbox launch overhead p50 | 2.525 ms |
| Sandbox launch overhead p95 | 3.595 ms |
| Sandbox launch overhead p99 | 5.697 ms |

Overhead is the paired wall-clock difference between sandboxed and direct runs of /usr/bin/true, including sandbox setup and teardown.
