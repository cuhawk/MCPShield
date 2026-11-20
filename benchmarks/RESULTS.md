# MCPShield benchmark results

Python 3.12.14 on x86_64. 1000 measured requests and 100 warm-up requests per case.
Sequential in-process ASGI requests with a stub upstream. Timing includes request encoding, authentication, interception and response handling.

| Case | Requests | Intercepted | Rate | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Allowed read | 1000 | 0 | 0.0% | 0.329 | 0.548 | 0.712 |
| Allowed write | 1000 | 0 | 0.0% | 0.335 | 0.594 | 0.733 |
| Guard / Origin | 1000 | 1000 | 100.0% | 0.247 | 0.428 | 0.573 |
| Guard / version | 1000 | 1000 | 100.0% | 0.246 | 0.456 | 0.916 |
| Policy / tool | 1000 | 1000 | 100.0% | 0.268 | 0.449 | 0.652 |
| Taint / canary | 1000 | 1000 | 100.0% | 0.303 | 0.532 | 0.670 |
| All compliant | 2000 | 0 | 0.0% | 0.332 | 0.576 | 0.731 |
| All non-compliant | 4000 | 4000 | 100.0% | 0.269 | 0.477 | 0.666 |
