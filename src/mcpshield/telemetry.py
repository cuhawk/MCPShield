import json
from datetime import UTC, datetime

from opentelemetry import trace


class Audit:
    def __init__(self, stream=None):
        self.stream = stream
        self.tracer = trace.get_tracer("mcpshield")

    def record(self, outcome):
        with self.tracer.start_as_current_span("mcpshield.request") as span:
            span.set_attribute("mcpshield.outcome", outcome)
            if self.stream is not None:
                print(json.dumps({
                    "timestamp": datetime.now(UTC).isoformat(),
                    "outcome": outcome,
                }), file=self.stream, flush=True)
