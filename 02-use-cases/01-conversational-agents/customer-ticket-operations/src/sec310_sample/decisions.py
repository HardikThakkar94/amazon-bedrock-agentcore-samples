"""A decision is anything a control decided about a request.

Controls emit ``Decision`` objects to a sink. Patch 5 plugs in a tracer that hashes
identifiers and drops free text before anything is indexed. Until then the sink is a
plain callable, which keeps the earlier patches free of telemetry concerns.

Every component wraps its sink in ``GuardedSink``: telemetry is a *degraded read-only*
dependency (see ``failure_policy``), so a sink that raises must never take the request
down with it. Dropped events are counted, not hidden.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sec310_sample.identity import RequestIdentity


@dataclass(frozen=True)
class Decision:
    stage: str  # identity | input | model | output | action | admission | job
    control: str  # which control decided (guardrail, link_validator, action_gateway, ...)
    outcome: str  # short stable token: allowed, blocked, denied, degraded, ...
    identity: RequestIdentity | None = None
    session_id: str | None = None
    tool_name: str | None = None
    target_class: str | None = None  # "rule" / "account" / "finding" — never the id
    latency_ms: int = 0
    detail: str = ""  # free text; MUST NOT be indexed as-is


DecisionSink = Callable[[Decision], None]


def no_sink(_: Decision) -> None:
    return None


class GuardedSink:
    """Wraps a sink so a failing tracer degrades telemetry instead of failing the request."""

    def __init__(self, sink: DecisionSink) -> None:
        self._sink = sink.inner if isinstance(sink, GuardedSink) else sink
        self.dropped = 0

    @property
    def inner(self) -> DecisionSink:
        return self._sink

    def __call__(self, decision: Decision) -> None:
        try:
            self._sink(decision)
        except Exception:  # noqa: BLE001 - any sink failure is "tracing degraded", by policy
            self.dropped += 1
