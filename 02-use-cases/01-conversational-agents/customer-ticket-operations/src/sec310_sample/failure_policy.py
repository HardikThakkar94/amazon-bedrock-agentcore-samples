"""Failure direction is a design decision, made per dependency, written down.

"Graceful degradation" is a slogan. This table is the actual policy. Blast radius
decides the direction: anything that gates authority fails closed; anything that only
enriches a read may degrade; anything that is just slow gets a bounded retry.
"""

from __future__ import annotations

from enum import StrEnum


class FailurePolicy(StrEnum):
    FAIL_CLOSED = "fail_closed"  # reject the operation
    DEGRADED_READ_ONLY = "degraded_read_only"  # continue, but only reads; disclose degraded mode
    RETRY_BOUNDED = "retry_bounded"  # retry within a budget, then terminal state


POLICIES: dict[str, FailurePolicy] = {
    "identity_envelope": FailurePolicy.FAIL_CLOSED,
    "session_ownership": FailurePolicy.FAIL_CLOSED,
    "mutation_authorizer": FailurePolicy.FAIL_CLOSED,
    "confirmation": FailurePolicy.FAIL_CLOSED,
    "operator_stop": FailurePolicy.FAIL_CLOSED,
    "guardrail": FailurePolicy.DEGRADED_READ_ONLY,  # reads may continue; writes fail closed
    "tracing": FailurePolicy.DEGRADED_READ_ONLY,  # a failing sink drops events, never requests
    "downstream_overload": FailurePolicy.RETRY_BOUNDED,
    "worker_timeout": FailurePolicy.RETRY_BOUNDED,
}

POLICY_VERSION = "failure-policy/2026.09.1"


def policy_for(dependency: str) -> FailurePolicy:
    """Unknown dependencies fail closed.

    Forgetting to classify something is not a licence to fail open.
    """
    return POLICIES.get(dependency, FailurePolicy.FAIL_CLOSED)
