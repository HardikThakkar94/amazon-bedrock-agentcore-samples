"""Patch 5 — observe decisions, not just HTTP health.

A ``Tracer`` turns raw ``Decision`` objects into ``DecisionEvent`` records that are
safe to index:

- identifiers become keyed hashes (HMAC-SHA256, truncated), never raw values;
- the free-text ``detail`` field is dropped entirely;
- any indexed token that still contains an identity-derived raw value (tenant,
  principal, account, session) is scrubbed at runtime, and the scrub is counted;
- every event carries the model / prompt / policy versions that produced it.

The scrub is a mechanism; ``assert_redacted`` is the test that proves it. Keep both.
A truncated keyed hash over a tiny identity space is still enumerable by anyone who
holds the key: protect the key, and do not sell this as anonymisation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from sec310_sample.action_gateway import GATEWAY_POLICY_VERSION
from sec310_sample.decisions import Decision
from sec310_sample.failure_policy import POLICY_VERSION
from sec310_sample.request_preparation import PROMPT_VERSION

REDACTED = "[redacted]"


@dataclass(frozen=True)
class Versions:
    model_version: str
    prompt_version: str = PROMPT_VERSION
    policy_version: str = f"{POLICY_VERSION}+{GATEWAY_POLICY_VERSION}"


@dataclass(frozen=True)
class DecisionEvent:
    stage: str
    control: str
    outcome: str
    identity_hash: str | None
    session_hash: str | None
    model_version: str
    prompt_version: str
    policy_version: str
    tool_name: str | None
    target_class: str | None
    latency_ms: int


def hash_identifier(value: str, key: str) -> str:
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]


class Tracer:
    """Decision sink. Call it with a ``Decision``; read back redacted events."""

    def __init__(self, versions: Versions, key: str | None = None) -> None:
        self._versions = versions
        self._key = key or secrets.token_hex(16)
        self._events: list[DecisionEvent] = []
        self.scrubbed = 0

    def __call__(self, decision: Decision) -> None:
        raw_values = self._raw_values(decision)
        identity_hash = (
            hash_identifier(decision.identity.partition, self._key) if decision.identity else None
        )
        session_hash = (
            hash_identifier(decision.session_id, self._key) if decision.session_id else None
        )
        self._events.append(
            DecisionEvent(
                stage=self._scrub(decision.stage, raw_values),
                control=self._scrub(decision.control, raw_values),
                outcome=self._scrub(decision.outcome, raw_values),
                identity_hash=identity_hash,
                session_hash=session_hash,
                model_version=self._versions.model_version,
                prompt_version=self._versions.prompt_version,
                policy_version=self._versions.policy_version,
                tool_name=self._scrub(decision.tool_name, raw_values),
                target_class=self._scrub(decision.target_class, raw_values),
                latency_ms=decision.latency_ms,
            )
        )

    @staticmethod
    def _raw_values(decision: Decision) -> tuple[str, ...]:
        values: set[str] = set()
        if decision.identity is not None:
            values.update(
                {
                    decision.identity.tenant_id,
                    decision.identity.principal_id,
                    *decision.identity.allowed_accounts,
                }
            )
        if decision.session_id:
            values.add(decision.session_id)
        return tuple(sorted(values, key=len, reverse=True))

    def _scrub(self, token: str | None, raw_values: tuple[str, ...]) -> str | None:
        if token is None:
            return None
        cleaned = token
        for raw in raw_values:
            if raw and raw in cleaned:
                cleaned = cleaned.replace(raw, REDACTED)
                self.scrubbed += 1
        return cleaned

    @property
    def events(self) -> tuple[DecisionEvent, ...]:
        return tuple(self._events)

    def export(self) -> list[dict[str, Any]]:
        return [asdict(e) for e in self._events]

    def outcomes(self) -> Counter[tuple[str, str, str]]:
        return Counter((e.stage, e.control, e.outcome) for e in self._events)

    def assert_redacted(self, forbidden: Iterable[str]) -> None:
        """Raise if any raw identifier or payload string leaked into indexed attributes."""
        blob = "\n".join(str(v) for event in self.export() for v in event.values())
        leaked = [term for term in forbidden if term and term in blob]
        if leaked:
            raise AssertionError(f"raw identifiers in telemetry: {leaked}")
