"""Patch 2 — guardrails are a layer, not a permission.

A guardrail decision has three outcomes, and the code branches on all three:
``NONE`` (continue), ``INTERVENED`` (stop, say so), ``UNAVAILABLE`` (apply the failure
policy). Emitting a metric and carrying on is telemetry, not enforcement.

``LocalGuardrail`` is a small keyword detector so the demo is deterministic and
offline. It is intentionally weak: the indirect-injection fixture sails past it,
which is exactly why Patch 3 exists. ``BedrockGuardrail`` is the opt-in real thing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Protocol

Source = Literal["INPUT", "OUTPUT"]


class GuardrailAction(StrEnum):
    NONE = "NONE"
    INTERVENED = "GUARDRAIL_INTERVENED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class GuardrailDecision:
    action: GuardrailAction
    source: Source
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def intervened(self) -> bool:
        return self.action is GuardrailAction.INTERVENED

    @property
    def unavailable(self) -> bool:
        return self.action is GuardrailAction.UNAVAILABLE


class Guardrail(Protocol):
    def assess(self, text: str, source: Source) -> GuardrailDecision: ...


_PROMPT_ATTACK_PATTERNS = (
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
    r"disregard (your|all|the) (instructions|rules|guidelines)",
    r"you are now (in )?[a-z ]*mode",
    r"system override",
    r"reveal (your )?(system prompt|instructions)",
)
_PROMPT_ATTACK_RE = re.compile("|".join(f"(?:{p})" for p in _PROMPT_ATTACK_PATTERNS), re.IGNORECASE)


class LocalGuardrail:
    """Deterministic keyword detector. Offline. Deliberately not clever."""

    def assess(self, text: str, source: Source) -> GuardrailDecision:
        hits = tuple(sorted({m.group(0).lower() for m in _PROMPT_ATTACK_RE.finditer(text)}))
        if hits:
            return GuardrailDecision(GuardrailAction.INTERVENED, source, hits)
        return GuardrailDecision(GuardrailAction.NONE, source)


class UnavailableGuardrail:
    """Test double for a guardrail dependency outage."""

    def assess(self, text: str, source: Source) -> GuardrailDecision:
        return GuardrailDecision(GuardrailAction.UNAVAILABLE, source, ("dependency_unavailable",))


class BedrockGuardrail:
    """Opt-in: Amazon Bedrock Guardrails ``ApplyGuardrail`` API.

    Requires ``SEC310_GUARDRAIL_ID`` and ``SEC310_GUARDRAIL_VERSION``. Any client error
    maps to ``UNAVAILABLE`` so the caller's failure policy decides what happens next.
    """

    def __init__(
        self, guardrail_id: str | None = None, version: str | None = None, client=None
    ) -> None:
        self.guardrail_id = guardrail_id or os.environ.get("SEC310_GUARDRAIL_ID")
        self.version = version or os.environ.get("SEC310_GUARDRAIL_VERSION", "DRAFT")
        if not self.guardrail_id:
            raise RuntimeError("set SEC310_GUARDRAIL_ID to use the live guardrail path")
        if client is None:
            import boto3  # lazy

            client = boto3.client("bedrock-runtime")
        self._client = client

    def assess(self, text: str, source: Source) -> GuardrailDecision:
        try:
            resp = self._client.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.version,
                source=source,
                content=[{"text": {"text": text}}],
            )
        except Exception as exc:  # noqa: BLE001 - any failure is "unavailable" to the policy layer
            return GuardrailDecision(GuardrailAction.UNAVAILABLE, source, (type(exc).__name__,))
        action = resp.get("action")
        if action == "GUARDRAIL_INTERVENED":
            reasons = tuple(sorted(_assessment_reasons(resp)))
            return GuardrailDecision(GuardrailAction.INTERVENED, source, reasons)
        if action == "NONE":
            return GuardrailDecision(GuardrailAction.NONE, source)
        # A missing or unknown action is not evidence that the text passed.
        return GuardrailDecision(
            GuardrailAction.UNAVAILABLE, source, (f"unexpected_action:{action or 'missing'}",)
        )


def _assessment_reasons(resp: dict) -> set[str]:
    reasons: set[str] = set()
    for assessment in resp.get("assessments", []):
        for policy_name, policy in assessment.items():
            if isinstance(policy, dict):
                for key in (
                    "filters",
                    "topics",
                    "customWords",
                    "managedWordLists",
                    "piiEntities",
                    "regexes",
                ):
                    for item in policy.get(key, []):
                        reasons.add(f"{policy_name}:{item.get('type') or item.get('name') or key}")
    return reasons or {"intervened"}
