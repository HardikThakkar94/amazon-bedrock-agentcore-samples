"""The six visible builds for the live support-ticket demo.

These functions are both the code executed by the demo and the code shown in its Code tab.
Input screening and typed response parsing happen in the shared pipeline before these action
boundaries. Each build adds one independent boundary around the same model proposal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Stage = Literal["v0", "v1", "v2", "v3", "v4", "v5"]


@dataclass(frozen=True)
class PatchContext:
    operator_customer: str
    stop_requested: bool


@dataclass(frozen=True)
class PatchControl:
    name: str
    status: Literal["PASS", "DENY"]
    detail: str


@dataclass(frozen=True)
class PatchDecision:
    allow_effect: bool
    effect_status: str
    controls: tuple[PatchControl, ...] = ()


def v0(context: PatchContext, proposal: dict[str, Any]) -> PatchDecision:
    """Unsafe: a model proposal reaches the broad local demo client directly."""
    return PatchDecision(True, "EXECUTE_UNCHECKED")


def v1(context: PatchContext, proposal: dict[str, Any]) -> PatchDecision:
    """Bind the operator to one customer. Same-customer injected actions can still pass."""
    customer = proposal.get("customer_id")
    if customer != context.operator_customer:
        return PatchDecision(
            False,
            "DENIED_IDENTITY",
            (PatchControl("identity + tenant", "DENY", f"{customer} is outside operator scope"),),
        )
    return PatchDecision(
        True,
        "IDENTITY_PASSED",
        (
            PatchControl(
                "identity + tenant",
                "PASS",
                f"verified operator may reach {context.operator_customer}",
            ),
        ),
    )


def v2(context: PatchContext, proposal: dict[str, Any]) -> PatchDecision:
    """Add input screening and a typed response; neither is action authorization."""
    return v1(context, proposal)


def v3(context: PatchContext, proposal: dict[str, Any]) -> PatchDecision:
    """Put a deterministic capability check between every proposal and its effect."""
    identity = v2(context, proposal)
    if not identity.allow_effect:
        return identity
    if proposal.get("operation") == "close_ticket":
        return PatchDecision(
            False,
            "DENIED_POLICY",
            identity.controls
            + (
                PatchControl(
                    "action policy",
                    "DENY",
                    "close_ticket capability is absent from this conversation",
                ),
            ),
        )
    return identity


def v4(context: PatchContext, proposal: dict[str, Any]) -> PatchDecision:
    """Check a durable operator stop again immediately before an effect."""
    policy = v3(context, proposal)
    if not policy.allow_effect:
        return policy
    if context.stop_requested:
        return PatchDecision(
            False,
            "STOPPED",
            policy.controls
            + (PatchControl("durable stop", "DENY", "stop observed before effect"),),
        )
    return policy


def v5(context: PatchContext, proposal: dict[str, Any]) -> PatchDecision:
    """Use the same boundaries and record proposal, decision and observed effect separately."""
    return v4(context, proposal)


PATCHES = {"v0": v0, "v1": v1, "v2": v2, "v3": v3, "v4": v4, "v5": v5}
PATCH_TITLES = {
    "v0": "Unsafe: model output executes",
    "v1": "Identity: bind operator and customer",
    "v2": "Validation: treat records as data",
    "v3": "Policy: authorize every effect",
    "v4": "Stop: check before admission and effect",
    "v5": "Evidence: gate release on behavior",
}
