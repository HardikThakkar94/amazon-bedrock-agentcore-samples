"""Opt-in live adapters for the on-stage "prove it" stage.

Everything in this module makes real AWS calls. Nothing is imported or constructed on the
offline path. Region and credentials come from the standard AWS SDK chain; identifiers come
from the environment (see ``model.BedrockModel`` and ``guardrails.BedrockGuardrail``).

``GuardrailChecks``
    The agentic guardrail API (``InvokeGuardrailChecks``): prompt-attack screening of a
    *proposed tool call* before it executes, and of a tool's result before it enters the
    context. A detection is a signal for the application to act on — it is not a permission.

``CedarPolicyGate``
    AgentCore Policy control plane (``bedrock-agentcore-control``): creating a policy with
    ``validationMode=FAIL_ON_ANY_FINDINGS`` runs automated-reasoning semantic validation on
    the Cedar statement, so the policy is machine-checked before anything could enforce it.
    The throwaway engine and policies are deleted afterwards.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CheckResult:
    """One screening result. A signal, not an authorization."""

    blocked: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    unavailable: bool = False


class GuardrailChecks:
    """Prompt-attack screening of tool traffic (``bedrock-runtime:InvokeGuardrailChecks``)."""

    def __init__(self, client=None) -> None:
        if client is None:
            import boto3  # lazy: the offline path must not need it

            client = boto3.client("bedrock-runtime")
        self._client = client

    def check_tool_call(self, tool_name: str, arguments: dict) -> CheckResult:
        """Screen a proposed tool call before it executes."""
        text = f"proposed tool call: {tool_name}\narguments: {json.dumps(arguments, default=str)}"
        return self._check(text)

    def check_tool_result(self, text: str) -> CheckResult:
        """Screen a tool's result before it enters the context."""
        return self._check(text)

    def _check(self, text: str) -> CheckResult:
        try:
            resp = self._client.invoke_guardrail_checks(
                messages=[{"role": "user", "content": [{"text": text}]}],
                checks={"promptAttack": {"categories": [{"category": "PROMPT_INJECTION"}]}},
            )
        except Exception as exc:  # noqa: BLE001 - any failure is "unavailable" to the caller
            return CheckResult(blocked=False, reasons=(type(exc).__name__,), unavailable=True)
        reasons = tuple(
            sorted(
                {
                    f"promptAttack:{hit.get('category', '?')}"
                    for hit in resp.get("results", {}).get("promptAttack", {}).get("results", [])
                }
            )
        )
        return CheckResult(blocked=bool(reasons), reasons=reasons)


@dataclass(frozen=True)
class PolicyVerification:
    """Outcome of automated-reasoning policy validation."""

    accepted: bool
    status: str
    findings: tuple[str, ...] = field(default_factory=tuple)
    policy_id: str | None = None


# The good policy scopes a write to the caller's account; the bad one permits everything,
# which semantic validation flags.
GOOD_CEDAR = (
    'permit(principal, action == Action::"update_rule", resource) '
    "when { principal.account == resource.account };"
)
BAD_CEDAR = "permit(principal, action, resource);"


class CedarPolicyGate:
    """AgentCore Policy control plane: machine-checked Cedar before enforcement."""

    def __init__(self, engine_name: str = "sec310-demo", client=None) -> None:
        self._engine_name = engine_name
        self._engine_id: str | None = None
        self._policies: list[tuple[str, str]] = []  # (policyEngineId, policyId)
        if client is None:
            import boto3  # lazy

            client = boto3.client("bedrock-agentcore-control")
        self._client = client

    def provision(self) -> str:
        """Create the throwaway policy engine; returns its id."""
        resp = self._client.create_policy_engine(name=self._engine_name)
        self._engine_id = resp["policyEngineId"]
        return self._engine_id

    def verify(self, name: str, cedar_statement: str) -> PolicyVerification:
        """Create a policy under FAIL_ON_ANY_FINDINGS; automated reasoning runs at create time."""
        if not self._engine_id:
            raise RuntimeError("call provision() first")
        try:
            resp = self._client.create_policy(
                name=name,
                policyEngineId=self._engine_id,
                definition={"cedar": {"statement": cedar_statement}},
                validationMode="FAIL_ON_ANY_FINDINGS",
                enforcementMode="LOG_ONLY",
            )
        except Exception as exc:  # noqa: BLE001 - a rejected policy surfaces as a client error
            return PolicyVerification(
                accepted=False, status="REJECTED", findings=(f"{type(exc).__name__}: {exc}"[:300],)
            )
        self._policies.append((self._engine_id, resp["policyId"]))
        findings = tuple(str(r)[:200] for r in resp.get("statusReasons", []))
        return PolicyVerification(
            accepted=resp.get("status") in ("CREATING", "ACTIVE"),
            status=resp.get("status", "?"),
            findings=findings,
            policy_id=resp["policyId"],
        )

    def cleanup(self) -> None:
        for engine_id, policy_id in self._policies:
            try:
                self._client.delete_policy(policyEngineId=engine_id, policyId=policy_id)
            except Exception:  # noqa: BLE001 - cleanup is best-effort; ids are printed on stage
                pass
        self._policies.clear()
        if self._engine_id:
            try:
                self._client.delete_policy_engine(policyEngineId=self._engine_id)
            except Exception:  # noqa: BLE001
                pass
            self._engine_id = None


def ar_guardrail_id() -> str | None:
    """Guardrail with an Automated Reasoning policy attached, if the presenter created one."""
    return os.environ.get("SEC310_AR_GUARDRAIL_ID")
