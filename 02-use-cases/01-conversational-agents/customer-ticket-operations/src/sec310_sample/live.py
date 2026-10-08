"""Opt-in live adapters for the on-stage "prove it" stage.

Everything in this module makes real AWS calls. Nothing is imported or constructed on the
offline path. Region and credentials come from the standard AWS SDK chain; identifiers come
from the environment (see ``model.BedrockModel`` and ``guardrails.BedrockGuardrail``).

``GuardrailChecks``
    The agentic guardrail API (``InvokeGuardrailChecks``): prompt-attack screening of a
    *proposed tool call* before it executes, and of a tool's result before it enters the
    context. The service returns a severity score per requested category (discrete, 0 to 1);
    the score itself blocks nothing. The threshold is an application decision, so it is
    explicit here. An incomplete evaluation is UNAVAILABLE, never a clean pass.

``CedarPolicyGate``
    AgentCore Policy control plane (``bedrock-agentcore-control``). Creating a policy under
    ``validationMode=FAIL_ON_ANY_FINDINGS`` runs schema checks and automated-reasoning
    semantic validation. Creation is asynchronous: the call returns ``CREATING`` and the
    policy settles to ``ACTIVE`` or ``CREATE_FAILED`` with ``statusReasons``. A verdict is
    read from the terminal state; a transport or service failure is an operational error,
    not a verdict. The throwaway engine and policies are deleted afterwards and anything left
    behind is reported, not hidden.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

# Discrete severity scores: 0, 0.2, 0.4, 0.6, 0.8, 1.0. At or above this value the sample
# treats a proposed tool call as a prompt attack. Benign content scores 0.
PROMPT_ATTACK_THRESHOLD = 0.6
PROMPT_ATTACK_CATEGORIES = ("PROMPT_INJECTION", "JAILBREAK")


@dataclass(frozen=True)
class CheckResult:
    """One screening result. A signal for the application, not an authorization."""

    blocked: bool
    scores: dict[str, float] = field(default_factory=dict)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    unavailable: bool = False


class GuardrailChecks:
    """Prompt-attack screening of tool traffic (``bedrock-runtime:InvokeGuardrailChecks``)."""

    def __init__(self, client=None, threshold: float = PROMPT_ATTACK_THRESHOLD) -> None:
        if client is None:
            import boto3  # lazy: the offline path must not need it

            client = boto3.client("bedrock-runtime")
        self._client = client
        self.threshold = threshold

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
                checks={
                    "promptAttack": {
                        "categories": [{"category": c} for c in PROMPT_ATTACK_CATEGORIES]
                    }
                },
            )
        except Exception as exc:  # noqa: BLE001 - any failure is "unavailable" to the caller
            return CheckResult(blocked=False, reasons=(type(exc).__name__,), unavailable=True)
        hits = resp.get("results", {}).get("promptAttack", {}).get("results", [])
        scores = {
            h["category"]: float(h["severityScore"])
            for h in hits
            if "category" in h and "severityScore" in h
        }
        missing = tuple(c for c in PROMPT_ATTACK_CATEGORIES if c not in scores)
        if missing:
            # The service did not evaluate what we asked for; that is not a clean pass.
            return CheckResult(
                blocked=False,
                scores=scores,
                reasons=tuple(f"not_evaluated:{c}" for c in missing),
                unavailable=True,
            )
        reasons = tuple(
            sorted(f"promptAttack:{c}={s:.1f}" for c, s in scores.items() if s >= self.threshold)
        )
        return CheckResult(blocked=bool(reasons), scores=scores, reasons=reasons)


class PolicyGateError(RuntimeError):
    """Operational failure (transport, service, timeout). Not a validation verdict."""


@dataclass(frozen=True)
class PolicyVerification:
    """Terminal outcome of policy creation under FAIL_ON_ANY_FINDINGS."""

    accepted: bool
    status: str
    findings: tuple[str, ...] = field(default_factory=tuple)
    policy_id: str | None = None


@dataclass
class CleanupReport:
    deleted: list[str] = field(default_factory=list)
    remaining: list[str] = field(default_factory=list)  # "kind id: error"

    @property
    def clean(self) -> bool:
        return not self.remaining


# Cedar for AgentCore Policy. Actions are gateway tools (``AgentCore::Action::"Target___tool"``)
# and resources are gateways, so a policy that names a specific tool only passes schema checks
# when the engine has a gateway attached that defines it. Permit-all needs no schema and is
# rejected by semantic validation as overly permissive. Both rejections are documented
# behaviour; an *accepted* policy needs the presenter's own gateway (see ``presenter_policy``).
PERMIT_ALL_CEDAR = "permit(principal, action, resource);"
UNDEFINED_TOOL_CEDAR = (
    'permit(principal, action == AgentCore::Action::"EvidenceTools___read_evidence", '
    "resource is AgentCore::Gateway);"
)


_TERMINAL = {"ACTIVE", "CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}


class CedarPolicyGate:
    """AgentCore Policy control plane: machine-checked Cedar before enforcement."""

    def __init__(
        self,
        engine_name: str = "sec310-demo",
        client=None,
        *,
        deadline_s: float = 180.0,
        poll_s: float = 3.0,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._engine_name = engine_name
        self._engine_id: str | None = None
        self._owns_engine = False
        self._policies: list[str] = []
        self._deadline_s = deadline_s
        self._poll_s = poll_s
        self._sleep = sleep or time.sleep  # resolved per instance so tests can patch time
        self._clock = clock or time.monotonic
        if client is None:
            import boto3  # lazy

            client = boto3.client("bedrock-agentcore-control")
        self._client = client

    @property
    def engine_id(self) -> str | None:
        return self._engine_id

    def provision(self) -> str:
        """Create a throwaway policy engine (owned, deleted by cleanup) and wait for ACTIVE."""
        resp = self._call(self._client.create_policy_engine, name=self._engine_name)
        self._engine_id = resp["policyEngineId"]
        self._owns_engine = True
        self._require_active_engine()
        return self._engine_id

    def attach(self, engine_id: str) -> str:
        """Use an existing engine (the presenter's, with a gateway attached). Never deleted here.

        Schema checks run against the gateways associated with an engine, so an *accepted*
        policy that names a tool can only be shown on an engine that has that gateway.
        """
        self._engine_id = engine_id
        self._owns_engine = False
        self._require_active_engine()
        return engine_id

    def _require_active_engine(self) -> None:
        engine = self._poll(
            lambda: self._call(self._client.get_policy_engine, policyEngineId=self._engine_id),
            what=f"policy engine {self._engine_id}",
        )
        if engine["status"] != "ACTIVE":
            raise PolicyGateError(
                f"policy engine {self._engine_id} is {engine['status']}: "
                f"{list(engine.get('statusReasons', []))}"
            )

    def verify(self, name: str, cedar_statement: str) -> PolicyVerification:
        """Create a policy under FAIL_ON_ANY_FINDINGS and read the terminal verdict."""
        if not self._engine_id:
            raise PolicyGateError("call provision() first")
        resp = self._call(
            self._client.create_policy,
            name=name,
            policyEngineId=self._engine_id,
            definition={"cedar": {"statement": cedar_statement}},
            validationMode="FAIL_ON_ANY_FINDINGS",
            enforcementMode="LOG_ONLY",
        )
        policy_id = resp["policyId"]
        self._policies.append(policy_id)
        policy = self._poll(
            lambda: self._call(
                self._client.get_policy, policyEngineId=self._engine_id, policyId=policy_id
            ),
            what=f"policy {name}",
        )
        return PolicyVerification(
            accepted=policy["status"] == "ACTIVE",
            status=policy["status"],
            findings=tuple(str(r) for r in policy.get("statusReasons", [])),
            policy_id=policy_id,
        )

    def cleanup(self) -> CleanupReport:
        """Delete the policies this gate created, then an engine it owns. Never raises.

        An attached (presenter-owned) engine is left alone. Anything that could not be removed
        is reported, not hidden.
        """
        report = CleanupReport()
        for policy_id in list(self._policies):
            if self._delete_policy(report, policy_id):
                self._policies.remove(policy_id)
        if not self._owns_engine:
            return report
        if self._engine_id and not self._policies:
            engine_id = self._engine_id
            if self._delete(
                report,
                f"policy engine {engine_id}",
                lambda: self._client.delete_policy_engine(policyEngineId=engine_id),
                lambda: self._client.get_policy_engine(policyEngineId=engine_id),
            ):
                self._engine_id = None
        elif self._engine_id:
            report.remaining.append(
                f"policy engine {self._engine_id}: not deleted while policies remain"
            )
        return report

    def _delete_policy(self, report: CleanupReport, policy_id: str) -> bool:
        engine_id = self._engine_id
        return self._delete(
            report,
            f"policy {policy_id}",
            lambda: self._client.delete_policy(policyEngineId=engine_id, policyId=policy_id),
            lambda: self._client.get_policy(policyEngineId=engine_id, policyId=policy_id),
        )

    # -- helpers ---------------------------------------------------------------------------
    @staticmethod
    def _call(fn, **kwargs):
        try:
            return fn(**kwargs)
        except Exception as exc:  # noqa: BLE001 - re-raised as operational, never as a verdict
            raise PolicyGateError(f"{type(exc).__name__}: {exc}") from exc

    def _poll(self, fetch: Callable[[], dict], *, what: str) -> dict:
        start = self._clock()
        while True:
            state = fetch()
            if state.get("status") in _TERMINAL:
                return state
            if self._clock() - start >= self._deadline_s:
                raise PolicyGateError(
                    f"{what} still {state.get('status')} after {self._deadline_s:.0f}s"
                )
            self._sleep(self._poll_s)

    def _delete(self, report: CleanupReport, what: str, delete, fetch) -> bool:
        """Issue the delete and wait until the resource is gone. True when confirmed."""
        try:
            delete()
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) != "ResourceNotFoundException":
                report.remaining.append(f"{what}: {_error_code(exc)}: {exc}")
                return False
        start = self._clock()
        while True:
            try:
                state = fetch()
            except Exception as exc:  # noqa: BLE001
                if _error_code(exc) == "ResourceNotFoundException":
                    report.deleted.append(what)
                    return True
                report.remaining.append(f"{what}: {_error_code(exc)}: {exc}")
                return False
            if state.get("status") == "DELETE_FAILED":
                report.remaining.append(
                    f"{what}: DELETE_FAILED {list(state.get('statusReasons', []))}"
                )
                return False
            if self._clock() - start >= self._deadline_s:
                report.remaining.append(
                    f"{what}: still {state.get('status')} after {self._deadline_s:.0f}s"
                )
                return False
            self._sleep(self._poll_s)


def _error_code(exc: BaseException) -> str:
    """Service error code when the SDK supplies one, else the exception type name."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return str(code)
    return type(exc).__name__


def ar_guardrail_id() -> str | None:
    """Guardrail with an Automated Reasoning policy attached, if the presenter created one."""
    return os.environ.get("SEC310_AR_GUARDRAIL_ID")


@dataclass(frozen=True)
class PresenterPolicy:
    engine_id: str
    statement: str


def presenter_policy() -> PresenterPolicy | None:
    """The accepted-policy example, if the presenter configured one.

    ``SEC310_POLICY_ENGINE_ID`` names an engine the presenter owns that has a gateway attached;
    ``SEC310_CEDAR_POLICY_FILE`` holds one statement naming a tool that gateway defines. Both
    are required: schema checks run against the engine's gateways, so a fresh engine cannot
    accept a tool policy. The engine is never deleted by the sample.
    """
    engine_id = os.environ.get("SEC310_POLICY_ENGINE_ID")
    path = os.environ.get("SEC310_CEDAR_POLICY_FILE")
    if not engine_id and not path:
        return None
    if not (engine_id and path):
        raise PolicyGateError(
            "SEC310_POLICY_ENGINE_ID and SEC310_CEDAR_POLICY_FILE must be set together: an accepted "
            "tool policy needs an engine with a gateway attached"
        )
    with open(path, encoding="utf-8") as fh:
        statement = fh.read().strip()
    if not statement:
        raise PolicyGateError(f"{path} is empty")
    return PresenterPolicy(engine_id=engine_id, statement=statement)
