"""Opt-in live adapters for the on-stage "prove it" stage.

Everything in this module makes real AWS calls. Nothing is imported or constructed on the
offline path. Region and credentials come from the standard AWS SDK chain; identifiers come
from the environment (see ``model.BedrockModel`` and ``guardrails.BedrockGuardrail``).

``GuardrailChecks``
    The agentic guardrail API (``InvokeGuardrailChecks``): prompt-attack screening of a
    *proposed tool call* before it executes, and of a tool's result before it enters the
    context. Only the argument *values* are screened: they are the one part of a tool call
    that untrusted data can reach, and the classifier scores an instruction-shaped wrapper
    such as ``"proposed tool call: ..."`` as an attack on its own (observed 0.8). The service
    returns a severity score per requested category (discrete, 0 to 1); the score itself
    blocks nothing. The threshold is an application decision, so it is explicit here. An
    incomplete evaluation is UNAVAILABLE, never a clean pass.

``CedarPolicyGate``
    AgentCore Policy control plane (``bedrock-agentcore-control``). Creating a policy under
    ``validationMode=FAIL_ON_ANY_FINDINGS`` runs schema checks and automated-reasoning
    semantic validation. Two kinds of verdict exist, both observed live (2026-10-08): the
    parser rejects some statements synchronously with a ``ValidationException`` (for example
    an unconstrained ``resource``), and everything else is asynchronous: the call returns
    ``CREATING`` and the policy settles to ``ACTIVE`` or ``CREATE_FAILED`` with
    ``statusReasons``. A verdict is read from the response or the terminal state; any other
    failure (throttling, access, transport) is an operational error, never a verdict. The
    throwaway engine and policies are deleted afterwards and anything left behind is
    reported, not hidden.

``GatewayClient``
    Signed MCP calls to an AgentCore Gateway whose policy engine is in ENFORCE mode (set up by
    ``scripts/live_gateway.py``). This is where Cedar and Dogwood decide: the same tool call is
    allowed or denied depending on the arguments and on what happened earlier in the policy
    session. Each decision comes back as an MCP result or a JSON-RPC error; the client reports
    both faithfully and never retries.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
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
        """Screen the attacker-reachable part of a proposed tool call: its string values.

        The tool name and argument keys come from the application's own schema. Numbers and
        booleans carry no instructions. If nothing is screenable the result says so.
        """
        values = _string_values(arguments)
        if not values:
            return CheckResult(blocked=False, reasons=("nothing_to_screen",))
        return self._check("\n".join(values))

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


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        return [v for item in value.values() for v in _string_values(item)]
    if isinstance(value, (list, tuple)):
        return [v for item in value for v in _string_values(item)]
    return []


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


# Cedar for AgentCore Policy, as the service judged them on an engine with no gateway attached
# (observed 2026-10-08, us-east-1). Actions are gateway tools and resources are gateways, so a
# bare engine has no tool schema: only gateway-wide statements get as far as semantic
# validation, and anything that touches tool arguments fails the schema check. Accepted,
# enforced policies live on the engine that ``scripts/live_gateway.py`` attaches to a real gateway.
PERMIT_ALL_CEDAR = "permit(principal, action, resource);"
"""Rejected synchronously by the parser: an unconstrained resource is not allowed."""
PERMIT_ALL_GATEWAYS_CEDAR = "permit(principal, action, resource is AgentCore::Gateway);"
"""Settles CREATE_FAILED, automated reasoning: overly permissive."""
FORBID_ALL_GATEWAYS_CEDAR = "forbid(principal, action, resource is AgentCore::Gateway);"
"""Settles CREATE_FAILED, automated reasoning: overly restrictive."""
SCOPED_WITHOUT_GATEWAY_CEDAR = (
    "permit(principal, action, resource is AgentCore::Gateway) "
    'when { context.input.account_id == "acct-a" };'
)
"""Settles CREATE_FAILED, schema check: no attached gateway defines ``input.account_id``."""

_TERMINAL = {"ACTIVE", "CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}
# Engine and policy names: letters, digits, underscores; no hyphens (service constraint).
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,47}")


def _valid_name(name: str, what: str) -> str:
    # fullmatch: a `$` anchor would accept a trailing newline, and that would reach the service.
    if not _NAME.fullmatch(name):
        raise PolicyGateError(f"{what} name {name!r} must match ^{_NAME.pattern}$")
    return name


class CedarPolicyGate:
    """AgentCore Policy control plane: machine-checked Cedar before enforcement."""

    def __init__(
        self,
        engine_name: str = "sec310_demo",
        client=None,
        *,
        deadline_s: float = 180.0,
        poll_s: float = 3.0,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._engine_name = _valid_name(engine_name, "policy engine")
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
        """Use an existing engine (one with a gateway attached). Never deleted here.

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
            raise PolicyGateError("call provision() or attach() first")
        name = _valid_name(name, "policy")
        try:
            resp = self._client.create_policy(
                name=name,
                policyEngineId=self._engine_id,
                definition={"cedar": {"statement": cedar_statement}},
                validationMode="FAIL_ON_ANY_FINDINGS",
                enforcementMode="LOG_ONLY",
            )
        except Exception as exc:  # noqa: BLE001 - sorted into verdict vs operational below
            if _error_code(exc) == "ValidationException":
                # The parser judged the statement itself (parameters are validated locally).
                return PolicyVerification(
                    accepted=False, status="REJECTED", findings=(_error_message(exc),)
                )
            raise PolicyGateError(f"{_error_code(exc)}: {exc}") from exc
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


@dataclass(frozen=True)
class GatewayDecision:
    """One tool call as the gateway decided it."""

    allowed: bool
    http_status: int
    detail: str  # tool output when allowed; the gateway's reason when not

    @property
    def denied_by_policy(self) -> bool:
        return not self.allowed and "policy" in self.detail.lower()


class GatewayClient:
    """SigV4-signed MCP client for one AgentCore Gateway (AWS_IAM inbound authorization)."""

    PROTOCOL_VERSION = "2025-03-26"  # the version the gateway accepted on 2026-10-08
    SESSION_HEADER = "x-amzn-bedrock-agentcore-policy-session-id"

    def __init__(
        self,
        url: str,
        *,
        session=None,
        transport: Callable[[urllib.request.Request], tuple[int, bytes]] | None = None,
    ) -> None:
        self.url = url
        if transport is None:
            import boto3  # lazy

            session = session or boto3.session.Session()
            self._credentials = session.get_credentials()
            self._region = session.region_name
        self._transport = transport or self._send
        self._ids = 0

    def list_tools(self, policy_session: str | None) -> list[str]:
        status, body = self._rpc("tools/list", {}, policy_session)
        if "error" in body:
            raise RuntimeError(f"tools/list failed ({status}): {body['error']}")
        return [t["name"] for t in body.get("result", {}).get("tools", [])]

    def call_tool(self, name: str, arguments: dict, policy_session: str | None) -> GatewayDecision:
        status, body = self._rpc(
            "tools/call", {"name": name, "arguments": arguments}, policy_session
        )
        if "error" in body:
            err = body["error"]
            return GatewayDecision(False, status, f"{err.get('code')}: {err.get('message', '')}")
        result = body.get("result", {})
        text = " ".join(
            c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"
        )
        return GatewayDecision(not result.get("isError", False), status, text or json.dumps(result))

    # -- plumbing -----------------------------------------------------------------------------
    def _rpc(self, method: str, params: dict, policy_session: str | None) -> tuple[int, dict]:
        self._ids += 1
        data = json.dumps(
            {"jsonrpc": "2.0", "id": self._ids, "method": method, "params": params}
        ).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.PROTOCOL_VERSION,
        }
        if policy_session:
            headers[self.SESSION_HEADER] = policy_session
        request = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        status, raw = self._transport(request)
        try:
            return status, json.loads(raw.decode())
        except ValueError:
            return status, {
                "error": {"code": status, "message": raw.decode(errors="replace")[:300]}
            }

    def _send(self, request: urllib.request.Request) -> tuple[int, bytes]:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest

        signed = AWSRequest(
            method="POST",
            url=request.full_url,
            data=request.data,
            headers=dict(request.header_items()),
        )
        SigV4Auth(
            self._credentials.get_frozen_credentials(), "bedrock-agentcore", self._region
        ).add_auth(signed)
        for k, v in signed.headers.items():
            request.add_header(k, v)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


def gateway_url() -> str | None:
    """MCP endpoint of the enforcement gateway created by ``scripts/live_gateway.py``."""
    return os.environ.get("SEC310_GATEWAY_URL")


def _error_code(exc: BaseException) -> str:
    """Service error code when the SDK supplies one, else the exception type name."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return str(code)
    return type(exc).__name__


def _error_message(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        message = response.get("Error", {}).get("Message")
        if message:
            return str(message)
    return str(exc)


def ar_guardrail_id() -> str | None:
    """Guardrail with an Automated Reasoning policy attached, if the presenter created one."""
    return os.environ.get("SEC310_AR_GUARDRAIL_ID")
