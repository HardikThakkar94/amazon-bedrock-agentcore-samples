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
    """One tool call as the gateway decided it, classified so a transport failure can never
    satisfy an expectation of a policy denial (or of an allow)."""

    kind: str  # allowed | policy_denied | invalid_request | tool_error | transport
    http_status: int
    detail: str  # tool output when allowed; the gateway's reason or the failure otherwise

    @property
    def allowed(self) -> bool:
        return self.kind == "allowed"


# JSON-RPC error codes the gateway returned on 2026-10-08.
_POLICY_DENIED = -32002  # "Tool call not allowed due to policy enforcement [...]"
_INVALID_REQUEST = (
    -32006
)  # "Policy Evaluation rejected the request as invalid [sessionId is required ...]"


class GatewayClient:
    """SigV4-signed MCP client for one AgentCore Gateway (AWS_IAM inbound authorization).

    Only an HTTP 2xx carrying a JSON-RPC ``result`` object counts as a tool outcome; anything
    else is a transport failure, reported as such. Nothing is retried.
    """

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
        if not (200 <= status < 300) or not isinstance(body.get("result"), dict):
            raise RuntimeError(f"tools/list failed: HTTP {status} {json.dumps(body)[:300]}")
        tools = body["result"].get("tools")
        if not isinstance(tools, list):
            raise RuntimeError(f"tools/list returned no tools list: {json.dumps(body)[:300]}")
        return [t["name"] for t in tools]

    def call_tool(self, name: str, arguments: dict, policy_session: str | None) -> GatewayDecision:
        status, body = self._rpc(
            "tools/call", {"name": name, "arguments": arguments}, policy_session
        )
        error = body.get("error")
        if isinstance(error, dict):
            code, message = error.get("code"), str(error.get("message", ""))
            if code == _POLICY_DENIED:
                kind = "policy_denied"
            elif code == _INVALID_REQUEST:
                kind = "invalid_request"
            else:
                kind = "transport"
            return GatewayDecision(kind, status, f"{code}: {message}")
        result = body.get("result")
        if not (200 <= status < 300) or not isinstance(result, dict) or "isError" not in result:
            return GatewayDecision("transport", status, f"HTTP {status} {json.dumps(body)[:200]}")
        text = " ".join(
            c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"
        )
        if result["isError"]:
            return GatewayDecision("tool_error", status, text or json.dumps(result))
        return GatewayDecision("allowed", status, text or json.dumps(result))

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


@dataclass(frozen=True)
class PolicyDecisionCounts:
    """What the policy engine itself reports having decided, from CloudWatch.

    ``datapoints`` is the number of real datapoints CloudWatch returned in the window. Zero
    means "nothing recorded yet" (metrics lag the calls by a few minutes); it is not the same
    as counts that are zero, and discovering a policy's historical series does not count.
    ``by_policy`` lists only policies with at least one datapoint in the window.
    """

    allow: int
    deny: int
    no_determining_policy: int
    by_policy: dict[str, dict[str, int]]  # policy id -> {"allow": n, "deny": n}
    datapoints: int

    @property
    def total(self) -> int:
        return self.allow + self.deny


class MetricReadError(RuntimeError):
    """CloudWatch answered, but not with a complete result: an in-band error status, a
    PartialData result with no way to continue, or an operation-level message. Never a count."""


def _window(hours: float, now: float | None):
    import datetime as dt

    end = dt.datetime.fromtimestamp(now, tz=dt.UTC) if now is not None else dt.datetime.now(dt.UTC)
    return end - dt.timedelta(hours=hours), end


def _sum_query(qid: str, namespace: str, metric: str, dims: list[dict], period: int) -> dict:
    return {
        "Id": qid,
        "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": dims},
            "Period": period,
            "Stat": "Sum",
        },
    }


class MetricReader:
    """GetMetricData, read completely: every page followed, values accumulated per query id,
    datapoints counted separately from values. An error status, an incomplete result with no
    continuation, or an operation-level message raises; it is never a count."""

    def __init__(self, client) -> None:
        self._client = client

    def read(self, queries: list[dict], start, end) -> tuple[dict[str, int], dict[str, int]]:
        sums: dict[str, int] = {}
        points: dict[str, int] = {}
        for i in range(0, len(queries), 100):  # GetMetricData takes at most 100 queries
            self._read_batch(queries[i : i + 100], start, end, sums, points)
        return sums, points

    def _read_batch(self, batch, start, end, sums: dict[str, int], points: dict[str, int]) -> None:
        kwargs = {"MetricDataQueries": batch, "StartTime": start, "EndTime": end}
        status: dict[str, str] = {}
        while True:
            resp = self._client.get_metric_data(**kwargs)
            if resp.get("Messages"):
                raise MetricReadError(
                    "GetMetricData returned messages: "
                    + "; ".join(f"{m.get('Code')}: {m.get('Value')}" for m in resp["Messages"])
                )
            for r in resp.get("MetricDataResults", []):
                values = r.get("Values", [])
                sums[r["Id"]] = sums.get(r["Id"], 0) + int(sum(values))
                points[r["Id"]] = points.get(r["Id"], 0) + len(values)
                status[r["Id"]] = r.get("StatusCode", "missing")
                if status[r["Id"]] in ("InternalError", "Forbidden"):
                    detail = "; ".join(
                        f"{m.get('Code')}: {m.get('Value')}" for m in r.get("Messages", [])
                    )
                    raise MetricReadError(
                        f"GetMetricData result {r['Id']} is {status[r['Id']]}: {detail or 'no detail'}"
                    )
            token = resp.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
        incomplete = sorted(q["Id"] for q in batch if status.get(q["Id"]) != "Complete")
        if incomplete:
            raise MetricReadError(
                f"GetMetricData ended with incomplete results and no continuation: {incomplete}"
            )

    def series(self, namespace: str, metric: str, dims: list[dict] | None = None):
        """Every metric series CloudWatch remembers for this name (discovery, not data)."""
        kwargs = {"Namespace": namespace, "MetricName": metric}
        if dims:
            kwargs["Dimensions"] = dims
        for page in self._client.get_paginator("list_metrics").paginate(**kwargs):
            yield from page.get("Metrics", [])


class PolicyObserver:
    """Reads AgentCore Policy's own decision metrics (published by default, no setup).

    Namespace ``AWS/Bedrock-AgentCore``, operation ``AuthorizeAction``: ``AllowDecisions``,
    ``DenyDecisions`` and ``NoDeterminingPolicies`` per policy engine, and ``AllowDecisions`` /
    ``DenyDecisions`` per policy id. The per-policy series carry the engine as a dimension
    (observed 2026-10-09: OperationName, Policy, PolicyEngine, TargetResource), so every row
    here belongs to the same engine as the totals. Metrics lag the calls by a few minutes.
    """

    NAMESPACE = "AWS/Bedrock-AgentCore"

    def __init__(self, client=None) -> None:
        if client is None:
            import boto3  # lazy

            client = boto3.client("cloudwatch")
        self._client = client

    def decisions(
        self,
        engine_id: str,
        *,
        gateway_id: str | None = None,
        hours: float = 3.0,
        now: float | None = None,
    ) -> PolicyDecisionCounts:
        start, end = _window(hours, now)
        period = int(hours * 3600)
        engine_dims = [
            {"Name": "OperationName", "Value": "AuthorizeAction"},
            {"Name": "PolicyEngine", "Value": engine_id},
        ]
        queries = [
            {
                "Id": "allow",
                "MetricStat": {
                    "Metric": {
                        "Namespace": self.NAMESPACE,
                        "MetricName": "AllowDecisions",
                        "Dimensions": engine_dims,
                    },
                    "Period": period,
                    "Stat": "Sum",
                },
            },
            {
                "Id": "deny",
                "MetricStat": {
                    "Metric": {
                        "Namespace": self.NAMESPACE,
                        "MetricName": "DenyDecisions",
                        "Dimensions": engine_dims,
                    },
                    "Period": period,
                    "Stat": "Sum",
                },
            },
            {
                "Id": "nodet",
                "MetricStat": {
                    "Metric": {
                        "Namespace": self.NAMESPACE,
                        "MetricName": "NoDeterminingPolicies",
                        "Dimensions": engine_dims,
                    },
                    "Period": period,
                    "Stat": "Sum",
                },
            },
        ]
        by_policy: dict[str, dict[str, int]] = {}
        policy_queries: list[tuple[str, str, str]] = []  # (query id, policy id, kind)
        per_policy_dims = {"OperationName", "Policy", "PolicyEngine", "TargetResource"}
        for metric, kind in (("AllowDecisions", "allow"), ("DenyDecisions", "deny")):
            for page in self._client.get_paginator("list_metrics").paginate(
                Namespace=self.NAMESPACE, MetricName=metric, Dimensions=engine_dims
            ):
                for m in page.get("Metrics", []):
                    dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
                    if set(dims) == per_policy_dims and dims["PolicyEngine"] == engine_id:
                        if gateway_id and dims["TargetResource"] != gateway_id:
                            continue
                        qid = f"p{len(policy_queries)}"
                        policy_queries.append((qid, dims["Policy"], kind))
                        queries.append(
                            {
                                "Id": qid,
                                "MetricStat": {
                                    "Metric": {
                                        "Namespace": self.NAMESPACE,
                                        "MetricName": metric,
                                        "Dimensions": m["Dimensions"],
                                    },
                                    "Period": period,
                                    "Stat": "Sum",
                                },
                            }
                        )
        sums, points = MetricReader(self._client).read(queries, start, end)
        for qid, policy_id, kind in policy_queries:
            if points.get(qid, 0) == 0:
                continue  # a series that exists but has no datapoints in this window
            by_policy.setdefault(policy_id, {"allow": 0, "deny": 0})[kind] += sums[qid]
        return PolicyDecisionCounts(
            sums.get("allow", 0),
            sums.get("deny", 0),
            sums.get("nodet", 0),
            by_policy,
            datapoints=sum(points.values()),
        )


@dataclass(frozen=True)
class GuardrailCounts:
    """What CloudWatch recorded for one guardrail: ``AWS/Bedrock/Guardrails``, dimensions
    GuardrailArn + GuardrailVersion (observed 2026-10-12). ``intervened`` is the service's own
    ``InvocationsIntervened`` count: for an Automated Reasoning guardrail it counts checks that
    produced findings even when the returned action was NONE, so it is reported, not interpreted.
    ``check_invocations`` is ``CheckInvocations`` for InvokeGuardrailChecks (CheckType PromptAttack),
    which is account-wide, not per guardrail."""

    guardrail_id: str
    invocations: int
    intervened: int
    text_units: int
    datapoints: int


class GuardrailObserver:
    NAMESPACE = "AWS/Bedrock/Guardrails"

    def __init__(self, client=None) -> None:
        if client is None:
            import boto3  # lazy

            client = boto3.client("cloudwatch")
        self._reader = MetricReader(client)

    def counts(
        self, guardrail_ids: list[str], *, hours: float = 3.0, now: float | None = None
    ) -> tuple[list[GuardrailCounts], int | None]:
        """Per guardrail (every version CloudWatch has seen for it), plus the account-wide
        prompt-attack CheckInvocations count (None when no series exists)."""
        start, end = _window(hours, now)
        period = int(hours * 3600)
        queries: list[dict] = []
        owners: list[tuple[str, str, str]] = []  # (query id, guardrail id, kind)
        for series in self._reader.series(self.NAMESPACE, "Invocations"):
            dims = {d["Name"]: d["Value"] for d in series["Dimensions"]}
            if set(dims) != {"GuardrailArn", "GuardrailVersion"}:
                continue
            gid = dims["GuardrailArn"].rsplit("/", 1)[-1]
            if gid not in guardrail_ids:
                continue
            for metric, kind in (
                ("Invocations", "invocations"),
                ("InvocationsIntervened", "intervened"),
                ("TextUnitCount", "text_units"),
            ):
                qid = f"g{len(owners)}"
                owners.append((qid, gid, kind))
                queries.append(
                    _sum_query(qid, self.NAMESPACE, metric, series["Dimensions"], period)
                )
        check_dims = [
            {"Name": "CheckType", "Value": "PromptAttack"},
            {"Name": "Operation", "Value": "InvokeGuardrailChecks"},
        ]
        has_checks = any(
            True for _ in self._reader.series(self.NAMESPACE, "CheckInvocations", check_dims)
        )
        if has_checks:
            queries.append(
                _sum_query("checks", self.NAMESPACE, "CheckInvocations", check_dims, period)
            )
        if not queries:
            return [], None
        sums, points = self._reader.read(queries, start, end)
        per: dict[str, dict[str, int]] = {}
        for qid, gid, kind in owners:
            row = per.setdefault(
                gid, {"invocations": 0, "intervened": 0, "text_units": 0, "datapoints": 0}
            )
            row[kind] += sums.get(qid, 0)
            row["datapoints"] += points.get(qid, 0)
        rows = [
            GuardrailCounts(
                gid, r["invocations"], r["intervened"], r["text_units"], r["datapoints"]
            )
            for gid in guardrail_ids
            if (r := per.get(gid))
        ]
        checks = sums.get("checks") if has_checks and points.get("checks", 0) else None
        return rows, checks


_INJECTED_URL = "exfil.example.net"


@dataclass(frozen=True)
class InvocationRecord:
    """One Bedrock model invocation log entry (schemaType ModelInvocationLog 1.0, observed
    2026-10-12): the platform's copy of what the model was asked and what it answered."""

    timestamp: str
    model_id: str
    operation: str
    caller: str
    input_tokens: int | None
    output_tokens: int | None
    stop_reason: str
    output_text: str
    error_code: str | None = None

    @property
    def carries(self) -> list[str]:
        """Structured proposals/links, not a refusal merely quoting the attack. No action is
        inferred to have executed from a model invocation log."""
        from sec310_sample.model import _unfence

        try:
            payload = json.loads(_unfence(self.output_text))
        except (ValueError, TypeError):
            return []
        if not isinstance(payload, dict):
            return []
        found = []
        links, actions = payload.get("links"), payload.get("proposed_actions")
        if isinstance(links, list) and any(_INJECTED_URL in str(link) for link in links):
            found.append("attacker URL in links (not a network transfer)")
        if isinstance(actions, list) and any(
            isinstance(a, dict) and a.get("operation") == "delete_rule" for a in actions
        ):
            found.append("delete_rule proposal (not proof of execution)")
        return found


class LogReadError(RuntimeError):
    """CloudWatch Logs could be queried but a record was not what the platform documents."""


class InvocationLogReader:
    def __init__(self, client=None) -> None:
        if client is None:
            import boto3  # lazy

            client = boto3.client("logs")
        self._client = client

    def records(
        self,
        log_group: str,
        *,
        hours: float = 3.0,
        now: float | None = None,
        run_id: str | None = None,
    ) -> list[InvocationRecord]:
        out: list[InvocationRecord] = []
        for event in _log_events(self._client, log_group, hours, now):
            try:
                rec = json.loads(event["message"])
            except ValueError as exc:
                if (
                    event["message"].strip()
                    == "Permissions are correctly set for Amazon Bedrock logs."
                ):
                    continue
                raise LogReadError("unreadable model invocation log record") from exc
            if not isinstance(rec, dict) or rec.get("schemaType") != "ModelInvocationLog":
                raise LogReadError("unexpected model invocation log schema")
            if run_id and rec.get("requestMetadata", {}).get("sec310_run") != run_id:
                continue
            output = rec.get("output", {}).get("outputBodyJson")
            error_code = rec.get("errorCode")
            if error_code:
                output = {}  # A service-rejected attempt has no model answer; it is still a valid log.
            elif not isinstance(output, dict):
                raise LogReadError(
                    "invocation output is absent or not inline; inspect its S3 reference"
                )
            message = output.get("output", {}).get("message", {})
            parts = []
            for block in message.get("content", []):
                if "text" in block:
                    parts.append(block["text"])
                if "toolUse" in block:
                    parts.append(json.dumps(block["toolUse"].get("input", {})))
            # A text preamble alongside toolUse is not part of the structured response.
            tool_input = next(
                (
                    b["toolUse"].get("input", {})
                    for b in message.get("content", [])
                    if "toolUse" in b
                ),
                None,
            )
            if tool_input is not None:
                parts = [json.dumps(tool_input)]
            identity = rec.get("identity", {}).get("arn", "")
            role = (
                identity.split(":assumed-role/", 1)[1].split("/", 1)[0]
                if ":assumed-role/" in identity
                else "[masked]"
            )
            out.append(
                InvocationRecord(
                    timestamp=rec.get("timestamp", ""),
                    model_id=rec.get("modelId", "?"),
                    operation=rec.get("operation", "?"),
                    caller=role,
                    input_tokens=rec.get("input", {}).get("inputTokenCount"),
                    output_tokens=rec.get("output", {}).get("outputTokenCount"),
                    stop_reason=str(output.get("stopReason", "?")),
                    output_text="".join(parts),
                    error_code=str(error_code) if error_code else None,
                )
            )
        return out


@dataclass(frozen=True)
class GatewayRequest:
    """One MCP request through the gateway, assembled from its vended log lines (observed
    2026-10-12: Started processing / policy / Tool Execution Denied / Successfully processed,
    all sharing a request_id). ``decision`` and ``reason`` come from the engine's own
    ``body.policy`` record, not from the response text."""

    timestamp_ms: int
    method: str
    tool: str
    account_id: str
    decision: str  # ALLOW | DENY | REJECTED | n/a
    reason: str
    determining_policies: tuple[str, ...]
    temporal: bool | None
    latency_ms: int | None


def _field(body: str, key: str) -> str:
    match = re.search(rf"\b{key}=([^,{{}}]+)", body)
    return match.group(1).strip() if match else ""


class GatewayLogReader:
    def __init__(self, client=None) -> None:
        if client is None:
            import boto3  # lazy

            client = boto3.client("logs")
        self._client = client

    def requests(
        self, log_group: str, *, hours: float = 3.0, now: float | None = None
    ) -> list[GatewayRequest]:
        grouped: dict[str, list[dict]] = {}
        for event in _log_events(self._client, log_group, hours, now):
            try:
                rec = json.loads(event["message"])
            except ValueError as exc:
                raise LogReadError("gateway log line is not JSON") from exc
            if not isinstance(rec, dict) or not isinstance(rec.get("body"), dict):
                raise LogReadError("gateway log record is not an object with a body")
            grouped.setdefault(rec.get("request_id", event.get("eventId", "?")), []).append(rec)
        out = []
        for lines in grouped.values():
            lines.sort(key=lambda r: r.get("event_timestamp", 0))
            request = next(
                (r["body"]["requestBody"] for r in lines if "requestBody" in r.get("body", {})), ""
            )
            policy = next(
                (r["body"]["policy"] for r in lines if "policy" in r.get("body", {})), None
            )
            denied = next(
                (
                    r["body"]["log"]
                    for r in lines
                    if str(r.get("body", {}).get("log", "")).startswith("Tool Execution Denied")
                ),
                None,
            )
            method = _field(request, "method") or "?"
            if policy:
                decision, reason = str(policy.get("decision", "?")), str(policy.get("reason", ""))
                determining = tuple(
                    p if isinstance(p, str) else str(p.get("policyId", p))
                    for p in policy.get("determiningPolicies", [])
                )
                temporal = policy.get("temporal_evaluation_invoked")
                latency = policy.get("latencyMs")
            elif denied:
                decision, reason, determining, temporal, latency = (
                    "REJECTED"
                    if "rejected the request as invalid" in denied
                    else "UNCLASSIFIED_ERROR",
                    denied.split("Tool Execution Denied: ", 1)[-1],
                    (),
                    None,
                    None,
                )
            else:
                decision, reason, determining, temporal, latency = "n/a", "", (), None, None
            out.append(
                GatewayRequest(
                    timestamp_ms=int(lines[0].get("event_timestamp", 0)),
                    method=method,
                    tool=_field(request, "name"),
                    account_id=_field(request, "account_id"),
                    decision=decision,
                    reason=reason,
                    determining_policies=determining,
                    temporal=temporal,
                    latency_ms=latency,
                )
            )
        out.sort(key=lambda r: r.timestamp_ms)
        return out


def _log_events(client, log_group: str, hours: float, now: float | None):
    """Every event in the window, every page. FilterLogEvents has no botocore paginator."""
    start, end = _window(hours, now)
    kwargs = {
        "logGroupName": log_group,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
    }
    seen_tokens: set[str] = set()
    seen_events: set[str] = set()
    while True:
        resp = client.filter_log_events(**kwargs)
        for event in resp.get("events", []):
            eid = event.get("eventId")
            if eid and eid in seen_events:
                continue
            if eid:
                seen_events.add(eid)
            yield event
        token = resp.get("nextToken")
        if not token:
            return
        if token in seen_tokens:
            raise LogReadError("FilterLogEvents repeated a continuation token; read is incomplete")
        seen_tokens.add(token)
        kwargs["nextToken"] = token


def invocation_log_group() -> str | None:
    """Where Bedrock model invocation logging delivers (set by ``scripts/live_logging.py up``)."""
    return os.environ.get("SEC310_INVOCATION_LOG_GROUP")


def gateway_log_group() -> str | None:
    """Where the gateway's vended logs deliver (set by ``scripts/live_logging.py up``)."""
    return os.environ.get("SEC310_GATEWAY_LOG_GROUP")


def gateway_url() -> str | None:
    """MCP endpoint of the enforcement gateway created by ``scripts/live_gateway.py``."""
    return os.environ.get("SEC310_GATEWAY_URL")


def policy_engine_id() -> str | None:
    """Policy engine behind that gateway, for reading its decision metrics back."""
    return os.environ.get("SEC310_POLICY_ENGINE_ID")


def gateway_id_from_url(url: str | None) -> str | None:
    """``https://<gatewayId>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp`` -> gatewayId."""
    if not url:
        return None
    host = url.split("//", 1)[-1].split("/", 1)[0]
    return host.split(".", 1)[0] if ".gateway." in host else None


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
