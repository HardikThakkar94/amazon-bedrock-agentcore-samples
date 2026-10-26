"""SEC310 presenter API (Lambda function URL, AuthType=AWS_IAM, reachable only via CloudFront).

CloudFront's Lambda@Edge has already verified the Cognito session and forwards the access token
in ``x-sec310-access-token``; this function verifies its signature, issuer, audience and expiry
again (defence in depth) and takes the persona from the token's claims, never from the body.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import boto3
import runs
from jwt_verify import InvalidToken, verify

TICKETS = os.environ["TICKETS_TABLE"]
STATE = os.environ["STATE_TABLE"]
MAX_SUBJECT, MAX_BODY = 120, 2000
AGENT_TIMEOUT = 50  # seconds; CloudFront waits up to 60 for the API origin

_ddb = boto3.resource("dynamodb")
ISSUER = os.environ["ISSUER"]
# The web app client is created with the CloudFront site (a later root), so its ID is read from
# SSM on first use rather than baked in at deploy time.
_client_id: str | None = None


def client_id() -> str:
    global _client_id
    if _client_id is None:
        ssm = boto3.client("ssm")
        _client_id = ssm.get_parameter(Name=os.environ["CLIENT_ID_PARAM"])["Parameter"]["Value"]
    return _client_id


# The agent root deploys after this one; its runtime ARN and model are read from SSM on demand.
_agent: dict[str, str] = {}


def agent_config() -> dict[str, str]:
    if not _agent:
        ssm = boto3.client("ssm")
        prefix = os.environ["AGENT_PARAM_PREFIX"]
        for key in ("runtime_arn", "model_id"):
            try:
                _agent[key] = ssm.get_parameter(Name=f"{prefix}/{key}")["Parameter"]["Value"]
            except ssm.exceptions.ParameterNotFound as exc:
                _agent.clear()
                raise HttpError(503, "the agent is not deployed yet (make deploy-agent)") from exc
    return _agent


_tickets = _ddb.Table(TICKETS)
_state = _ddb.Table(STATE)
_events = _ddb.Table(os.environ["EVENTS_TABLE"])
RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
OWNER_SK = "0000000000000#api#owner"
# Seed tickets per customer: what Reset restores (mirrors infra/iac/roots/app/main.tf).
SEED = {
    "customer-a": {
        "A-41": ("Package arrived late", "Please explain the delay."),
        "A-42": ("Correct billing address", "Please update the postal code on my next invoice."),
    },
    "customer-b": {"B-77": ("Refund status", "When will my refund arrive?")},
}
_persona_cache: dict[str, tuple[float, dict[str, str]]] = {}

STAGES = ["v0", "v1", "v2", "v3", "v4", "v5"]
TITLES = {
    "v0": "Unsafe: model output executes",
    "v1": "Identity: bind operator and customer",
    "v2": "Validation: treat records as data",
    "v3": "Policy: authorize every effect",
    "v4": "Contain: halt on the first denied action",
    "v5": "Evidence: gate release on behavior",
}
LESSONS = {
    "v0": "VULNERABLE — no independent boundary; the ticket can close.",
    "v1": "STILL VULNERABLE — identity passes because this attack stays inside Customer A.",
    "v2": "STILL VULNERABLE — valid, screened JSON is still not permission to act.",
    "v3": "PROTECTED — action policy denies close_ticket; A-42 remains open.",
    "v4": "CONTAINED — the first denied action ends the run and the agent stays stopped until reset.",
    "v5": "EVIDENCE — the halt and the unchanged ticket are recorded; the release invariant passes.",
}


# Which controls each build turns on (mirrors src/sec310_agent/controls.py and the agent root).
CONTROLS = {
    "Inbound JWT authorizer (AgentCore Identity on Runtime and Gateway)": "v0",
    "AgentCore Policy: caller and tenant fence (Cedar)": "v1",
    "Amazon Bedrock Guardrails: prompt-attack screen on ticket text": "v2",
    "AgentCore Policy: forbid close_ticket for the summary task (Cedar)": "v3",
    "Stop on the first denial; durable stop checked at admission (agent hook)": "v4",
    "Release gate: AgentCore Evaluations must pass": "v5",
}


GATEWAY_OF = {"v0": "v0", "v1": "v1", "v2": "v1", "v3": "v3", "v4": "v3", "v5": "v3"}


def build_code(stage: str) -> dict[str, Any]:
    """The active build's controls, with its Cedar policies read back from AgentCore Policy."""
    n = STAGES.index(stage)
    controls = [{"name": k, "on": STAGES.index(v) <= n, "detail": ""} for k, v in CONTROLS.items()]
    engines = json.loads(agent_param("policy_engines", "{}"))
    engine = engines.get(stage)
    policies = []
    if engine:
        ctl = boto3.client("bedrock-agentcore-control")
        for item in ctl.list_policies(policyEngineId=engine).get("policies", []):
            p = ctl.get_policy(policyEngineId=engine, policyId=item["policyId"])
            d = p.get("definition", {})
            text = (d.get("cedar") or d.get("policy") or {}).get("statement", "")
            policies.append(
                {"name": p.get("name", ""), "status": p.get("status", ""), "statement": text}
            )
    return {
        "stage": stage,
        "title": TITLES[stage],
        "gateway": json.loads(agent_param("gateways", "{}")).get(GATEWAY_OF[stage], ""),
        "policy_engine": engine,
        "policies": sorted(policies, key=lambda p: p["name"]),
        "controls": controls,
    }


def agent_param(key: str, default: str) -> str:
    ssm = boto3.client("ssm")
    try:
        return ssm.get_parameter(Name=f"{os.environ['AGENT_PARAM_PREFIX']}/{key}")["Parameter"][
            "Value"
        ]
    except ssm.exceptions.ParameterNotFound:
        return default


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def access_token(event: dict[str, Any]) -> str:
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token = headers.get("x-sec310-access-token")
    if not token:
        raise HttpError(401, "missing session")
    return token


def persona(event: dict[str, Any]) -> dict[str, str]:
    token = access_token(event)
    cached = _persona_cache.get(token)
    if cached and cached[0] > time.time():
        return cached[1]
    try:
        claims = verify(token, ISSUER, client_id())
    except InvalidToken as exc:
        raise HttpError(401, "invalid session") from exc
    who = {
        "username": claims.get("username", ""),
        "sub": claims.get("sub", ""),
        "customer_id": claims.get("customer_id", ""),
        "role": claims.get("role", ""),
    }
    if not who["customer_id"] or who["role"] not in ("operator", "customer"):
        raise HttpError(403, "persona has no tenant or role")
    _persona_cache[token] = (min(time.time() + 60, claims["exp"]), who)
    return who


def require(who: dict[str, str], role: str) -> None:
    if who["role"] != role:
        raise HttpError(403, f"{role} only")


def all_tickets() -> list[dict[str, Any]]:
    """Every tenant's tickets (a demo-sized table): effects are diffed across tenants, so a
    cross-customer write is caught even though the operator's console shows only their own."""
    items, kwargs = [], {}
    while True:
        page = _tickets.scan(**kwargs)
        items += page["Items"]
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def tickets_for(customer_id: str) -> list[dict[str, Any]]:
    items = _tickets.query(
        KeyConditionExpression="customer_id = :c",
        ExpressionAttributeValues={":c": customer_id},
    )["Items"]
    return sorted(items, key=lambda t: t["ticket_id"])


def demo_state(customer_id: str) -> dict[str, Any]:
    item = _state.get_item(Key={"customer_id": customer_id}).get("Item")
    return item or {"customer_id": customer_id, "active_stage": "v0", "stop_requested": False}


def capture_state(st: dict[str, Any], tickets: list[dict[str, Any]]) -> dict[str, Any]:
    cap = json.loads(st["capture"]) if st.get("capture") else None
    return {
        "capture_available": cap is not None,
        "capture_stale": bool(cap) and cap["fingerprint"] != runs.fingerprint(tickets),
        "capture_source": cap and cap["stage"],
        "capture_calls": cap["calls"] if cap else [],
        "capture_run_id": cap and cap["run_id"],
    }


def other_tickets(who: dict[str, str], st: dict[str, Any]) -> list[dict[str, Any]]:
    """Tickets in another tenant that the last run tried to change: shown (subject and status
    only) so a cross-customer attempt is visible on the operator's screen, held or not."""
    run = json.loads(st["last_run"]) if st.get("last_run") else {}
    keys = {
        (x.get("customer_id"), x.get("target") or x.get("ticket_id"))
        for x in run.get("effects", []) + run.get("proposals", [])
    }
    out = []
    for cid, tid in sorted(k for k in keys if k[0] and k[1] and k[0] != who["customer_id"]):
        t = _tickets.get_item(Key={"customer_id": cid, "ticket_id": tid}).get("Item")
        if t:
            out.append(
                {
                    "ticket_id": tid,
                    "customer_id": cid,
                    "subject": t.get("subject", ""),
                    "status": t.get("status", "OPEN"),
                }
            )
    return out


def public_state(who: dict[str, str]) -> dict[str, Any]:
    st = demo_state(who["customer_id"])
    stage = st.get("active_stage", "v0")
    tickets = tickets_for(who["customer_id"])
    before = json.loads(st.get("before_tickets", "{}"))
    comparison = {}
    for t in tickets:
        after = {k: t.get(k, "") for k in ("subject", "body", "status")}
        prior = before.get(t["ticket_id"])
        changed = [f for f in after if prior is None or prior.get(f) != after[f]] if before else []
        comparison[t["ticket_id"]] = {
            "before": prior,
            "after": after,
            "changed": bool(changed),
            "changed_fields": changed,
        }
    return {
        "persona": who,
        "model": model_label(),
        "live_model": True,
        "guardrail": "Amazon Bedrock Guardrails",
        "busy": int(st.get("busy_until", 0)) > time.time(),
        "stop_requested": bool(st.get("stop_requested")),
        "stop_source": st.get("stop_source", "none"),
        "active_stage": stage,
        "active_title": TITLES[stage],
        "active_lesson": LESSONS[stage],
        **capture_state(st, tickets),
        "tickets": [
            {
                "ticket_id": t["ticket_id"],
                "customer_id": t["customer_id"],
                "subject": t.get("subject", ""),
                "body": t.get("body", ""),
                "status": t.get("status", "OPEN"),
                "submitted_by": t.get("submitted_by", "customer"),
                "untrusted": bool(t.get("untrusted", True)),
                "origin": t.get("origin", "seed"),
            }
            for t in tickets
        ],
        "store_comparison": comparison,
        "other_tickets": other_tickets(who, st),
        "store_change_source": st.get("store_change_source", "Clean reset"),
        "last_run": json.loads(st["last_run"]) if st.get("last_run") else None,
        "decisions": json.loads(st.get("decisions", "[]")),
        "observability": {
            "sec310_run": st.get("run_id"),
            "region": os.environ.get("AWS_REGION"),
            "invocation_log_group": os.environ.get("INVOCATION_LOG_GROUP"),
            "scope": "Agent on AgentCore Runtime; tools and policy at AgentCore Gateway",
        },
    }


def model_label() -> str:
    try:
        return f"AgentCore Runtime · {agent_config()['model_id']} · tools via AgentCore Gateway"
    except HttpError:
        return "AgentCore Runtime (agent not deployed yet)"


def invoke_agent(token: str, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """InvokeAgentRuntime over HTTPS with the user's own token (OAuth inbound, no SigV4)."""
    arn = agent_config()["runtime_arn"]
    region = arn.split(":")[3]
    url = (
        f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/"
        f"{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT"
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as resp:
            body = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode(errors="replace")
        raise RuntimeError(f"AgentCore Runtime returned {exc.code}: {detail}") from exc
    if not isinstance(body, dict) or "error" in body:
        raise RuntimeError(
            f"agent error: {str(body.get('error') if isinstance(body, dict) else body)[:200]}"
        )
    return body


def claim_run(customer_id: str) -> None:
    now = int(time.time())
    try:
        _state.update_item(
            Key={"customer_id": customer_id},
            UpdateExpression="SET busy_until = :until",
            ConditionExpression="attribute_not_exists(busy_until) OR busy_until < :now",
            ExpressionAttributeValues={":until": now + AGENT_TIMEOUT + 5, ":now": now},
        )
    except _state.meta.client.exceptions.ConditionalCheckFailedException as exc:
        raise HttpError(409, "an agent run is already in progress") from exc


def run_agent(who: dict[str, str], token: str, body: dict[str, Any]) -> dict[str, Any]:
    require(who, "operator")
    st = demo_state(who["customer_id"])
    stage = st.get("active_stage", "v0")  # the build is server state, never taken from the body
    mode = "replay" if body.get("mode") == "replay" else "live"
    agent_payload: dict[str, Any] = {"operator": who["username"], "stage": stage, "mode": mode}
    if mode == "replay":
        cap = capture_state(st, tickets_for(who["customer_id"]))
        if not cap["capture_available"]:
            raise HttpError(409, "nothing to replay yet: run the agent live first")
        if cap["capture_stale"]:
            raise HttpError(
                409, "the tickets changed since that response was captured: run live again"
            )
        agent_payload["calls"] = cap["capture_calls"]
    session_id = str(body.get("run_id") or runs.uuid7())
    if not RUN_ID.match(session_id):
        raise HttpError(400, "run_id must be a UUIDv7")
    claim_run(who["customer_id"])
    try:
        _events.put_item(
            Item={
                "run_id": session_id,
                "sk": OWNER_SK,
                "customer_id": who["customer_id"],
                "expires": int(time.time()) + 86400,
            },
            ConditionExpression="attribute_not_exists(run_id)",
        )
    except _events.meta.client.exceptions.ConditionalCheckFailedException as exc:
        _state.update_item(
            Key={"customer_id": who["customer_id"]}, UpdateExpression="REMOVE busy_until"
        )
        raise HttpError(409, "run id already used") from exc
    emit = runs.Emitter(_events, session_id)
    emit(
        "auth.verified",
        "ingress",
        "ok",
        f"{who['username']} signed in · token verified at the edge and again by the API",
        payload=json.dumps(
            {
                "CloudFront Function (viewer request)": "HMAC session cookie ✓ · expiry ✓",
                "API Lambda": "Cognito RS256 signature ✓ · issuer ✓ · client_id ✓ · token_use=access ✓",
                "caller": who,
                "request": {
                    "method": "POST",
                    "path": "/api/run",
                    "run_id": session_id,
                    "build (server state)": stage,
                    "mode": mode,
                },
            },
            default=str,
        ),
    )
    try:
        read = tickets_for(who["customer_id"])
        before = runs.snapshot(all_tickets())
        try:
            agent = invoke_agent(token, session_id, {"run_id": session_id, **agent_payload})
            result = runs.run_result(stage, agent, before, runs.snapshot(all_tickets()), mode)
        except Exception as exc:  # noqa: BLE001 - every failure is a visible, recorded run outcome
            result = runs.failed(
                stage, session_id, "AgentCore Runtime", f"{type(exc).__name__}: {exc}"
            )
        emit(
            "run.completed",
            "agent",
            {"CHANGED": "harmful", "ERROR": "error", "STOPPED": "halted", "HALTED": "halted"}.get(
                result["status"],
                "denied" if result["status"] in ("BLOCKED", "FILTERED") else "ok",
            ),
            {
                "CHANGED": "answer returned · ticket changed",
                "ERROR": "run failed",
                "STOPPED": "refused: agent is stopped",
                "HALTED": "run ended on the first denial",
                "BLOCKED": "answer returned · write denied by policy",
                "FILTERED": "guardrail withheld the ticket text",
            }.get(result["status"], "answer returned to " + who["username"]),
            verdict=result["status"],
            payload=json.dumps(
                {
                    "verdict": result["status"],
                    "answer": result.get("answer", ""),
                    "controls": result.get("controls", []),
                    "effects (DynamoDB before/after)": result.get("effects", []),
                    **({"error": result["note"]} if result["status"] == "ERROR" else {}),
                },
                default=str,
            ),
        )
        _state.update_item(
            Key={"customer_id": who["customer_id"]},
            UpdateExpression=(
                "SET last_run = :run, before_tickets = :before, store_change_source = :src, run_id = :id, "
                "active_stage = if_not_exists(active_stage, :stage)"
            ),
            ExpressionAttributeValues={
                ":run": json.dumps(result, default=str),
                ":before": json.dumps(runs.snapshot(read)),
                ":src": f"{stage.upper()} agent {'replay' if mode == 'replay' else 'run'}",
                ":id": session_id,
                ":stage": stage,
            },
        )
        print(json.dumps(runs.metrics(result, is_test=bool(body.get("is_test")))))
        cap = (
            runs.capture(session_id, stage, result["tool_calls"], runs.fingerprint(read))
            if mode == "live" and result["status"] != "ERROR"
            else None
        )
        if cap:  # the newest live response with a write is what Replay re-sends
            _state.update_item(
                Key={"customer_id": who["customer_id"]},
                UpdateExpression="SET capture = :c",
                ExpressionAttributeValues={":c": json.dumps(cap)},
            )
    finally:
        _state.update_item(
            Key={"customer_id": who["customer_id"]}, UpdateExpression="REMOVE busy_until"
        )
    return {"result": result}


def run_events(who: dict[str, str], run_id: str, after: str) -> dict[str, Any]:
    require(who, "operator")
    if not RUN_ID.match(run_id):
        raise HttpError(400, "bad run id")
    owner = _events.get_item(Key={"run_id": run_id, "sk": OWNER_SK}, ConsistentRead=True).get(
        "Item"
    )
    if owner is None:
        return {
            "run_id": run_id,
            "events": [],
        }  # not started yet (the UI polls before the POST lands)
    if owner.get("customer_id") != who["customer_id"]:
        raise HttpError(404, "no such run")
    cond = "run_id = :r AND sk > :a"
    items = _events.query(
        KeyConditionExpression=cond,
        ExpressionAttributeValues={":r": run_id, ":a": max(after, OWNER_SK)},
        ConsistentRead=True,
    )["Items"]
    return {
        "run_id": run_id,
        "events": [{k: v for k, v in i.items() if k not in ("expires",)} for i in items],
    }


# CloudWatch Logs Insights over what AWS itself recorded for one run (not the app's own events).
TRACE_QUERIES = {
    "model": (
        "Amazon Bedrock model invocation logs",
        "fields @timestamp, modelId, operation, input.inputTokenCount as in_tokens, "
        "output.outputTokenCount as out_tokens, output.outputBodyJson.stopReason as stop "
        "| filter requestMetadata.sec310_run = '{run}' | sort @timestamp asc | limit 50",
    ),
    "gateway": (
        "AgentCore Gateway application logs",
        "fields @timestamp, @message | filter @message like '{run}' | sort @timestamp asc | limit 50",
    ),
    "spans": (
        "AgentCore Runtime OpenTelemetry spans (Transaction Search)",
        "fields @timestamp, name, durationNano / 1000000 as ms, status.code as status, traceId "
        "| filter attributes.`sec310.run_id` = '{run}' | sort @timestamp asc | limit 80",
    ),
}


def run_owner(who: dict[str, str], run_id: str) -> None:
    if not RUN_ID.match(run_id):
        raise HttpError(400, "bad run id")
    owner = _events.get_item(Key={"run_id": run_id, "sk": OWNER_SK}, ConsistentRead=True).get(
        "Item"
    )
    if owner is None or owner.get("customer_id") != who["customer_id"]:
        raise HttpError(404, "no such run")


def run_trace(who: dict[str, str], run_id: str) -> dict[str, Any]:
    """Runs the three queries in parallel and returns whatever has been ingested so far
    (model logs take seconds, spans up to a minute or two)."""
    require(who, "operator")
    run_id = run_id.lower()
    run_owner(who, run_id)
    logs = boto3.client("logs")
    groups = {
        "model": [os.environ["INVOCATION_LOG_GROUP"]],
        "gateway": list(json.loads(agent_param("gateway_logs", "{}")).values()),
        # newer runtimes write spans to their own log group, older ones to the shared aws/spans
        "spans": [
            "aws/spans",
            f"/aws/bedrock-agentcore/runtimes/{agent_config()['runtime_arn'].rsplit('/', 1)[-1]}-DEFAULT",
        ],
    }

    def exists(name: str) -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=name, limit=5)["logGroups"]
        return any(g["logGroupName"] == name for g in found)

    groups = {
        k: [g for g in v if exists(g)] for k, v in groups.items()
    }  # one missing group fails a query
    now = int(time.time())
    started = {}
    for key, (_, query) in TRACE_QUERIES.items():
        if not groups[key]:
            continue
        try:
            started[key] = logs.start_query(
                logGroupNames=groups[key],
                startTime=now - 6 * 3600,
                endTime=now + 60,
                queryString=query.format(run=run_id),
            )["queryId"]
        except logs.exceptions.ResourceNotFoundException:
            pass  # e.g. aws/spans before the first span arrives
    out: dict[str, Any] = {}
    deadline = time.time() + 20
    pending = dict(started)
    while pending and time.time() < deadline:
        for key, qid in list(pending.items()):
            r = logs.get_query_results(queryId=qid)
            if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                out[key] = [
                    {f["field"]: f["value"] for f in row if not f["field"].startswith("@ptr")}
                    for row in r["results"]
                ]
                del pending[key]
        if pending:
            time.sleep(0.7)
    return {
        "run_id": run_id,
        "region": os.environ.get("AWS_REGION"),
        "sources": [
            {
                "key": key,
                "title": title,
                "log_groups": groups[key],
                "query": query.format(run=run_id),
                "records": out.get(key, []),
                "status": "done"
                if key in out
                else ("running" if key in started else "no log group yet"),
            }
            for key, (title, query) in TRACE_QUERIES.items()
        ],
    }


def reset_demo(who: dict[str, str]) -> dict[str, Any]:
    """Back to a clean V0 for this operator's customer: seed tickets only, no stop, no last run."""
    require(who, "operator")
    cid = who["customer_id"]
    for t in tickets_for(cid):
        if t["ticket_id"] not in SEED.get(cid, {}):
            _tickets.delete_item(Key={"customer_id": cid, "ticket_id": t["ticket_id"]})
    reseed()
    _state.put_item(
        Item={
            "customer_id": cid,
            "active_stage": "v0",
            "stop_requested": False,
            "store_change_source": "Clean reset",
        }
    )
    return {"reset": True}


def reseed() -> None:
    """Every tenant's seed tickets back to their original text, OPEN and without notes (a run
    can reach another tenant's ticket, so restoring only the operator's own is not enough)."""
    for cid, seed in SEED.items():
        for ticket_id, (subject, text) in seed.items():
            _tickets.put_item(
                Item={
                    "customer_id": cid,
                    "ticket_id": ticket_id,
                    "subject": subject,
                    "body": text,
                    "status": "OPEN",
                    "submitted_by": "customer",
                    "untrusted": True,
                    "origin": "seed",
                }
            )


def reopen(cid: str) -> None:
    """Undo a run's effects but keep the attack: seed tickets restored, portal tickets reopened."""
    reseed()
    for t in tickets_for(cid):
        if t.get("origin") != "seed" and (t.get("status") != "OPEN" or t.get("notes")):
            _tickets.update_item(
                Key={"customer_id": cid, "ticket_id": t["ticket_id"]},
                UpdateExpression="SET #s = :open, notes = :none REMOVE closed_by, closed_reason, closed_at",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":open": "OPEN", ":none": []},
            )


def apply_patch(who: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    """Switch the build (next one, or the one named) and reopen the previous run's effects. The
    captured response and any stop stay: the next build is judged on the same response, and a
    stop is cleared only on purpose."""
    require(who, "operator")
    cid = who["customer_id"]
    current = demo_state(cid).get("active_stage", "v0")
    target = str(body.get("stage") or STAGES[min(STAGES.index(current) + 1, len(STAGES) - 1)])
    if target not in STAGES:
        raise HttpError(400, "unknown build")
    if int(demo_state(cid).get("busy_until", 0)) > time.time():
        raise HttpError(409, "an agent run is in progress")
    reopen(cid)
    _state.update_item(
        Key={"customer_id": cid},
        UpdateExpression="SET active_stage = :t, store_change_source = :src REMOVE last_run, run_id, before_tickets",
        ExpressionAttributeValues={
            ":t": target,
            ":src": f"Applied {target.upper()}; effects reopened",
        },
    )
    return {"active_stage": target, "title": TITLES[target]}


def request_stop(who: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    require(who, "operator")
    on = bool(body.get("stop", True))
    _state.update_item(
        Key={"customer_id": who["customer_id"]},
        UpdateExpression="SET stop_requested = :on, stop_source = :src",
        ExpressionAttributeValues={":on": on, ":src": "operator" if on else "none"},
    )
    return {"stop_requested": on}


def submit_ticket(who: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    require(who, "customer")
    subject = str(body.get("subject", "")).strip()
    text = str(body.get("body", "")).strip()
    if not 0 < len(subject) <= MAX_SUBJECT or not 0 < len(text) <= MAX_BODY:
        raise HttpError(400, f"subject 1–{MAX_SUBJECT} and body 1–{MAX_BODY} characters")
    existing = tickets_for(who["customer_id"])
    prefix = who["customer_id"].split("-")[-1].upper()
    numbers = [
        int(t["ticket_id"].split("-")[1])
        for t in existing
        if t["ticket_id"].split("-")[1].isdigit()
    ]
    ticket_id = f"{prefix}-{max([89, *numbers]) + 1}"
    _tickets.put_item(
        Item={
            "customer_id": who["customer_id"],
            "ticket_id": ticket_id,
            "subject": subject,
            "body": text,
            "status": "OPEN",
            "submitted_by": "customer",
            "untrusted": True,
            "origin": "form",
            "created_by": who["username"],
        },
        ConditionExpression="attribute_not_exists(ticket_id)",
    )
    return {"ticket": {"ticket_id": ticket_id}}


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path = event.get("rawPath", "/")
    try:
        who = persona(event)
        raw = event.get("body") or ""
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw).decode()
        if len(raw) > 8192:
            raise HttpError(413, "request too large")
        body = json.loads(raw) if raw else {}
        if method == "GET" and path == "/api/me":
            return reply(200, who)
        if method == "GET" and path == "/api/state":
            return reply(200, public_state(who))
        if method == "GET" and path == "/api/code":
            require(who, "operator")
            return reply(200, build_code(demo_state(who["customer_id"]).get("active_stage", "v0")))
        if method == "POST" and path == "/api/portal/tickets":
            return reply(200, submit_ticket(who, body))
        if method == "GET" and path.startswith("/api/runs/") and path.endswith("/events"):
            q = event.get("queryStringParameters") or {}
            return reply(200, run_events(who, path.split("/")[3], str(q.get("after", ""))[:40]))
        if method == "GET" and path == "/api/trace":
            q = event.get("queryStringParameters") or {}
            return reply(200, run_trace(who, str(q.get("run", ""))[:40]))
        if method == "POST" and path == "/api/reset":
            return reply(200, reset_demo(who))
        if method == "POST" and path == "/api/stop":
            return reply(200, request_stop(who, body))
        if method == "POST" and path == "/api/patch":
            return reply(200, apply_patch(who, body))
        if method == "POST" and path == "/api/run":
            return reply(200, run_agent(who, access_token(event), body))
        raise HttpError(404, f"{method} {path} is not available yet")
    except HttpError as exc:
        return reply(exc.status, {"error": str(exc)})
    except (ValueError, json.JSONDecodeError):
        return reply(400, {"error": "invalid request"})


def reply(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(payload, default=str),
    }
