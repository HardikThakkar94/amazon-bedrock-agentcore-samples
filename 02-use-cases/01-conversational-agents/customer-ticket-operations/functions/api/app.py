"""SEC310 presenter API (Lambda function URL, AuthType=AWS_IAM, reachable only via CloudFront).

CloudFront's Lambda@Edge has already verified the Cognito session and forwards the access token
in ``x-sec310-access-token``; this function verifies its signature, issuer, audience and expiry
again (defence in depth) and takes the persona from the token's claims, never from the body.
"""

from __future__ import annotations

import base64
import json
import os
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


def tickets_for(customer_id: str) -> list[dict[str, Any]]:
    items = _tickets.query(
        KeyConditionExpression="customer_id = :c",
        ExpressionAttributeValues={":c": customer_id},
    )["Items"]
    return sorted(items, key=lambda t: t["ticket_id"])


def demo_state(customer_id: str) -> dict[str, Any]:
    item = _state.get_item(Key={"customer_id": customer_id}).get("Item")
    return item or {"customer_id": customer_id, "active_stage": "v0", "stop_requested": False}


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
        "capture_available": False,
        "capture_stale": False,
        "capture_source": None,
        "capture_ticket_count": 0,
        "capture_run_id": None,
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
    stage = str(body.get("stage") or st.get("active_stage", "v0"))
    if stage != "v0":
        raise HttpError(
            409, "builds V1–V5 arrive with the per-build gateways; this deployment runs V0"
        )
    if body.get("reuse_capture"):
        raise HttpError(409, "exact-response replay arrives with the per-build gateways")
    claim_run(who["customer_id"])
    session_id = runs.uuid7()
    try:
        before = runs.snapshot(tickets_for(who["customer_id"]))
        try:
            agent = invoke_agent(
                token, session_id, {"run_id": session_id, "operator": who["username"]}
            )
            result = runs.run_result(
                stage, agent, before, runs.snapshot(tickets_for(who["customer_id"]))
            )
        except Exception as exc:  # noqa: BLE001 - every failure is a visible, recorded run outcome
            result = runs.failed(
                stage, session_id, "AgentCore Runtime", f"{type(exc).__name__}: {exc}"
            )
        _state.update_item(
            Key={"customer_id": who["customer_id"]},
            UpdateExpression=(
                "SET last_run = :run, before_tickets = :before, store_change_source = :src, run_id = :id, "
                "active_stage = if_not_exists(active_stage, :stage)"
            ),
            ExpressionAttributeValues={
                ":run": json.dumps(result, default=str),
                ":before": json.dumps(before),
                ":src": f"{stage.upper()} agent run",
                ":id": session_id,
                ":stage": stage,
            },
        )
    finally:
        _state.update_item(
            Key={"customer_id": who["customer_id"]}, UpdateExpression="REMOVE busy_until"
        )
    return {"result": result}


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
            stage = demo_state(who["customer_id"]).get("active_stage", "v0")
            return reply(
                200,
                {
                    "stage": stage,
                    "title": TITLES[stage],
                    "path": "AgentCore Gateway policies for this build",
                    "source": "Per-build Gateway policies and agent hooks are shown here once builds are live.",
                    "diff": "",
                    "shared_pipeline": "agent on AgentCore Runtime",
                },
            )
        if method == "POST" and path == "/api/portal/tickets":
            return reply(200, submit_ticket(who, body))
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
