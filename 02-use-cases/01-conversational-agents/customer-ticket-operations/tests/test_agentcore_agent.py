"""Agent on AgentCore Runtime (#3): the API's run evidence, TicketTools, and the agent's identity."""

import base64
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runs = load("sec310_api_runs", ROOT / "functions/api/runs.py")
tools = load("sec310_ticket_tools", ROOT / "functions/ticket_tools/handler.py")
from sec310_agent.agent import Recorder, actor_from, bearer, claims_of  # noqa: E402

SEED = [
    {
        "ticket_id": "A-41",
        "customer_id": "customer-a",
        "subject": "Package arrived late",
        "body": "Please explain the delay.",
        "status": "OPEN",
    },
    {
        "ticket_id": "A-42",
        "customer_id": "customer-a",
        "subject": "Correct billing address",
        "body": "Please update the postal code.",
        "status": "OPEN",
    },
]
ACTOR = {"user_sub": "sub-alice", "customer_id": "customer-a"}


def jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


# ── run evidence (functions/api/runs.py) ──────────────────────────────────
def test_session_id_is_uuid7_and_long_enough_for_agentcore():
    sid = runs.uuid7()
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", sid)
    assert len(sid) >= 33
    assert runs.uuid7() != sid


def test_normal_run_with_only_reads_is_no_effect():
    agent = {
        "run_id": "r1",
        "model_id": "m",
        "answer": "Two open tickets.",
        "tool_calls": [
            {
                "tool": "list_tickets",
                "input": {"customer_id": "customer-a", "actor": ACTOR},
                "status": "OK",
            }
        ],
    }
    before = runs.snapshot(SEED)
    result = runs.run_result("v0", agent, before, runs.snapshot(SEED))
    assert result["status"] == "NO_EFFECT"
    assert result["effects"] == [] and result["proposals"] == []
    assert result["answer"] == "Two open tickets."


def test_verdict_comes_from_the_table_not_the_agent():
    closed = [dict(SEED[0]), {**SEED[1], "status": "CLOSED"}]
    # the agent reports no write at all, yet the table changed: the effect is still shown
    result = runs.run_result("v0", {"tool_calls": []}, runs.snapshot(SEED), runs.snapshot(closed))
    assert result["status"] == "CHANGED"
    assert result["effects"] == [
        {
            "operation": "close_ticket",
            "target": "A-42",
            "status": "EXECUTED",
            "before": "OPEN",
            "after": "CLOSED",
        }
    ]


def test_refused_write_is_listed_but_is_not_an_effect():
    call = {
        "tool": "close_ticket",
        "input": {"customer_id": "customer-a", "ticket_id": "A-42", "reason": "dup"},
        "status": "ERROR",
    }
    result = runs.run_result("v0", {"tool_calls": [call]}, runs.snapshot(SEED), runs.snapshot(SEED))
    assert result["status"] == "NO_EFFECT"
    assert result["proposals"][0]["operation"] == "close_ticket"
    assert result["effects"] == [
        {
            "operation": "close_ticket",
            "target": "A-42",
            "status": "DENIED_GATEWAY",
            "before": None,
            "after": None,
        }
    ]


def test_failed_run_is_a_recorded_error():
    result = runs.failed("v0", "r2", "AgentCore Runtime", "RuntimeError: 401")
    assert result["status"] == "ERROR" and "401" in result["note"]


# ── TicketTools (functions/ticket_tools/handler.py) ────────────────────────
class FakeTable:
    def __init__(self, items):
        self.items = {(i["customer_id"], i["ticket_id"]): dict(i) for i in items}

    def query(self, KeyConditionExpression, ExpressionAttributeValues):
        c = ExpressionAttributeValues[":c"]
        return {"Items": [i for (cid, _), i in self.items.items() if cid == c]}

    def get_item(self, Key):
        item = self.items.get((Key["customer_id"], Key["ticket_id"]))
        return {"Item": dict(item)} if item else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, **_):
        item = self.items[(Key["customer_id"], Key["ticket_id"])]
        if ":closed" in ExpressionAttributeValues:
            item["status"] = "CLOSED"
            item["closed_by"] = ExpressionAttributeValues[":by"]
        else:
            item["notes"] = [*item.get("notes", []), *ExpressionAttributeValues[":note"]]


def ctx(tool: str):
    return SimpleNamespace(
        client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"TicketTools___{tool}"})
    )


def test_tool_name_comes_from_the_gateway_context(monkeypatch):
    table = FakeTable(SEED)
    monkeypatch.setattr(tools, "table", lambda: table)
    listed = tools.lambda_handler(
        {"customer_id": "customer-a", "actor": ACTOR}, ctx("list_tickets")
    )
    assert [t["ticket_id"] for t in listed["tickets"]] == ["A-41", "A-42"]
    assert tools.lambda_handler({}, ctx("delete_everything")) == {"status": "UNKNOWN_TOOL"}


def test_close_records_the_actor_and_is_idempotent(monkeypatch):
    table = FakeTable(SEED)
    monkeypatch.setattr(tools, "table", lambda: table)
    args = {"customer_id": "customer-a", "ticket_id": "A-42", "reason": "dup", "actor": ACTOR}
    assert tools.lambda_handler(args, ctx("close_ticket"))["status"] == "CLOSED"
    assert table.items[("customer-a", "A-42")]["closed_by"] == ACTOR
    assert tools.lambda_handler(args, ctx("close_ticket"))["status"] == "ALREADY_CLOSED"
    missing = {**args, "ticket_id": "A-99"}
    assert tools.lambda_handler(missing, ctx("close_ticket"))["status"] == "TARGET_NOT_FOUND"


def test_add_note_is_bounded(monkeypatch):
    table = FakeTable(SEED)
    monkeypatch.setattr(tools, "table", lambda: table)
    args = {"customer_id": "customer-a", "ticket_id": "A-41", "note": "x" * 900, "actor": ACTOR}
    assert tools.lambda_handler(args, ctx("add_note"))["status"] == "NOTED"
    assert len(table.items[("customer-a", "A-41")]["notes"][0]["text"]) == tools.MAX_NOTE
    assert tools.lambda_handler({**args, "note": "  "}, ctx("add_note"))["status"] == "EMPTY_NOTE"


# ── agent identity (src/sec310_agent/agent.py) ─────────────────────────────
def test_bearer_token_is_required():
    assert bearer({"authorization": "Bearer abc"}) == "abc"
    with pytest.raises(PermissionError):
        bearer({"x-other": "1"})
    with pytest.raises(PermissionError):
        bearer(None)


def test_actor_comes_from_token_claims():
    claims = claims_of(jwt({"sub": "sub-alice", "customer_id": "customer-a", "role": "operator"}))
    assert actor_from(claims) == ACTOR
    with pytest.raises(PermissionError):
        actor_from({"sub": "sub-alice"})
    with pytest.raises(ValueError):
        claims_of("not-a-jwt")


def test_recorder_overwrites_any_model_supplied_actor():
    rec = Recorder(dict(ACTOR))
    forged = {
        "customer_id": "customer-b",
        "ticket_id": "B-77",
        "actor": {"user_sub": "x", "customer_id": "customer-b"},
    }
    event = SimpleNamespace(tool_use={"name": "TicketTools___close_ticket", "input": forged})
    rec.before(event)
    assert event.tool_use["input"]["actor"] == ACTOR
    assert (
        event.tool_use["input"]["customer_id"] == "customer-b"
    )  # the target stays the model's choice
    done = SimpleNamespace(
        tool_use=event.tool_use,
        exception=None,
        result={"status": "error", "content": [{"text": "denied"}]},
    )
    rec.after(done)
    assert (
        rec.calls[0].tool == "close_ticket"
        and rec.calls[0].status == "ERROR"
        and rec.calls[0].result == "denied"
    )
