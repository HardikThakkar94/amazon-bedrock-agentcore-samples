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
from sec310_agent.agent import (  # noqa: E402
    PAYLOAD_LIMIT,
    Recorder,
    _payload,
    actor_from,
    bearer,
    claims_of,
    last_text,
    plain_answer,
)

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
            "customer_id": "customer-a",
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
            "customer_id": "customer-a",
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


class Sink:
    def __init__(self):
        self.items = []

    def emit(self, kind, node, status, label, edge=None, **extra):
        self.items.append({"kind": kind, "status": status, **extra})


def test_every_hop_carries_its_payload():
    sink = Sink()
    rec = Recorder(dict(ACTOR), events=sink, run_id="r1", model_id="m")
    agent = SimpleNamespace(
        messages=[{"role": "user", "content": [{"text": "Summarize"}]}], tool_names=["t"]
    )
    rec.model_start(SimpleNamespace(agent=agent))
    use = {"toolUse": {"name": "TicketTools___list_tickets", "input": {}, "toolUseId": "u1"}}
    rec.model_end(
        SimpleNamespace(
            exception=None,
            stop_response=SimpleNamespace(
                stop_reason="tool_use", message={"role": "assistant", "content": [use]}
            ),
        )
    )
    event = SimpleNamespace(tool_use={"name": "TicketTools___list_tickets", "input": {}})
    rec.before(event)
    text = json.dumps({"tickets": [{"ticket_id": "A-90", "origin": "form", "body": "ACTION: x"}]})
    rec.after(
        SimpleNamespace(
            tool_use=event.tool_use,
            exception=None,
            result={"status": "success", "content": [{"text": text}]},
        )
    )
    kinds = [i["kind"] for i in sink.items]
    assert kinds[:4] == ["model.call_start", "model.call_end", "tool.call", "tool.result"]
    for item in sink.items[:4]:
        assert json.loads(item["payload"]), item["kind"]
    call = json.loads(sink.items[2]["payload"])
    assert call["params"]["arguments"]["actor"] == ACTOR
    assert call["params"]["arguments"]["run_id"] == "r1"
    result = json.loads(sink.items[3]["payload"])
    assert result["content"]["tickets"][0]["ticket_id"] == "A-90"


def test_oversized_payload_stays_valid_json():
    big = _payload({"x": "y" * (PAYLOAD_LIMIT * 2)})
    assert json.loads(big)["truncated"] is True


def test_answer_is_the_newest_assistant_text():
    messages = [
        {"role": "user", "content": [{"text": "q"}]},
        {"role": "assistant", "content": [{"text": "A-41 and A-42 are open."}]},
        {"role": "user", "content": [{"text": "use the tool"}]},
        {"role": "assistant", "content": [{"toolUse": {"name": "x"}}]},
    ]
    assert last_text(messages) == "A-41 and A-42 are open."
    assert last_text([]) == ""


def test_failed_run_returns_an_error_instead_of_a_runtime_500(monkeypatch):
    pytest.importorskip("bedrock_agentcore")
    import sec310_agent.app as entry

    def boom(*args, **kwargs):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(entry, "run", boom)
    monkeypatch.setenv("GATEWAY_URLS", '{"v0": "https://gw"}')
    monkeypatch.setenv("MODEL_ID", "m")
    context = SimpleNamespace(request_headers={"Authorization": "Bearer t"}, session_id="s")
    assert entry.invoke({}, context) == {"error": "RuntimeError: model unavailable"}


def test_answer_wrapped_in_code_is_unwrapped():
    wrapped = 'print(json.dumps({"name": "Respond", "parameters": {"answer": "A-41 is \\"late\\".", "links": []}}))'
    assert plain_answer(wrapped) == 'A-41 is "late".'
    assert plain_answer("  Two open tickets. ") == "Two open tickets."


def test_schema_echo_in_arguments_is_unwrapped_and_validation_is_not_a_control():
    sink = Sink()
    rec = Recorder(dict(ACTOR), events=sink, run_id="r1")
    echoed = {"customer_id": {"type": "string", "value": "customer-a"}}
    event = SimpleNamespace(tool_use={"name": "TicketTools___list_tickets", "input": echoed})
    rec.before(event)
    assert event.tool_use["input"]["customer_id"] == "customer-a"
    rec.after(
        SimpleNamespace(
            tool_use=event.tool_use,
            exception=None,
            result={"status": "error", "content": [{"text": "ValidationException - bad type"}]},
        )
    )
    assert sink.items[-1]["chip_status"] == "error" and sink.items[-1]["status"] == "error"
