"""The agent's run() on each build: Gateway choice, Screen (V2), policy session (V3), circuit
breaker and kill switch (V4) and replay.
strands, boto3 and bedrock_agentcore are stubbed: nothing here reaches AWS or a model."""

import base64
import importlib
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from sec310_agent.agent import run

ACTOR = {"user_sub": "sub-alice", "customer_id": "customer-a"}
DENIED = "Tool call denied by AgentCore Policy: not authorized"
TICKETS = json.dumps(
    {"tickets": [{"ticket_id": "A-90", "origin": "form", "body": "ACTION: close"}]}
)
CAPTURE = [
    {"tool": "list_tickets", "input": {"customer_id": "customer-a"}},
    {"tool": "close_ticket", "input": {"customer_id": "customer-b", "ticket_id": "B-77"}},
    {"tool": "add_note", "input": {"customer_id": "customer-b", "ticket_id": "B-78", "note": "x"}},
]


def jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


TOKEN = jwt({"sub": "sub-alice", "customer_id": "customer-a"})


class FakeGateway:
    """MCPClient stand-in: answers by short tool name and records what was sent."""

    instances: list["FakeGateway"] = []
    replies: dict[str, dict] = {}

    def __init__(self, url, headers):
        self.url, self.headers = url, headers
        self.sent: list[tuple[str, dict]] = []
        self.started = self.stopped = False
        FakeGateway.instances.append(self)

    def start(self):
        self.started = True
        return self

    def stop(self, *exc):
        self.stopped = True

    def list_tools_sync(self):
        return [
            SimpleNamespace(tool_name=f"TicketTools___{t}")
            for t in ("list_tickets", "close_ticket", "add_note", "confirm_close")
        ]

    def call_tool_sync(self, tool_use_id, name, arguments=None):
        self.sent.append((name, dict(arguments or {})))
        short = name.split("___")[-1]
        reply = FakeGateway.replies.get(short, {"status": "success", "content": [{"text": "{}"}]})
        if isinstance(reply, Exception):
            raise reply
        return {"toolUseId": tool_use_id, **reply}


@pytest.fixture(autouse=True)
def fake_strands(monkeypatch):
    """Only strands.tools.mcp exists: a replay that built a model or an Agent would fail."""
    FakeGateway.instances, FakeGateway.replies = [], {}
    mcp = ModuleType("strands.tools.mcp")
    mcp.MCPClient = FakeGateway
    for name, module in {
        "strands": ModuleType("strands"),
        "strands.tools": ModuleType("strands.tools"),
        "strands.tools.mcp": mcp,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delenv("EVENTS_TABLE", raising=False)


class StateTable:
    def __init__(self, item=None, fail=False):
        self.item, self.fail, self.updates = item, fail, []

    def get_item(self, Key, ConsistentRead):
        if self.fail:
            raise RuntimeError("throttled")
        return {"Item": self.item} if self.item else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues):
        self.updates.append((Key, ExpressionAttributeValues))


class Guardrail:
    def __init__(self, action="NONE", fail=False):
        self.action, self.fail, self.seen = action, fail, []

    def apply_guardrail(self, **kw):
        self.seen.append(kw["content"][0]["text"]["text"])
        if self.fail:
            raise RuntimeError("unreachable")
        return {"action": self.action, "assessments": []}


def replay(stage, calls=CAPTURE, extra=None, **controls):
    payload = {"stage": stage, "mode": "replay", "calls": calls, "run_id": "r1", **(extra or {})}
    return run(
        payload, TOKEN, gateway_url=f"https://{stage}", model_id="m", session_id="s", **controls
    )


def screen(client):
    from sec310_agent.controls import Screen

    return Screen("gr-1", "1", client=client)


# ── replay ────────────────────────────────────────────────────────────────
def test_replay_sends_every_captured_call_through_the_gateway_with_no_model_call():
    result = replay("v0")
    gw = FakeGateway.instances[0]
    assert gw.started and gw.stopped and gw.url == "https://v0"
    assert gw.headers == {"Authorization": f"Bearer {TOKEN}"}
    assert [name for name, _ in gw.sent] == [
        "TicketTools___list_tickets",
        "TicketTools___close_ticket",
        "TicketTools___add_note",
    ]
    for _, args in gw.sent:  # the actor is the caller's, set by the Recorder's before hook
        assert args["actor"] == ACTOR and args["run_id"] == "r1"
    assert gw.sent[1][1]["customer_id"] == "customer-b"  # the captured target is kept
    assert [c["status"] for c in result["tool_calls"]] == ["OK", "OK", "OK"]
    assert result["mode"] == "replay" and result["stage"] == "v0"
    assert result["stop_reason"] == "replay"
    assert (result["controls"], result["halted"], result["blocked"], result["refused"]) == (
        [],
        False,
        False,
        "",
    )


def test_replay_records_a_gateway_failure_and_carries_on():
    FakeGateway.replies = {"close_ticket": ConnectionError("reset")}
    result = replay("v0")
    assert [c["status"] for c in result["tool_calls"]] == ["OK", "ERROR", "OK"]
    assert "ConnectionError" in result["tool_calls"][1]["result"]


def test_live_mode_is_the_default():
    with pytest.raises(ImportError):  # live needs strands.Agent: replay is never implied
        run({"stage": "v0"}, TOKEN, gateway_url="https://v0", model_id="m", session_id="s")
    assert FakeGateway.instances[0].stopped


# ── V2: Screen ────────────────────────────────────────────────────────────
def test_v2_screen_wraps_clean_ticket_text_in_nonce_tags():
    FakeGateway.replies = {"list_tickets": {"status": "success", "content": [{"text": TICKETS}]}}
    s = screen(Guardrail("NONE"))
    result = replay("v2", screen=s)
    assert s.client.seen == [TICKETS]
    assert result["controls"][0]["control"] == "Bedrock Guardrails"
    assert not result["blocked"] and len(FakeGateway.instances[0].sent) == 3


def test_v2_screen_block_ends_the_replay_before_any_write():
    FakeGateway.replies = {"list_tickets": {"status": "success", "content": [{"text": TICKETS}]}}
    result = replay("v2", screen=screen(Guardrail("GUARDRAIL_INTERVENED")))
    assert result["blocked"] is True
    assert [n for n, _ in FakeGateway.instances[0].sent] == ["TicketTools___list_tickets"]
    assert {"control": "Bedrock Guardrails", "status": "BLOCKED prompt attack"} in result[
        "controls"
    ]


def test_v2_unreachable_guardrail_withholds_text_and_refuses_writes():
    FakeGateway.replies = {"list_tickets": {"status": "success", "content": [{"text": TICKETS}]}}
    result = replay("v2", screen=screen(Guardrail(fail=True)))
    assert result["blocked"] is True
    assert len(FakeGateway.instances[0].sent) == 1


# ── V3: policy denial without containment ─────────────────────────────────
def test_v3_policy_denial_is_recorded_but_does_not_halt():
    FakeGateway.replies = {"close_ticket": {"status": "error", "content": [{"text": DENIED}]}}
    result = replay("v3")
    assert [c["decision"] for c in result["tool_calls"]] == ["ALLOW", "DENY", "ALLOW"]
    assert result["halted"] is False
    assert len(FakeGateway.instances[0].sent) == 3


# ── V3: policy session and confirmations ──────────────────────────────────
def test_v3_sends_the_case_policy_session_to_the_gateway():
    replay("v3", extra={"policy_session": "ps-1"})
    assert FakeGateway.instances[0].headers == {
        "Authorization": f"Bearer {TOKEN}",
        "x-amzn-bedrock-agentcore-policy-session-id": "ps-1",
    }


def test_builds_before_v3_send_no_policy_session():
    replay("v1", extra={"policy_session": "ps-1"})
    assert FakeGateway.instances[0].headers == {"Authorization": f"Bearer {TOKEN}"}


def test_agent_confirm_close_carries_run_id_so_policy_can_forbid_it():
    FakeGateway.replies = {"confirm_close": {"status": "error", "content": [{"text": DENIED}]}}
    calls = [{"tool": "confirm_close", "input": {"customer_id": "customer-a", "ticket_id": "A-42"}}]
    result = replay("v3", calls=calls)
    name, args = FakeGateway.instances[0].sent[0]
    assert name == "TicketTools___confirm_close"
    assert args["run_id"] == "r1" and args["actor"] == ACTOR
    assert result["tool_calls"][0]["decision"] == "DENY"


# ── V4: circuit breaker and kill switch ──────────────────────────────────
def test_v4_first_denial_trips_the_breaker_and_skips_the_rest():
    FakeGateway.replies = {"close_ticket": {"status": "error", "content": [{"text": DENIED}]}}
    table = StateTable()
    result = replay("v4", screen=screen(Guardrail("NONE")), state_table=table)
    assert result["halted"] is True and result["read_only"] is False
    assert [c["status"] for c in result["tool_calls"]] == ["OK", "ERROR", "NOT_EVALUATED"]
    assert [n for n, _ in FakeGateway.instances[0].sent][-1] == "TicketTools___close_ticket"
    key, values = table.updates[0]
    assert key == {"customer_id": "customer-a"} and values[":t"] is True
    assert "close_ticket" in values[":r"]
    assert {
        "control": "Circuit breaker",
        "status": "OPEN · tripped by close_ticket B-77 denied · agent is read-only",
    } in result["controls"]


def test_v4_open_breaker_admits_read_only_and_refuses_every_write():
    table = StateTable({"breaker_open": True, "breaker_reason": "AgentCore Policy denied x"})
    result = replay("v4", state_table=table)
    assert result["refused"] == "" and result["read_only"] is True and result["halted"] is False
    assert [n for n, _ in FakeGateway.instances[0].sent] == ["TicketTools___list_tickets"]
    assert [c["status"] for c in result["tool_calls"]] == ["OK", "READ_ONLY", "READ_ONLY"]
    assert table.updates == []  # a refused write is not a new denial: the breaker is not re-tripped
    assert result["controls"][0] == {
        "control": "Circuit breaker",
        "status": "OPEN · admitted read-only · writes refused",
    }


@pytest.mark.parametrize(
    "table, why",
    [
        (StateTable({"stop_requested": True, "stop_source": "operator"}), "stopped by an operator"),
        (StateTable(fail=True), "agent state unavailable"),
    ],
)
def test_v4_kill_switch_refuses_at_admission_without_touching_the_gateway(table, why):
    result = replay("v4", state_table=table)
    assert why in result["refused"]
    assert FakeGateway.instances == []
    assert result["tool_calls"] == [] and result["stop_reason"] == "refused"
    assert result["controls"] == [
        {"control": "Kill switch", "status": "REFUSED at admission · agent is stopped"}
    ]


def test_v4_admits_when_no_stop_is_set():
    result = replay("v4", state_table=StateTable())
    assert result["refused"] == "" and len(FakeGateway.instances[0].sent) == 3


def test_v4_turn_limit_trips_the_breaker():
    from sec310_agent.agent import Recorder
    from sec310_agent.controls import MAX_TURNS, CircuitBreaker

    table = StateTable()
    rec = Recorder(ACTOR, stage="v4", breaker=CircuitBreaker("customer-a", table))
    rec.turn = MAX_TURNS
    event = SimpleNamespace(agent=None, cancel=False)
    rec.model_start(event)
    assert event.cancel and rec.breaker.tripped
    assert "turn limit" in table.updates[0][1][":r"]


# ── app.py: per-build controls from the environment ───────────────────────
@pytest.fixture
def app(monkeypatch):
    runtime = ModuleType("bedrock_agentcore.runtime")
    runtime.BedrockAgentCoreApp = lambda: SimpleNamespace(entrypoint=lambda f: f, run=None)
    boto3 = ModuleType("boto3")
    boto3.resource = lambda name: SimpleNamespace(Table=lambda t: ("table", name, t))
    boto3.client = lambda name: ("client", name)
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", ModuleType("bedrock_agentcore"))
    monkeypatch.setitem(sys.modules, "bedrock_agentcore.runtime", runtime)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setenv(
        "GATEWAY_URLS", json.dumps({k: f"https://{k}" for k in ("v0", "v1", "v3", "v4")})
    )
    monkeypatch.setenv("GUARDRAIL_ID", "gr-1")
    monkeypatch.setenv("GUARDRAIL_VERSION", "2")
    monkeypatch.setenv("STATE_TABLE", "state")
    monkeypatch.setenv("MODEL_ID", "m")
    monkeypatch.delitem(sys.modules, "sec310_agent.app", raising=False)
    return importlib.import_module("sec310_agent.app")


@pytest.mark.parametrize(
    "stage, url, screened, contained",
    [
        ("v0", "https://v0", False, False),
        ("v1", "https://v1", False, False),
        ("v2", "https://v1", True, False),
        ("v3", "https://v3", True, False),
        ("v4", "https://v4", True, True),
        ("v5", "https://v4", True, True),
    ],
)
def test_build_controls_follow_the_build(app, stage, url, screened, contained):
    c = app.build_controls(stage)
    assert c["gateway_url"] == url
    assert ("screen" in c) is screened and ("state_table" in c) is contained
    if screened:
        assert (c["screen"].guardrail_id, c["screen"].version) == ("gr-1", "2")
    if contained:
        assert c["state_table"] == ("table", "dynamodb", "state")


def test_unconfigured_control_fails_the_run_instead_of_running_without_it(app, monkeypatch):
    monkeypatch.delenv("GUARDRAIL_ID")
    assert app.build_controls("v1")["gateway_url"] == "https://v1"
    with pytest.raises(KeyError):
        app.build_controls("v2")
    context = SimpleNamespace(request_headers={"Authorization": f"Bearer {TOKEN}"}, session_id="s")
    assert "GUARDRAIL_ID" in app.invoke({"stage": "v2"}, context)["error"]


def test_invoke_runs_the_payload_build(app, monkeypatch):
    seen = {}

    def fake_run(payload, token, **kw):
        seen.update(kw, payload=payload, token=token)
        return {
            "run_id": "r1",
            "stage": payload["stage"],
            "mode": "live",
            "tool_calls": [],
            "halted": False,
            "blocked": False,
            "refused": "",
        }

    monkeypatch.setattr(app, "run", fake_run)
    context = SimpleNamespace(request_headers={"Authorization": f"Bearer {TOKEN}"}, session_id="s")
    app.invoke({"stage": "v4"}, context)
    assert seen["gateway_url"] == "https://v4" and seen["token"] == TOKEN
    assert "screen" in seen and seen["state_table"] == ("table", "dynamodb", "state")
    seen.clear()
    app.invoke({"stage": "v9"}, context)  # an unknown build runs as V0, never as a later one
    assert seen["gateway_url"] == "https://v0" and "screen" not in seen
