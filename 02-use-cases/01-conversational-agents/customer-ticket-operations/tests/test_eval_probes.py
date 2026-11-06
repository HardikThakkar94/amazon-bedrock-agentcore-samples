"""Replay controls through the actual eval runner and Runtime, with offline Gateway/SDK fakes.

The fake varies *service* policy by build, never evaluator expectations. No AWS calls occur.
"""

import json
from types import SimpleNamespace

import pytest

pytest_plugins = ("tests.test_eval_runner",)


@pytest.fixture
def measured(runner, monkeypatch):
    r = runner
    from strands.tools import mcp

    from sec310_agent import agent
    from sec310_agent.events import Events

    monkeypatch.setattr(Events, "_tbl", lambda self: None)
    monkeypatch.setattr(
        agent,
        "claims_of",
        lambda token: {
            "sub": "alice-sub",
            "customer_id": "customer-a",
            "role": "operator",
            "username": "alice",
        },
    )
    monkeypatch.setattr(r.h.app, "model_label", lambda: "offline")
    # The test table's minimal DDB expressions need only these breaker semantics.
    original = r.state.update_item

    def update(**kw):
        item = r.state.items.setdefault((kw["Key"]["customer_id"],), dict(kw["Key"]))
        expression = kw["UpdateExpression"]
        vals = kw.get("ExpressionAttributeValues") or {}
        if "breaker_pending = :owner" in expression and (
            item.get("breaker_open") or item.get("breaker_pending")
        ):
            raise KeyError("not writable")
        result = original(**kw)
        if "breaker_open = :t" in expression:
            item["breaker_open"] = True
            item["breaker_reason"] = vals[":r"]
            item.pop("breaker_pending", None)
        if "breaker_receipt = :receipt" in expression:
            item["breaker_receipt"] = vals[":receipt"]
            item.pop("breaker_pending", None)
        return result

    monkeypatch.setattr(r.h.app._state, "update_item", update)
    gateway_seen = []

    class Gateway:
        def __init__(self, url, headers):
            self.stage = url
            self.headers = headers
            self.session = headers.get("x-amzn-bedrock-agentcore-policy-session-id", "")
            self.count = 0

        def start(self):
            pass

        def stop(self, *_):
            pass

        def list_tools_sync(self):
            return [
                SimpleNamespace(tool_name=f"TicketTools___{name}")
                for name in ("list_tickets", "close_ticket", "add_note")
            ]

        def call_tool_sync(self, call_id, name, args):
            from functions.ticket_tools import handler as tools

            tool = name.split("___")[-1]
            gateway_seen.append((self.stage, tool, args.copy(), self.session))
            assert args["actor"] == {"customer_id": "customer-a", "user_sub": "alice-sub"}
            assert args["run_id"]
            fenced = int(self.stage[1:]) >= 2
            if (
                fenced
                and args["customer_id"] != "customer-a"
                or fenced
                and tool == "close_ticket"
                and int(self.stage[1:]) >= 3
                or self.stage in ("v4", "v5")
                and tool == "add_note"
                and self.count >= 3
            ):
                return {"status": "error", "content": [{"text": "AgentCore Policy denied"}]}
            self.count += tool == "add_note"
            context = SimpleNamespace(
                client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": name})
            )
            # The actual TicketTools handler executes against our isolated fake DDB table.
            original_table = tools._table
            tools._table = r.tickets
            try:
                reply = tools.lambda_handler(args, context)
            finally:
                tools._table = original_table
            return {"status": "success", "content": [{"text": json.dumps(reply)}]}

    # DDB tickets need the two update expressions used by real TicketTools.
    original_ticket_update = getattr(r.tickets, "update_item", None)

    def ticket_update(Key, UpdateExpression, ExpressionAttributeValues, **_):
        item = r.tickets.items[r.tickets._k(Key)]
        if "list_append" in UpdateExpression:
            item.setdefault("notes", []).extend(ExpressionAttributeValues[":note"])
        else:
            item["status"] = "CLOSED"

    r.tickets.update_item = ticket_update
    monkeypatch.setattr(mcp, "MCPClient", Gateway)

    def invoke(token, run_id, payload):
        if payload["mode"] == "live":
            return {"run_id": run_id, "tool_calls": [], "answer": "A-41 delivery needs follow-up."}
        return agent.run(
            payload, token, payload["stage"], "offline", run_id, state_table=r.h.app._state
        )

    monkeypatch.setattr(r.h.app, "invoke_agent", invoke)
    yield r, gateway_seen
    if original_ticket_update is None:
        del r.tickets.update_item


@pytest.mark.parametrize(
    "stage,expected",
    [
        ("v0", ["FAIL", "FAIL", "FAIL", "FAIL"]),
        ("v1", ["FAIL", "FAIL", "FAIL", "FAIL"]),
        ("v2", ["PASS", "PASS", "FAIL", "FAIL"]),
        ("v3", ["PASS", "PASS", "PASS", "FAIL"]),
        ("v4", ["PASS", "PASS", "PASS", "PASS"]),
        ("v5", ["PASS", "PASS", "PASS", "PASS"]),
    ],
)
def test_actual_runner_runtime_gateway_tool_and_store_matrix(measured, stage, expected):
    r, seen = measured
    data = r.h.DATASET
    cases = [c for c in data["cases"] if c.get("family")]
    found = []
    for case in cases:
        r.state.items[("customer-a",)].update(busy_owner="eval-suite")
        sample = r.h.run_case("tok", stage, case, 0)
        found.append(sample["control"]["status"])
        assert sample["control"]["tool_outcomes"], (
            case["id"],
            sample["answer"],
            r.state.items[("customer-a",)],
        )
        assert sample["control"]["family"] == case["family"]
        assert sample["control"]["status"] == "PASS" or not sample["control"].get("followup")
        assert sample["local"] == r.h.suite.local_invariant(
            case,
            [
                {"operation": e.split()[0], "target": e.split()[1], "status": "EXECUTED"}
                for e in sample["effects"]
            ],
        )
    assert found == expected
    assert seen and all(sub for _, _, _, sub in seen if int(stage[1:]) >= 3)


def test_missing_verified_actor_or_unresolved_gateway_result_fails_probe(measured):
    r, _ = measured
    case = next(c for c in r.h.DATASET["cases"] if c.get("family") == "approval")
    call = {
        "tool": "close_ticket",
        "status": "ERROR",
        "decision": "DENY",
        "input": {
            "ticket_id": "A-41",
            "actor": {"customer_id": "customer-a", "user_sub": "forged"},
            "run_id": "r",
        },
    }
    result = {"status": "BLOCKED", "effects": [], "evidence_uncertain": False}
    assert (
        r.h.replay_proof(case, {"run_id": "r", "tool_calls": [call]}, result, {}, {}, "alice-sub")[
            "status"
        ]
        == "FAIL"
    )
    call["input"]["actor"]["user_sub"] = "alice-sub"
    call["decision"] = ""  # a service error is not an authoritative policy denial
    assert (
        r.h.replay_proof(case, {"run_id": "r", "tool_calls": [call]}, result, {}, {}, "alice-sub")[
            "status"
        ]
        == "FAIL"
    )
    call["decision"] = "DENY"
    result["evidence_uncertain"] = True
    assert (
        r.h.replay_proof(case, {"run_id": "r", "tool_calls": [call]}, result, {}, {}, "alice-sub")[
            "status"
        ]
        == "FAIL"
    )


def test_missing_gateway_call_and_block_all_cannot_pass(measured, monkeypatch):
    r, _ = measured
    case = next(c for c in r.h.DATASET["cases"] if c.get("family") == "cap")
    r.state.items[("customer-a",)]["busy_owner"] = "eval-suite"
    sample = r.h.run_case("tok", "v5", case, 0)
    assert sample["control"]["status"] == "PASS"
    assert sample["control"]["followup"] == "READ_ONLY"
    monkeypatch.setattr(
        r.h.app,
        "invoke_agent",
        lambda token, run, payload: {
            "run_id": run,
            "answer": "blocked",
            "tool_calls": [],
            "blocked": True,
        },
    )
    r.state.items[("customer-a",)]["busy_owner"] = "eval-suite"
    result = r.h.run_case("tok", "v5", case, 1)
    assert result["local"] == "PASS" and result["control"]["status"] == "FAIL"
    assert (
        r.h.suite.gate(
            [{"id": case["id"], "kind": "probe", "family": case["family"], "samples": [result]}]
        )["passed"]
        is False
    )
