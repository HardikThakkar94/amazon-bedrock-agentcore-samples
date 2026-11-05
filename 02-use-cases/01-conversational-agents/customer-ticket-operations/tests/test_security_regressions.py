"""Real API handler with in-memory conditional DynamoDB; no network or credentials."""

import base64
import importlib.util
import json
import sys
import threading
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ALICE = {"role": "operator", "customer_id": "customer-a", "username": "alice", "sub": "alice-sub"}


class Conflict(Exception):
    pass


class Table:
    def __init__(self, keys):
        self.keys, self.rows, self.lock = keys, {}, threading.RLock()
        self.meta = SimpleNamespace(
            client=SimpleNamespace(
                exceptions=SimpleNamespace(ConditionalCheckFailedException=Conflict)
            )
        )

    def key(self, item):
        return tuple(item[k] for k in self.keys)

    def get_item(self, Key, **kw):
        with self.lock:
            item = self.rows.get(self.key(Key))
            return {"Item": dict(item)} if item is not None else {}

    def put_item(self, Item, ConditionExpression=None):
        with self.lock:
            key = self.key(Item)
            if ConditionExpression and key in self.rows:
                raise Conflict()
            self.rows[key] = dict(Item)

    def delete_item(
        self,
        Key,
        ConditionExpression=None,
        ExpressionAttributeNames=None,
        ExpressionAttributeValues=None,
    ):
        with self.lock:
            item = self.rows.get(self.key(Key))
            if ConditionExpression and (
                item is None
                or item.get("origin") != ExpressionAttributeValues[":form"]
                or item.get("submitted_by") != ExpressionAttributeValues[":customer"]
            ):
                raise Conflict()
            self.rows.pop(self.key(Key), None)

    def query(self, ExpressionAttributeValues, **kw):
        with self.lock:
            return {
                "Items": [
                    dict(v)
                    for v in self.rows.values()
                    if v.get("customer_id") == ExpressionAttributeValues.get(":c")
                ]
            }

    def scan(self, **kw):
        with self.lock:
            return {"Items": [dict(v) for v in self.rows.values()]}

    def update_item(
        self,
        Key,
        UpdateExpression,
        ExpressionAttributeValues=None,
        ConditionExpression=None,
        ReturnValues=None,
    ):
        with self.lock:
            item = self.rows.setdefault(self.key(Key), dict(Key))
            v, cond = ExpressionAttributeValues or {}, ConditionExpression or ""
            if "attribute_not_exists(busy_owner)" in cond and "busy_owner" in item:
                raise Conflict()
            if (
                "attribute_not_exists(busy_until) OR busy_until < :now" in cond
                and item.get("busy_until", -1) >= v[":now"]
            ):
                raise Conflict()
            for col, param in (
                ("busy_owner", ":owner"),
                ("policy_session", ":session"),
                ("approval_uncertain", ":marker"),
            ):
                if f"{col} = {param}" in cond and item.get(col) != v[param]:
                    raise Conflict()
            if "active_stage = :stage" in cond and item.get("active_stage") != v[":stage"]:
                raise Conflict()
            if "approvals = :previous" in cond and item.get("approvals") != v[":previous"]:
                raise Conflict()
            if "attribute_not_exists(approval_uncertain)" in cond and "approval_uncertain" in item:
                raise Conflict()
            if "attribute_not_exists(approval_dispatch)" in cond and "approval_dispatch" in item:
                raise Conflict()
            if "busy_until = :until" in UpdateExpression:
                item["busy_until"] = v[":until"]
                if ":owner" in v:
                    item["busy_owner"] = v[":owner"]
                if "busy_stage = :stage" in UpdateExpression:
                    item["busy_stage"], item["busy_sub"] = v[":stage"], v[":principal"]
            if "policy_session = if_not_exists" in UpdateExpression:
                item.setdefault("policy_session", v[":s"])
            if "approval_uncertain = :marker" in UpdateExpression:
                item["approval_uncertain"] = v[":marker"]
            if "exclusion_disposition = :status" in UpdateExpression:
                item["exclusion_disposition"] = v[":status"]
                item["exclusion_reason"] = v[":reason"]
            if "approval_dispatch = :marker" in UpdateExpression:
                item.update(approval_dispatch=v[":marker"], confirmed=v[":c"])
            if "approvals = :a" in UpdateExpression:
                item["approvals"] = v[":a"]
            if "policy_session = :fresh" in UpdateExpression:
                item.update(
                    policy_session=v[":fresh"], approvals=v[":cards"], confirmed=v[":empty"]
                )
            if "confirmed = :confirmed" in UpdateExpression:
                item["confirmed"] = v[":confirmed"]
            if "portal_ticket_seq = :next" in UpdateExpression:
                item["portal_ticket_seq"] = v[":next"]
            if "store_change_source = :source" in UpdateExpression:
                item["store_change_source"] = v[":source"]
            if "exclusion_disposition = :status" in UpdateExpression:
                item["exclusion_disposition"] = v[":status"]
                item["exclusion_reason"] = v[":reason"]
            if "last_run = :run" in UpdateExpression:
                item.update(
                    last_run=v[":run"],
                    before_tickets=v[":before"],
                    store_change_source=v[":src"],
                    run_id=v[":id"],
                )
            if "breaker_open = :f" in UpdateExpression:
                item["breaker_open"] = v[":f"]
            if "active_stage = :stage" in UpdateExpression:
                item.update(
                    active_stage=v[":stage"],
                    stop_requested=False,
                    breaker_open=False,
                    store_change_source=v[":src"],
                    policy_session=v[":ps"],
                )
            if " REMOVE " in UpdateExpression or UpdateExpression.startswith("REMOVE "):
                for col in UpdateExpression.split("REMOVE ", 1)[1].split(","):
                    item.pop(col.strip(), None)
            return {"Attributes": dict(item)}


@pytest.fixture
def api(monkeypatch):
    tables = {
        name: Table(keys)
        for name, keys in (
            ("tickets", ("customer_id", "ticket_id")),
            ("state", ("customer_id",)),
            ("events", ("run_id", "sk")),
        )
    }
    fake = ModuleType("boto3")
    fake.resource = lambda kind: SimpleNamespace(Table=lambda name: tables[name])
    fake.client = lambda name: (_ for _ in ()).throw(AssertionError("network forbidden"))
    monkeypatch.setitem(sys.modules, "boto3", fake)
    monkeypatch.syspath_prepend(str(ROOT / "functions/api"))
    for key, value in (
        ("TICKETS_TABLE", "tickets"),
        ("STATE_TABLE", "state"),
        ("EVENTS_TABLE", "events"),
        ("ISSUER", "offline"),
    ):
        monkeypatch.setenv(key, value)
    for name in ("runs", "jwt_verify"):
        spec = importlib.util.spec_from_file_location(name, ROOT / f"functions/api/{name}.py")
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, mod)
        spec.loader.exec_module(mod)
    spec = importlib.util.spec_from_file_location("security_api", ROOT / "functions/api/app.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    monkeypatch.setattr(app, "persona", lambda event: dict(ALICE))
    monkeypatch.setattr(app, "model_label", lambda: "offline")
    monkeypatch.setattr(app, "agent_param", lambda key, default: json.dumps({"v3": "offline"}))
    for ticket, (subject, body) in app.SEED["customer-a"].items():
        tables["tickets"].put_item(
            Item={
                "customer_id": "customer-a",
                "ticket_id": ticket,
                "subject": subject,
                "body": body,
                "origin": "seed",
                "status": "OPEN",
            }
        )
    tables["state"].put_item(
        Item={"customer_id": "customer-a", "active_stage": "v3", "policy_session": "policy-1"}
    )
    return SimpleNamespace(app=app, tables=tables)


def request(api, path, body=None, token="offline"):
    reply = api.app.lambda_handler(
        {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": path,
            "body": json.dumps(body or {}),
            "headers": {"x-sec310-access-token": token},
        },
        None,
    )
    return reply["statusCode"], json.loads(reply["body"])


def tool_run(payload):
    calls = (
        [
            {
                "tool": "close_ticket",
                "input": {
                    "customer_id": "customer-a",
                    "ticket_id": payload.get("requests", ["A-42"])[0],
                    "reason": "yes",
                },
                "status": "PENDING_APPROVAL",
            }
        ]
        if payload["mode"] == "live" and payload.get("requests")
        else []
    )
    return {
        "run_id": payload["run_id"],
        "model_id": "offline",
        "tool_calls": calls,
        "answer": "summary",
    }


def cards_of(api):
    state = api.app.demo_state("customer-a")
    if hasattr(api.app, "current_approvals"):
        return api.app.current_approvals(state)
    return api.app.approvals(state)


def held(api, monkeypatch, ticket="A-42"):
    monkeypatch.setattr(api.app, "invoke_agent", lambda token, run_id, payload: tool_run(payload))
    status, _ = request(api, "/api/run", {"requests": [ticket]})
    assert status == 200
    return cards_of(api)[-1]


def test_gateway_confirmation_requires_exact_structured_target(api, monkeypatch):
    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self.body

    data = {"status": "CONFIRMED", "ticket_id": "A-42", "customer_id": "customer-a"}
    replies = [data, {**data, "ticket_id": "A-41"}, {**data, "status": "NOT CONFIRMED"}]
    args = {"customer_id": "customer-a", "ticket_id": "A-42"}
    for expected, inner in zip((True, False, False), replies, strict=True):
        rpc = {"result": {"content": [{"text": json.dumps(inner)}]}}
        monkeypatch.setattr(
            api.app.urllib.request,
            "urlopen",
            lambda *a, reply=rpc, **kw: Response(json.dumps(reply).encode()),
        )
        allowed, _ = api.app.gateway_call(
            "offline", "https://gateway.invalid", "policy-1", "TicketTools___confirm_close", args
        )
        assert allowed is expected


def test_post_failure_effect_remains_error_and_unknown_diff_is_explicit(api, monkeypatch):
    api.tables["state"].rows[("customer-a",)]["active_stage"] = "v0"

    def timeout(token, run_id, payload):
        api.tables["tickets"].rows[("customer-a", "A-42")]["status"] = "CLOSED"
        raise TimeoutError("after commit")

    monkeypatch.setattr(api.app, "invoke_agent", timeout)
    status, out = request(api, "/api/run")
    assert status == 200 and out["result"]["status"] == "ERROR"
    assert out["result"]["effects"][0]["target"] == "A-42"
    assert api.app.runs.metrics(out["result"])["ForbiddenEffects"] == 1
    exposed = api.app.public_state(ALICE)
    assert exposed["busy"] and exposed["recovery"]["required"]
    assert exposed["recovery"]["run_id"] == out["result"]["run_id"]
    assert "Runtime/approval" in exposed["recovery"]["reason"]
    assert api.app.runs.failed("v0", "x", "runtime", "timeout")["evidence_uncertain"]


def test_normal_active_writable_intent_is_not_false_recovery_alarm(api):
    api.app.claim_run("customer-a", "live-owner")
    api.tables["state"].rows[("customer-a",)]["breaker_pending"] = "runtime-intent"
    assert api.app.public_state(ALICE)["recovery"]["required"] is False
    api.app.release_run("customer-a", "live-owner")
    assert api.app.public_state(ALICE)["recovery"]["required"] is True


def test_unconfirmed_latch_needs_explicit_operator_reset_after_exclusion(api):
    state = api.tables["state"].rows[("customer-a",)]
    state["breaker_pending"] = "runtime-intent"
    assert api.app.public_state(ALICE)["recovery"]["required"]
    assert request(api, "/api/breaker/reset")[0] == 200
    assert "breaker_pending" not in api.app.demo_state("customer-a")
    assert api.app.public_state(ALICE)["recovery"]["required"] is False


def test_reset_races_real_run_handler_and_keeps_first_owner(api, monkeypatch):
    entered, resume, results = threading.Event(), threading.Event(), []

    def slow(token, run_id, payload):
        entered.set()
        assert resume.wait(5)
        return tool_run(payload)

    monkeypatch.setattr(api.app, "invoke_agent", slow)
    thread = threading.Thread(target=lambda: results.append(request(api, "/api/run")))
    thread.start()
    assert entered.wait(5)
    try:
        owner = api.app.demo_state("customer-a")["busy_owner"]
        assert request(api, "/api/reset")[0] == 409
        assert request(api, "/api/run")[0] == 409
        assert api.app.demo_state("customer-a")["busy_owner"] == owner
    finally:
        resume.set()
        thread.join(5)
    assert results and results[0][0] == 200


def test_expired_owner_hint_never_authorizes_reset_or_new_admission(api):
    api.app.claim_run("customer-a", "stale-owner", duration=-1)
    rec = api.app.public_state(ALICE)["recovery"]
    assert rec["required"] and rec["owner"] == "stale-owner"
    assert "time" in rec["reason"] and "quiescence" in rec["next_step"]
    assert request(api, "/api/reset")[0] == 409
    with pytest.raises(api.app.HttpError):
        api.app.claim_run("customer-a", "new-owner")


def test_reset_and_breaker_recovery_cannot_clear_active_exclusion(api):
    api.app.claim_run("customer-a", "owner")
    api.tables["state"].rows[("customer-a",)]["breaker_open"] = True
    assert request(api, "/api/reset")[0] == 409
    assert request(api, "/api/breaker/reset")[0] == 409
    with pytest.raises(api.app.HttpError):
        api.app.claim_run("customer-a", "other")
    with pytest.raises(Conflict):
        api.app.release_run("customer-a", "other")
    assert api.tables["state"].rows[("customer-a",)]["breaker_open"] is True
    api.app.release_run("customer-a", "owner")
    assert request(api, "/api/reset")[0] == 200


def test_cross_tenant_seed_reset_waits_for_other_tenant_exclusion(api):
    api.app.claim_run("customer-b", "other")
    assert request(api, "/api/reset")[0] == 409
    assert api.app.demo_state("customer-b")["busy_owner"] == "other"
    assert not api.app.demo_state("customer-a").get("busy_owner")
    api.app.release_run("customer-b", "other")


def test_reset_rejects_active_busy_hint_even_without_owner_compatibility(api):
    api.tables["state"].rows[("customer-a",)]["busy_until"] = 10**12
    assert request(api, "/api/reset")[0] == 409


def test_later_run_retains_pending_card_compatibility(api, monkeypatch):
    first = held(api, monkeypatch)
    assert request(api, "/api/run")[0] == 200
    assert any(a["id"] == first["id"] for a in cards_of(api))


def test_invalid_or_busy_approval_never_grants_compatibility(api, monkeypatch):
    card = held(api, monkeypatch)
    grants = []
    monkeypatch.setattr(
        api.app, "gateway_call", lambda *args: (grants.append(args) or True, "CONFIRMED")
    )
    assert (
        request(api, "/api/run", {"mode": "approve", "approval": card["id"], "run_id": "invalid"})[
            0
        ]
        == 400
    )
    api.tables["state"].rows[("customer-a",)]["busy_until"] = 10**12
    assert request(api, "/api/run", {"mode": "approve", "approval": card["id"]})[0] == 409
    assert grants == []


def test_same_uuid7_timestamp_still_yields_distinct_approval_identities(api, monkeypatch):
    monkeypatch.setattr(api.app.runs.time, "time_ns", lambda: 1_792_100_000_000_000_000)
    first = held(api, monkeypatch, "A-42")
    second = held(api, monkeypatch, "A-41")
    assert first["run_id"] != second["run_id"]
    assert first["id"] != second["id"] and first["id"].startswith(first["run_id"])


def test_cards_survive_runs_and_stale_id_targets_exact_card(api, monkeypatch):
    first = held(api, monkeypatch)
    second = held(api, monkeypatch, "A-41")
    assert first["id"] != second["id"] and first["ticket_id"] == "A-42"
    assert (
        request(api, "/api/run", {"run_id": "bad", "mode": "approve", "approval": first["id"]})[0]
        == 400
    )
    api.app.claim_run("customer-a", "blocking")
    assert request(api, "/api/run", {"mode": "approve", "approval": first["id"]})[0] == 409
    api.app.release_run("customer-a", "blocking")
    assert request(api, "/api/approvals/reject", {"id": second["id"]})[0] == 200
    assert request(api, "/api/run")[0] == 200
    cards = api.app.current_approvals(api.app.demo_state("customer-a"))
    assert cards[0]["status"] == "PENDING" and cards[1]["status"] == "REJECTED"
    grants = []
    monkeypatch.setattr(
        api.app, "gateway_call", lambda *args: (grants.append(args) or True, "CONFIRMED")
    )

    def approved(token, run_id, payload):
        if payload.get("approval"):
            target = payload["calls"][0]["input"]["ticket_id"]
            api.tables["tickets"].rows[("customer-a", target)]["status"] = "CLOSED"
        return {"run_id": run_id, "model_id": "offline", "tool_calls": [], "answer": "done"}

    monkeypatch.setattr(api.app, "invoke_agent", approved)
    assert request(api, "/api/run", {"mode": "approve", "approval": first["id"]})[0] == 200
    assert len(grants) == 1 and grants[0][2] == "policy-1"
    assert api.tables["tickets"].rows[("customer-a", "A-42")]["status"] == "CLOSED"
    assert api.tables["tickets"].rows[("customer-a", "A-41")]["status"] == "OPEN"
    state = api.app.demo_state("customer-a")
    assert api.app.current_approvals(state)[0]["status"] == "APPROVED"
    assert state["policy_session"] != "policy-1" and not state.get("approval_dispatch")
    assert request(api, "/api/run", {"mode": "approve", "approval": first["id"]})[0] == 409


def test_approval_history_capacity_rejects_before_model_invocation(api, monkeypatch):
    now = int(api.app.time.time())
    state = api.tables["state"].rows[("customer-a",)]
    state["approvals"] = json.dumps(
        [{"id": str(i), "status": "REJECTED", "at": now} for i in range(53)]
    )
    monkeypatch.setattr(api.app, "invoke_agent", lambda *args: pytest.fail("model must not run"))
    assert request(api, "/api/run")[0] == 409
    assert not api.app.demo_state("customer-a").get("busy_owner")


def test_post_failure_store_read_failure_reports_unknown_not_zero(api, monkeypatch):
    api.tables["state"].rows[("customer-a",)]["active_stage"] = "v0"
    original = api.app.all_tickets
    calls = []

    def unreadable():
        calls.append(True)
        if len(calls) > 1:
            raise RuntimeError("read unavailable")
        return original()

    def timeout(token, run_id, payload):
        api.tables["tickets"].rows[("customer-a", "A-42")]["status"] = "CLOSED"
        raise TimeoutError("write followed by timeout")

    monkeypatch.setattr(api.app, "all_tickets", unreadable)
    monkeypatch.setattr(api.app, "invoke_agent", timeout)
    status, out = request(api, "/api/run")
    result = out["result"]
    assert status == 200 and result["status"] == "ERROR"
    assert result["store_diff_available"] is False and result["evidence_uncertain"]
    assert "effects unknown" in result["note"]
    assert api.app.runs.metrics(result)["EvidenceUncertain"] == 1
    assert api.tables["tickets"].rows[("customer-a", "A-42")]["status"] == "CLOSED"


def test_confirmed_effect_after_runtime_timeout_is_error_not_forbidden(api, monkeypatch):
    card = held(api, monkeypatch)
    monkeypatch.setattr(api.app, "gateway_call", lambda *args: (True, "CONFIRMED"))

    def timeout_after_close(token, run_id, payload):
        api.tables["tickets"].rows[("customer-a", "A-42")]["status"] = "CLOSED"
        raise TimeoutError("response lost after close")

    monkeypatch.setattr(api.app, "invoke_agent", timeout_after_close)
    status, out = request(api, "/api/run", {"mode": "approve", "approval": card["id"]})
    assert status == 200 and out["result"]["status"] == "ERROR"
    assert out["result"]["effects"][0]["confirmed"] is True
    assert out["result"]["evidence_uncertain"] is True
    assert api.app.runs.metrics(out["result"])["ForbiddenEffects"] == 0
    state = api.app.demo_state("customer-a")
    assert cards_of(api)[0]["status"] == "APPROVED" and state.get("busy_owner")
    assert state["policy_session"] != "policy-1"


def test_lost_gateway_reply_retires_session_and_terminal_card(api, monkeypatch):
    card = held(api, monkeypatch)
    old = api.app.demo_state("customer-a")["policy_session"]
    grants = []

    def lost(*args):
        grants.append(args)
        raise TimeoutError("Gateway reply lost after grant")

    monkeypatch.setattr(api.app, "gateway_call", lost)
    assert request(api, "/api/run", {"mode": "approve", "approval": card["id"]})[0] == 502
    state = api.app.demo_state("customer-a")
    assert len(grants) == 1 and state["policy_session"] != old
    assert api.app.current_approvals(state)[0]["status"] == "FAILED"
    assert request(api, "/api/approvals/reject", {"id": card["id"]})[0] == 409
    assert not state.get("approval_uncertain")


@pytest.mark.parametrize("commits", [False, True])
def test_pregrant_marker_write_ambiguity_never_calls_gateway(api, monkeypatch, commits):
    card = held(api, monkeypatch)
    old = api.app.demo_state("customer-a")["policy_session"]
    original = api.app._state.update_item
    monkeypatch.setattr(api.app, "gateway_call", lambda *args: pytest.fail("grant before marker"))

    def ambiguous(**kwargs):
        if kwargs.get("UpdateExpression") == "SET approval_uncertain = :marker":
            if commits:
                original(**kwargs)
            raise RuntimeError("marker reply lost")
        return original(**kwargs)

    monkeypatch.setattr(api.app._state, "update_item", ambiguous)
    assert request(api, "/api/run", {"mode": "approve", "approval": card["id"]})[0] == 502
    st = api.app.demo_state("customer-a")
    assert st["policy_session"] != old and not st.get("approval_uncertain")


@pytest.mark.parametrize("commits", [False, True])
def test_grant_dispatch_write_ambiguity_retires_session(api, monkeypatch, commits):
    card = held(api, monkeypatch)
    original = api.app._state.update_item
    old = api.app.demo_state("customer-a")["policy_session"]
    grants = []
    monkeypatch.setattr(
        api.app, "gateway_call", lambda *args: (grants.append(args) or True, "CONFIRMED")
    )

    def ambiguous(**kwargs):
        if "approval_dispatch = :marker" in kwargs.get("UpdateExpression", ""):
            if commits:
                original(**kwargs)
            raise RuntimeError("lost state write reply")
        return original(**kwargs)

    monkeypatch.setattr(api.app._state, "update_item", ambiguous)
    status, _ = request(api, "/api/run", {"mode": "approve", "approval": card["id"]})
    assert status == 502 and len(grants) == 1
    st = api.app.demo_state("customer-a")
    assert st["policy_session"] != old and not st.get("approval_uncertain")
    assert not st.get("approval_dispatch")
    assert api.app.current_approvals(st)[0]["status"] == "FAILED"


def test_failed_rotation_retains_uncertainty_and_owned_exclusion(api, monkeypatch):
    card = held(api, monkeypatch)
    old = api.app.demo_state("customer-a")["policy_session"]
    monkeypatch.setattr(
        api.app, "gateway_call", lambda *args: (_ for _ in ()).throw(TimeoutError("lost grant"))
    )
    original = api.app._state.update_item

    def no_rotation(**kwargs):
        if "policy_session = :fresh" in kwargs.get("UpdateExpression", ""):
            raise RuntimeError("state store unavailable")
        return original(**kwargs)

    monkeypatch.setattr(api.app._state, "update_item", no_rotation)
    status, _ = request(api, "/api/run", {"mode": "approve", "approval": card["id"]})
    assert status == 503
    st = api.app.demo_state("customer-a")
    assert st["policy_session"] == old and st.get("approval_uncertain") and st.get("busy_owner")
    assert request(api, "/api/reset")[0] == 409
    assert request(api, "/api/run")[0] == 409


def _local_jwt():
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return (
        f"{part({'alg': 'RS256'})}."
        f"{part({'sub': 'alice-sub', 'customer_id': 'customer-a', 'role': 'operator'})}.sig"
    )


def _lost_tool_runtime(api, monkeypatch, tool, live=False, settled_refusal=None):
    """The real Runtime/Recorder dispatch a fake Gateway tool whose reply is lost;
    its actual ticket write is released only after the API has returned."""
    from sec310_agent import agent as runtime
    from sec310_agent.agent import ReplayToolEvent

    dispatched, release, committed = threading.Event(), threading.Event(), threading.Event()
    workers = []

    class Gateway:
        def __init__(self, url, headers):
            self.headers = headers

        def start(self):
            return self

        def stop(self, *args):
            pass

        def list_tools_sync(self):
            return [
                SimpleNamespace(tool_name=f"TicketTools___{name}")
                for name in ("list_tickets", "close_ticket", "add_note", "confirm_close")
            ]

        def call_tool_sync(self, tool_use_id, name, arguments=None):
            if name.endswith(tool):
                if settled_refusal is not None:
                    dispatched.set()
                    return {
                        "toolUseId": tool_use_id,
                        "status": "error",
                        "content": [{"text": settled_refusal}],
                    }

                def write_later():
                    if release.wait(5):
                        with api.tables["tickets"].lock:
                            ticket = api.tables["tickets"].rows[("customer-a", "A-42")]
                            if tool == "close_ticket":
                                ticket["status"] = "CLOSED"
                            else:
                                ticket.setdefault("notes", []).append("late authorized note")
                        committed.set()

                worker = threading.Thread(target=write_later, daemon=True)
                workers.append(worker)
                worker.start()
                dispatched.set()
                raise TimeoutError("Gateway reply lost after dispatch")
            return {"toolUseId": tool_use_id, "status": "success", "content": [{"text": "{}"}]}

    mcp = ModuleType("strands.tools.mcp")
    mcp.MCPClient = Gateway
    monkeypatch.setitem(sys.modules, "strands", ModuleType("strands"))
    monkeypatch.setitem(sys.modules, "strands.tools", ModuleType("strands.tools"))
    monkeypatch.setitem(sys.modules, "strands.tools.mcp", mcp)
    if live:

        def fake_model(payload, actor, gateway, recorder, model_id, run_id):
            use = {
                "toolUseId": "live-1",
                "name": f"TicketTools___{tool}",
                "input": {"customer_id": "customer-a", "ticket_id": "A-42", "note": "yes"},
            }
            event = ReplayToolEvent(use)
            recorder.before(event)
            assert not event.cancel_tool
            try:
                event.result = gateway.call_tool_sync(use["toolUseId"], use["name"], use["input"])
            except Exception as exc:  # actual hook receives the failed Gateway call
                event.exception = exc
                event.result = {"status": "error", "content": [{"text": str(exc)}]}
            recorder.after(event)
            return "summary", "end"

        monkeypatch.setattr(runtime, "live", fake_model)

    def invoke(token, run_id, payload):
        return runtime.run(
            {"run_id": run_id, **{k: v for k, v in payload.items() if k != "run_id"}},
            token,
            gateway_url="https://fake-gateway",
            model_id="model",
            session_id=run_id,
            state_table=api.tables["state"],
        )

    monkeypatch.setattr(api.app, "invoke_agent", invoke)
    return dispatched, release, committed, workers


def test_approved_close_lost_tool_reply_retains_owner_card_and_late_effect(api, monkeypatch):
    card = held(api, monkeypatch)
    monkeypatch.setattr(api.app, "gateway_call", lambda *args: (True, "CONFIRMED"))
    dispatched, release, committed, workers = _lost_tool_runtime(api, monkeypatch, "close_ticket")
    before = api.app.runs.snapshot(api.app.all_tickets())
    try:
        status, out = request(
            api, "/api/run", {"mode": "approve", "approval": card["id"]}, token=_local_jwt()
        )
        assert status == 200 and dispatched.is_set() and not committed.is_set()
        result = out["result"]
        assert result["status"] == "ERROR" and result["tool_outcome_uncertain"]
        assert result["evidence_uncertain"] and result["effects"][0]["status"] == "OUTCOME_UNKNOWN"
        assert api.app.runs.metrics(result)["EvidenceUncertain"] == 1
        state = api.app.demo_state("customer-a")
        assert (
            state["busy_owner"] == result["run_id"] and state["exclusion_disposition"] == "UNKNOWN"
        )
        assert api.app.public_state(ALICE)["recovery"]["required"]
        assert cards_of(api)[0]["status"] == "UNCERTAIN" and state["policy_session"] != "policy-1"
        assert request(api, "/api/reset")[0] == 409 and request(api, "/api/run")[0] == 409
    finally:
        release.set()
        for worker in workers:
            worker.join(5)
    assert (
        committed.is_set()
        and api.tables["tickets"].rows[("customer-a", "A-42")]["status"] == "CLOSED"
    )
    assert api.app.demo_state("customer-a")["store_change_source"] != "Clean reset"
    actual = api.app.runs.effects(before, api.app.runs.snapshot(api.app.all_tickets()), ("A-42",))
    assert actual[0]["confirmed"] is True  # late effect authorized, but completion was unknown


def test_approved_close_authoritatively_denied_finishes_without_unknown(api, monkeypatch):
    card = held(api, monkeypatch)
    monkeypatch.setattr(api.app, "gateway_call", lambda *args: (True, "CONFIRMED"))
    sent, _, committed, _ = _lost_tool_runtime(
        api, monkeypatch, "close_ticket", settled_refusal="AgentCore Policy denied: not authorized"
    )
    status, out = request(
        api, "/api/run", {"mode": "approve", "approval": card["id"]}, token=_local_jwt()
    )
    result = out["result"]
    assert status == 200 and sent.is_set() and not committed.is_set()
    assert result["status"] == "BLOCKED" and not result["evidence_uncertain"]
    assert result["effects"][0]["status"] == "DENIED_GATEWAY"
    assert cards_of(api)[0]["status"] == "FAILED"
    assert not api.app.demo_state("customer-a").get("busy_owner")
    assert request(api, "/api/reset")[0] == 200


def test_pre_dispatch_invalid_request_and_holds_do_not_create_unknown_effect(api, monkeypatch):
    monkeypatch.setattr(
        api.app, "invoke_agent", lambda *args: pytest.fail("invalid request dispatched")
    )
    assert request(api, "/api/run", {"requests": ["B-77"]})[0] == 400
    assert not api.app.demo_state("customer-a").get("busy_owner")
    monkeypatch.setattr(api.app, "invoke_agent", lambda token, run_id, payload: tool_run(payload))
    status, out = request(api, "/api/run", {"requests": ["A-42"]})
    assert status == 200 and out["result"]["status"] == "AWAITING_APPROVAL"
    assert not out["result"]["evidence_uncertain"] and not api.app.demo_state("customer-a").get(
        "busy_owner"
    )


def test_authoritative_policy_denial_is_completed_not_unknown(api, monkeypatch):
    state = api.tables["state"].rows[("customer-a",)]
    state["active_stage"] = "v2"
    state["capture"] = json.dumps(
        {
            "stage": "v2",
            "run_id": "captured",
            "fingerprint": api.app.runs.fingerprint(api.app.tickets_for("customer-a")),
            "calls": [
                {
                    "tool": "close_ticket",
                    "input": {"customer_id": "customer-a", "ticket_id": "A-42"},
                }
            ],
        }
    )
    sent, _, committed, _ = _lost_tool_runtime(
        api, monkeypatch, "close_ticket", settled_refusal="AgentCore Policy denied: not authorized"
    )
    status, out = request(api, "/api/run", {"mode": "replay"}, token=_local_jwt())
    result = out["result"]
    assert status == 200 and sent.is_set() and not committed.is_set()
    assert result["status"] == "BLOCKED" and not result["evidence_uncertain"]
    assert result["effects"][0]["status"] == "DENIED_GATEWAY"
    assert api.app.runs.metrics(result)["EvidenceUncertain"] == 0
    assert not api.app.demo_state("customer-a").get("busy_owner")
    assert request(api, "/api/reset")[0] == 200


@pytest.mark.parametrize(
    "stage,mode,tool", [("v0", "live", "add_note"), ("v1", "replay", "close_ticket")]
)
def test_earlier_stage_lost_write_reply_never_cleanly_completes(
    api, monkeypatch, stage, mode, tool
):
    state = api.tables["state"].rows[("customer-a",)]
    state["active_stage"] = stage
    if mode == "replay":
        state["capture"] = json.dumps(
            {
                "stage": stage,
                "run_id": "captured",
                "fingerprint": api.app.runs.fingerprint(api.app.tickets_for("customer-a")),
                "calls": [
                    {"tool": tool, "input": {"customer_id": "customer-a", "ticket_id": "A-42"}}
                ],
            }
        )
    dispatched, release, committed, workers = _lost_tool_runtime(
        api, monkeypatch, tool, live=mode == "live"
    )
    try:
        status, out = request(api, "/api/run", {"mode": mode}, token=_local_jwt())
        assert status == 200 and dispatched.is_set() and not committed.is_set()
        result = out["result"]
        assert result["status"] == "ERROR" and result["tool_outcome_uncertain"]
        assert result["effects"][0]["status"] == "OUTCOME_UNKNOWN"
        assert api.app.runs.metrics(result)["EvidenceUncertain"] == 1
        assert api.app.demo_state("customer-a")["busy_owner"] == result["run_id"]
        assert request(api, "/api/reset")[0] == 409
    finally:
        release.set()
        for worker in workers:
            worker.join(5)
    assert committed.is_set()
    ticket = api.tables["tickets"].rows[("customer-a", "A-42")]
    assert ticket["status"] == "CLOSED" if tool == "close_ticket" else len(ticket["notes"]) == 1


def test_concurrent_rejection_and_reset_blocked_before_gateway_grant(api, monkeypatch):
    card = held(api, monkeypatch)
    entered, resume = threading.Event(), threading.Event()

    def gateway(*args):
        entered.set()
        assert resume.wait(5)
        return False, "refused"

    monkeypatch.setattr(api.app, "gateway_call", gateway)
    out = []
    thread = threading.Thread(
        target=lambda: out.append(
            request(api, "/api/run", {"mode": "approve", "approval": card["id"]})[0]
        )
    )
    thread.start()
    assert entered.wait(5)
    try:
        assert request(api, "/api/approvals/reject", {"id": card["id"]})[0] == 409
        assert request(api, "/api/reset")[0] == 409
    finally:
        resume.set()
        thread.join(5)
    assert out == [502]
