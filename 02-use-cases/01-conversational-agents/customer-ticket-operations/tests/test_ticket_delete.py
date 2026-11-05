"""Offline API ticket deletion through the real handler and conditional in-memory tables."""

import json

import pytest

from tests.test_security_regressions import ALICE, Conflict

pytest_plugins = ["tests.test_security_regressions"]


def submit(api, monkeypatch, text="new ticket"):
    customer = {**ALICE, "role": "customer", "username": "visitor"}
    return api.app.submit_ticket(customer, {"subject": "Portal", "body": text})["ticket"][
        "ticket_id"
    ]


def delete(api, ticket_id):
    return api.app.lambda_handler(
        {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/api/tickets/delete",
            "body": json.dumps({"ticket_id": ticket_id}),
            "headers": {"x-sec310-access-token": "offline"},
        },
        None,
    )


def status(response):
    return response["statusCode"], json.loads(response["body"])


def assert_http(api, action, code):
    with pytest.raises(api.app.HttpError) as e:
        action()
    assert e.value.status == code


def test_delete_only_own_portal_ticket_preserves_control_and_run_history(api, monkeypatch):
    ticket = submit(api, monkeypatch)
    state = api.app.demo_state("customer-a")
    state.update(
        {
            "capture": json.dumps(
                {"stage": "v5", "run_id": "old", "calls": [], "fingerprint": "old"}
            ),
            "last_run": json.dumps({"status": "NO_EFFECT"}),
            "run_id": "old-run",
            "breaker_open": True,
            "stop_requested": True,
            "policy_session": "ps-1",
            "approvals": json.dumps([{"ticket_id": ticket, "status": "REJECTED", "id": "older"}]),
        }
    )
    api.tables["state"].put_item(Item=state)
    code, result = status(delete(api, ticket))
    assert (code, result) == (200, {"deleted": ticket, "source": "operator"})
    assert not api.tables["tickets"].get_item(
        Key={"customer_id": "customer-a", "ticket_id": ticket}
    )
    st = api.app.demo_state("customer-a")
    for key in (
        "active_stage",
        "last_run",
        "run_id",
        "breaker_open",
        "stop_requested",
        "policy_session",
        "approvals",
    ):
        assert st[key] == state[key]
    assert "capture" not in st and "busy_owner" not in st
    assert st["store_change_source"] == f"Operator deleted portal ticket {ticket}"
    assert not api.app.public_state(ALICE)["capture_available"]
    assert not any(t["ticket_id"] == ticket for t in api.app.public_state(ALICE)["tickets"])
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": ticket}), 404)
    next_ticket = submit(api, monkeypatch)
    assert next_ticket != ticket and int(next_ticket.split("-")[1]) > int(ticket.split("-")[1])


def test_delete_refuses_seed_cross_tenant_missing_invalid_and_nonoperator(api, monkeypatch):
    ticket = submit(api, monkeypatch)
    other = api.app.submit_ticket(
        {**ALICE, "role": "customer", "customer_id": "customer-b", "username": "visitor-b"},
        {"subject": "Other", "body": "private"},
    )["ticket"]["ticket_id"]
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": "A-41"}), 403)
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": other}), 404)
    assert api.tables["tickets"].get_item(Key={"customer_id": "customer-b", "ticket_id": other})
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": "A-999999"}), 404)
    for invalid in ("", "../A-41", "a-90", "A-1' OR '1", 42):
        assert_http(
            api,
            lambda invalid=invalid: api.app.delete_portal_ticket(ALICE, {"ticket_id": invalid}),
            400,
        )
    assert_http(
        api,
        lambda: api.app.delete_portal_ticket({**ALICE, "role": "customer"}, {"ticket_id": ticket}),
        403,
    )
    # A forged row with a protected seed ID cannot bypass the immutable seed-id fence.
    api.tables["tickets"].rows[("customer-a", "A-41")]["origin"] = "form"
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": "A-41"}), 403)
    assert api.tables["tickets"].get_item(Key={"customer_id": "customer-a", "ticket_id": ticket})


def test_delete_respects_busy_recovery_and_pending_approval(api, monkeypatch):
    ticket = submit(api, monkeypatch)
    api.app.claim_run("customer-a", "live-owner")
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": ticket}), 409)
    api.app.release_run("customer-a", "live-owner")
    table = api.tables["state"]
    st = api.app.demo_state("customer-a")
    st["exclusion_disposition"] = "UNKNOWN"
    table.put_item(Item=st)
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": ticket}), 409)
    st.pop("exclusion_disposition")
    st["approvals"] = json.dumps(
        [
            {
                "ticket_id": ticket,
                "status": "PENDING",
                "id": "card",
                "created_at": int(api.app.time.time()),
            }
        ]
    )
    table.put_item(Item=st)
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": ticket}), 409)
    assert not api.app.demo_state("customer-a").get("busy_owner")
    assert api.tables["tickets"].get_item(Key={"customer_id": "customer-a", "ticket_id": ticket})


def test_delete_conditional_conflict_releases_owner_and_ambiguous_failure_retains_it(
    api, monkeypatch
):
    ticket = submit(api, monkeypatch)
    original = api.tables["tickets"].delete_item

    def conflict(**kw):
        raise Conflict()

    monkeypatch.setattr(api.tables["tickets"], "delete_item", conflict)
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": ticket}), 409)
    assert not api.app.demo_state("customer-a").get("busy_owner")

    def ambiguous(**kw):
        raise TimeoutError("write outcome unknown")

    monkeypatch.setattr(api.tables["tickets"], "delete_item", ambiguous)
    code, body = status(delete(api, ticket))
    assert code == 503 and "write outcome unknown" not in str(body)
    st = api.app.demo_state("customer-a")
    assert st["busy_owner"] and st["exclusion_disposition"] == "UNKNOWN"
    monkeypatch.setattr(api.tables["tickets"], "delete_item", original)
    assert_http(api, lambda: api.app.delete_portal_ticket(ALICE, {"ticket_id": ticket}), 409)


def test_state_write_failure_after_delete_keeps_exclusion_for_reconciliation(api, monkeypatch):
    ticket = submit(api, monkeypatch)
    table = api.tables["state"]
    original = table.update_item

    def fail_record(**kw):
        if "REMOVE capture" in kw["UpdateExpression"]:
            raise RuntimeError("state unavailable")
        return original(**kw)

    monkeypatch.setattr(table, "update_item", fail_record)
    code, body = status(delete(api, ticket))
    assert code == 503 and "state unavailable" not in str(body)
    assert not api.tables["tickets"].get_item(
        Key={"customer_id": "customer-a", "ticket_id": ticket}
    )
    st = api.app.demo_state("customer-a")
    assert st["busy_owner"] and st["exclusion_disposition"] == "UNKNOWN"


def test_legacy_highest_deleted_id_never_reused_and_history_remains(api, monkeypatch):
    """Reproduce R1: pre-upgrade portal rows lack portal_ticket_seq in tenant state."""
    ticket = "A-90"
    api.tables["tickets"].put_item(
        Item={
            "customer_id": "customer-a",
            "ticket_id": ticket,
            "origin": "form",
            "submitted_by": "customer",
            "status": "OPEN",
            "subject": "old",
            "body": "old",
        }
    )
    state = api.app.demo_state("customer-a")
    assert "portal_ticket_seq" not in state
    state.update(
        {
            "last_run": json.dumps(
                {"proposals": [{"ticket_id": ticket, "operation": "add_note"}], "effects": []}
            ),
            "approvals": json.dumps([{"ticket_id": ticket, "status": "REJECTED", "id": "legacy"}]),
        }
    )
    api.tables["state"].put_item(Item=state)
    assert status(delete(api, ticket)) == (200, {"deleted": ticket, "source": "operator"})
    assert api.app.demo_state("customer-a")["portal_ticket_seq"] == 90
    customer = {**ALICE, "role": "customer", "username": "visitor"}
    new_id = api.app.submit_ticket(customer, {"subject": "New", "body": "after delete"})["ticket"][
        "ticket_id"
    ]
    assert new_id == "A-91"
    assert status(delete(api, new_id))[0] == 200
    before_reset = api.app.demo_state("customer-a")
    assert before_reset["portal_ticket_seq"] == 91
    assert before_reset["last_run"] == state["last_run"]
    assert before_reset["approvals"] == state["approvals"]
    # Local in-memory reset of the demo does not reset this monotonic identity marker.
    api.app.reset_demo(ALICE)
    again = api.app.submit_ticket(customer, {"subject": "Newer", "body": "after reset"})["ticket"][
        "ticket_id"
    ]
    assert again == "A-92"
    st = api.app.demo_state("customer-a")
    assert st["portal_ticket_seq"] == 92
    assert "busy_owner" not in st
    # Reset deliberately clears run history; before it, deletion retained it unchanged.


def test_delete_legacy_high_water_includes_other_live_ids_and_existing_seq(api, monkeypatch):
    for ticket in ("A-90", "A-98"):
        api.tables["tickets"].put_item(
            Item={
                "customer_id": "customer-a",
                "ticket_id": ticket,
                "origin": "form",
                "submitted_by": "customer",
                "status": "OPEN",
            }
        )
    state = api.app.demo_state("customer-a")
    state["portal_ticket_seq"] = 96
    api.tables["state"].put_item(Item=state)
    assert status(delete(api, "A-90"))[0] == 200
    assert api.app.demo_state("customer-a")["portal_ticket_seq"] == 98
    assert status(delete(api, "A-98"))[0] == 200
    assert api.app.demo_state("customer-a")["portal_ticket_seq"] == 98
    assert submit(api, monkeypatch) == "A-99"


def test_legacy_high_water_write_failure_keeps_owner_and_no_duplicate(api, monkeypatch):
    api.tables["tickets"].put_item(
        Item={
            "customer_id": "customer-a",
            "ticket_id": "A-90",
            "origin": "form",
            "submitted_by": "customer",
            "status": "OPEN",
        }
    )
    table = api.tables["state"]
    original = table.update_item

    def fail(**kw):
        if "store_change_source = :source" in kw["UpdateExpression"]:
            raise TimeoutError("high-water update uncertain")
        return original(**kw)

    monkeypatch.setattr(table, "update_item", fail)
    code, body = status(delete(api, "A-90"))
    assert code == 503 and "high-water update uncertain" not in str(body)
    assert api.app.demo_state("customer-a")["busy_owner"]
    assert api.app.demo_state("customer-a")["exclusion_disposition"] == "UNKNOWN"
    assert_http(api, lambda: submit(api, monkeypatch), 409)
