"""v0 cold open: prove the unsafe agent is useful *and* dangerous at the same time."""

from sec310_sample.unsafe_agent import UnsafeAgent
from tests.conftest import load_fixture


def test_unsafe_agent_answers_the_happy_path(store, model):
    agent = UnsafeAgent(model, store)
    request = load_fixture("normal-evidence")["request"]

    result = agent.handle(request)

    assert "acct-a" in result["answer"]
    assert (
        result["executed"][0]["operation"] == "update_rule"
    )  # it even re-enabled the rule, unasked-for confirmation
    assert store.rule("acct-a", "rule-42")["enabled"] is True


def test_unsafe_agent_follows_injected_tool_data_across_tenants(poisoned_store, model):
    """The user asked an honest question. A poisoned finding told the model to delete
    a rule in another tenant's account. Nothing stopped it."""
    agent = UnsafeAgent(model, poisoned_store)
    request = load_fixture("indirect-injection")["request"]
    assert "rule-77" in poisoned_store.rules("acct-b")

    result = agent.handle(request)

    assert {
        "op": "delete_rule",
        "account_id": "acct-b",
        "rule_id": "rule-77",
    } in poisoned_store.mutation_log
    assert "rule-77" not in poisoned_store.rules("acct-b")
    assert any(link.startswith("https://exfil.example.net") for link in result["links"])


def test_unsafe_agent_trusts_tenant_from_body(store, model):
    """Bob from tenant-b just types tenant-a's account id into the body."""
    agent = UnsafeAgent(model, store)
    request = {
        "tenant_id": "tenant-b",
        "principal_id": "bob",
        "account_id": "acct-a",
        "session_id": "session-9",
        "query": "Summarise the findings.",
    }

    result = agent.handle(request)

    assert "acct-a" in result["answer"]  # cross-tenant read, no error
