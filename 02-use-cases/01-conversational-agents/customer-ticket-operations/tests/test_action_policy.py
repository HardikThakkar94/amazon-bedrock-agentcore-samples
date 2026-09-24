"""Patch 3: a typed, schema-valid plan is still just a proposal until policy says otherwise."""

import pytest

from sec310_sample.action_gateway import ActionGateway, Confirmation, action_digest
from sec310_sample.credentials import CredentialBroker
from sec310_sample.errors import AuthorizationError, PolicyRejected
from sec310_sample.identity import RequestIdentity
from sec310_sample.schemas import ActionPlan, Operation

ALICE = RequestIdentity(
    "tenant-a", "alice", frozenset({"acct-a"}), frozenset({"analyst", "responder"})
)
CAROL = RequestIdentity(
    "tenant-a", "carol", frozenset({"acct-a"}), frozenset({"analyst"})
)  # read-only role

READ = ActionPlan(
    operation=Operation.READ_EVIDENCE, account_id="acct-a", resource_id="-", reason="look"
)
ENABLE_42 = ActionPlan(
    operation=Operation.UPDATE_RULE,
    account_id="acct-a",
    resource_id="rule-42",
    reason="re-enable",
    change={"enabled": True},
)
DELETE_42 = ActionPlan(
    operation=Operation.DELETE_RULE, account_id="acct-a", resource_id="rule-42", reason="injected"
)
CROSS_TENANT = ActionPlan(
    operation=Operation.UPDATE_RULE,
    account_id="acct-b",
    resource_id="rule-77",
    reason="injected",
    change={"enabled": False},
)


@pytest.fixture
def gateway(store):
    return ActionGateway(store, CredentialBroker())


def confirm(identity, plan, by=None):
    return Confirmation(action_digest(identity, plan), by or identity.principal_id)


def test_reads_are_allowed_within_scope(gateway):
    result = gateway.execute(ALICE, READ)

    assert result.status == "ok"
    assert result.payload["account_id"] == "acct-a"


def test_schema_valid_write_without_confirmation_is_not_executed(gateway, store):
    result = gateway.execute(ALICE, ENABLE_42)

    assert result.status == "confirmation_required"
    assert store.rule("acct-a", "rule-42")["enabled"] is False
    assert store.mutation_log == []


def test_confirmed_write_executes_once_and_is_audited(gateway, store):
    first = gateway.execute(ALICE, ENABLE_42, confirm(ALICE, ENABLE_42))
    replay = gateway.execute(ALICE, ENABLE_42, confirm(ALICE, ENABLE_42))  # client retried

    assert first.status == "ok"
    assert replay.status == "replayed"
    assert replay.payload == first.payload
    assert len(store.mutation_log) == 1  # exactly-once effect
    assert len(gateway.audit) == 1 and gateway.audit.verify_chain()


def test_confirmation_is_bound_to_the_exact_action_and_principal(gateway):
    other_plan = ENABLE_42.model_copy(update={"change": {"enabled": False}})

    with pytest.raises(PolicyRejected, match="confirmation_digest_mismatch"):
        gateway.execute(ALICE, ENABLE_42, confirm(ALICE, other_plan))  # confirmed something else
    with pytest.raises(PolicyRejected, match="confirmation_principal_mismatch"):
        gateway.execute(
            ALICE, ENABLE_42, confirm(ALICE, ENABLE_42, by="bob")
        )  # someone else clicked


def test_delete_is_not_a_capability_this_path_has(gateway, store):
    with pytest.raises(PolicyRejected, match="capability_absent"):
        gateway.execute(
            ALICE, DELETE_42, confirm(ALICE, DELETE_42)
        )  # even confirmed, even in scope

    assert "rule-42" in store.rules("acct-a")


def test_cross_tenant_write_is_denied_before_anything_else(gateway, store):
    with pytest.raises(AuthorizationError, match="target_not_authorized"):
        gateway.execute(ALICE, CROSS_TENANT, confirm(ALICE, CROSS_TENANT))

    assert store.rule("acct-b", "rule-77")["enabled"] is True


def test_role_without_write_capability_cannot_mutate_even_with_confirmation(gateway, store):
    with pytest.raises(AuthorizationError, match="write_capability_not_granted"):
        gateway.execute(CAROL, ENABLE_42, confirm(CAROL, ENABLE_42))

    assert store.mutation_log == []


def test_state_validation_rejects_no_op_and_missing_targets(gateway):
    gateway.execute(ALICE, ENABLE_42, confirm(ALICE, ENABLE_42))
    again = ENABLE_42.model_copy(update={"reason": "second time"})  # different digest, same effect
    with pytest.raises(PolicyRejected, match="no_op_change"):
        gateway.execute(ALICE, again, confirm(ALICE, again))

    ghost = ENABLE_42.model_copy(update={"resource_id": "rule-999"})
    with pytest.raises(PolicyRejected, match="target_not_found"):
        gateway.execute(ALICE, ghost, confirm(ALICE, ghost))
