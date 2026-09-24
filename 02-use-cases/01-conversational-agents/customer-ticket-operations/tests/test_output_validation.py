"""Patch 2: typed output and deterministic link validation."""

import pytest

from sec310_sample.errors import OutputValidationError
from sec310_sample.identity import RequestIdentity
from sec310_sample.output_validation import link_rejection_reason, validate_response
from sec310_sample.schemas import AssistantResponse, Operation, parse_model_output

ALICE = RequestIdentity("tenant-a", "alice", frozenset({"acct-a"}))


@pytest.mark.parametrize(
    "link, reason",
    [
        ("/accounts/acct-a/findings", None),
        ("/rules/rule-42", None),
        ("https://exfil.example.net/collect", "absolute_url"),
        ("//exfil.example.net/collect", "absolute_url"),
        ("javascript:alert(1)", "absolute_url"),
        ("/accounts/../admin", "path_traversal"),
        ("/admin/users", "route_not_allowed"),
    ],
)
def test_link_rules(link, reason):
    assert link_rejection_reason(link) == reason


def test_malformed_output_is_rejected_not_repaired():
    with pytest.raises(OutputValidationError, match="malformed_output"):
        parse_model_output('{"answer": "ok", "proposed_actions": [{"operation": "drop_table"}]}')
    with pytest.raises(OutputValidationError):
        parse_model_output("Sure! Here is some JSON: {}")


def test_schema_forbids_unknown_fields_and_bad_identifiers():
    with pytest.raises(OutputValidationError):
        parse_model_output(
            '{"answer": "ok", "proposed_actions": [], "links": [], "credentials": "x"}'
        )
    with pytest.raises(OutputValidationError):
        parse_model_output(
            '{"answer": "ok", "proposed_actions": [{"operation": "read_evidence", "account_id": "not-an-account", "resource_id": "-", "reason": "r"}]}'
        )


def test_validate_response_scopes_proposals_to_identity():
    response = AssistantResponse.model_validate(
        {
            "answer": "ok",
            "proposed_actions": [
                {
                    "operation": "read_evidence",
                    "account_id": "acct-a",
                    "resource_id": "-",
                    "reason": "r",
                },
                {
                    "operation": "delete_rule",
                    "account_id": "acct-b",
                    "resource_id": "rule-77",
                    "reason": "injected",
                },
            ],
            "links": ["/accounts/acct-a/findings", "https://exfil.example.net/x"],
        }
    )

    validated = validate_response(response, ALICE)

    assert [p.operation for p in validated.proposed_actions] == [Operation.READ_EVIDENCE]
    assert validated.rejected_actions[0][1] == "target_not_authorized"
    assert validated.links == ("/accounts/acct-a/findings",)
    assert validated.rejected_links == (("https://exfil.example.net/x", "absolute_url"),)


def test_change_payload_keys_are_allow_listed():
    from sec310_sample.schemas import ActionPlan, Operation

    with pytest.raises(ValueError, match="change may only touch"):
        ActionPlan(
            operation=Operation.UPDATE_RULE,
            account_id="acct-a",
            resource_id="rule-42",
            reason="r",
            change={"owner": "mallory"},
        )
    plan = ActionPlan(
        operation=Operation.UPDATE_RULE,
        account_id="acct-a",
        resource_id="rule-42",
        reason="r",
        change={"enabled": True},
    )
    assert plan.change == {"enabled": True}
