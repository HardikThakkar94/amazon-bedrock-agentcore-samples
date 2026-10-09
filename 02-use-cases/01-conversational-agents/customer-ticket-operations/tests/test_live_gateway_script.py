"""scripts/live_gateway.py: discovery must see every page and teardown must tell the truth.

The script is exercised with botocore Stubber on real clients, so pagination tokens and
response shapes are the service's own.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3", reason="aws extra not installed")
from botocore.stub import Stubber  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "live_gateway.py"


@pytest.fixture
def script():
    spec = importlib.util.spec_from_file_location("live_gateway", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["live_gateway"] = module
    spec.loader.exec_module(module)
    return module


def _live(script, monkeypatch):
    """A Live() whose clients are real botocore clients (so Stubber works) and never sleep."""
    live = object.__new__(script.Live)
    live.session = boto3.session.Session(region_name="us-east-1")
    live.region = "us-east-1"
    live.account = "fake-account-1234"
    live.iam = live.session.client("iam")
    live.lam = live.session.client("lambda")
    live.ctl = live.session.client("bedrock-agentcore-control")
    live.problems = []
    monkeypatch.setattr(script.time, "sleep", lambda s: None)
    return live


def _engine(name, eid, status="ACTIVE"):
    return {
        "policyEngineId": eid,
        "policyEngineArn": f"test-engine-{eid}".ljust(80, "x"),
        "name": name,
        "status": status,
        "statusReasons": [],
        "createdAt": 0,
        "updatedAt": 0,
    }


def _gateway_item(name, gid):
    return {
        "gatewayId": gid,
        "name": name,
        "status": "READY",
        "createdAt": 0,
        "updatedAt": 0,
        "authorizerType": "AWS_IAM",
        "protocolType": "MCP",
    }


def test_down_finds_the_demo_resources_on_a_later_page(script, monkeypatch):
    live = _live(script, monkeypatch)
    ctl, lam, iam = Stubber(live.ctl), Stubber(live.lam), Stubber(live.iam)
    # page 1 holds unrelated gateways; the demo gateway is on page 2
    ctl.add_response(
        "list_gateways",
        {"items": [_gateway_item("someone-elses", "other-0123456789")], "nextToken": "p2"},
    )
    ctl.add_response(
        "list_gateways",
        {"items": [_gateway_item(script.GATEWAY_NAME, "demo-0123456789")]},
        expected_params={"nextToken": "p2"},
    )
    ctl.add_response("list_gateway_targets", {"items": []})
    ctl.add_response("delete_gateway", {"gatewayId": "demo-0123456789", "status": "DELETING"})
    ctl.add_client_error("get_gateway", service_error_code="ResourceNotFoundException")
    # same for engines
    ctl.add_response(
        "list_policy_engines",
        {"policyEngines": [_engine("unrelated", "unrelated-0123456789ab")], "nextToken": "e2"},
    )
    ctl.add_response(
        "list_policy_engines",
        {"policyEngines": [_engine(script.ENGINE_NAME, "sec310demogw-0123456789")]},
        expected_params={"nextToken": "e2"},
    )
    ctl.add_response("list_policies", {"policies": []})
    ctl.add_response(
        "delete_policy_engine", _engine(script.ENGINE_NAME, "sec310demogw-0123456789", "DELETING")
    )
    ctl.add_client_error("get_policy_engine", service_error_code="ResourceNotFoundException")
    lam.add_client_error("delete_function", service_error_code="ResourceNotFoundException")
    lam.add_client_error("get_function", service_error_code="ResourceNotFoundException")
    for _ in (script.GATEWAY_ROLE, script.LAMBDA_ROLE):
        iam.add_client_error("list_attached_role_policies", service_error_code="NoSuchEntity")
        iam.add_client_error("get_role", service_error_code="NoSuchEntity")
    with ctl, lam, iam:
        code = live.down()
        ctl.assert_no_pending_responses()
    assert code == 0 and live.problems == []


def test_down_reports_what_it_could_not_delete_and_exits_nonzero(script, monkeypatch):
    live = _live(script, monkeypatch)
    ctl, lam, iam = Stubber(live.ctl), Stubber(live.lam), Stubber(live.iam)
    ctl.add_response(
        "list_gateways", {"items": [_gateway_item(script.GATEWAY_NAME, "demo-0123456789")]}
    )
    ctl.add_response("list_gateway_targets", {"items": []})
    ctl.add_client_error("delete_gateway", service_error_code="AccessDeniedException")
    ctl.add_response("list_policy_engines", {"policyEngines": []})
    lam.add_client_error("delete_function", service_error_code="ResourceNotFoundException")
    lam.add_client_error("get_function", service_error_code="ResourceNotFoundException")
    for _ in (script.GATEWAY_ROLE, script.LAMBDA_ROLE):
        iam.add_client_error("list_attached_role_policies", service_error_code="NoSuchEntity")
        iam.add_client_error("get_role", service_error_code="NoSuchEntity")
    with ctl, lam, iam:
        code = live.down()
    assert code == 1
    assert live.problems == [f"gateway {script.GATEWAY_NAME}: AccessDeniedException"]


def test_down_never_touches_other_names(script, monkeypatch):
    live = _live(script, monkeypatch)
    ctl, lam, iam = Stubber(live.ctl), Stubber(live.lam), Stubber(live.iam)
    ctl.add_response(
        "list_gateways", {"items": [_gateway_item("production-gateway", "prod-0123456789")]}
    )
    ctl.add_response(
        "list_policy_engines",
        {"policyEngines": [_engine("production_engine", "prod-0123456789ab")]},
    )
    lam.add_client_error("delete_function", service_error_code="ResourceNotFoundException")
    lam.add_client_error("get_function", service_error_code="ResourceNotFoundException")
    for _ in (script.GATEWAY_ROLE, script.LAMBDA_ROLE):
        iam.add_client_error("list_attached_role_policies", service_error_code="NoSuchEntity")
        iam.add_client_error("get_role", service_error_code="NoSuchEntity")
    with ctl, lam, iam:
        assert (
            live.down() == 0
        )  # no delete_gateway / delete_policy_engine was ever stubbed, so none was called
        ctl.assert_no_pending_responses()


def test_policies_are_created_in_dependency_order_and_the_scope_is_a_forbid(script):
    names = [n for n, _, _ in script.policies("gw-arn")]
    kinds = {n: k for n, k, _ in script.policies("gw-arn")}
    statements = {n: st for n, _, st in script.policies("gw-arn")}
    assert names.index("look_before_you_write") < names.index("no_writes_outside_acct_a")
    assert kinds["look_before_you_write"] == "policy"  # Dogwood goes under `policy`, not `cedar`
    assert statements["no_writes_outside_acct_a"].startswith("forbid(")
    assert 'like "acct-*"' in statements["read_known_accounts"]
    assert "formerly within 1h" in statements["look_before_you_write"]
    assert "input.account_id: context.input.account_id" in statements["look_before_you_write"]
    assert all(" " not in n and "-" not in n for n in names)  # policy-name constraint


def test_gateway_name_and_policy_names_follow_the_two_different_rules(script):
    import re

    assert re.fullmatch(r"([0-9a-zA-Z][-]?){1,48}", script.GATEWAY_NAME)
    for name in (script.ENGINE_NAME, *[n for n, _, _ in script.policies("gw-arn")]):
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", name), name
