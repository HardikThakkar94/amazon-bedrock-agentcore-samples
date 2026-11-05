"""CloudWatch trace contract: observed flattened Logs Insights fields, owner fencing and safe output."""

import json

import pytest

from tests.test_security_regressions import ALICE

pytest_plugins = ["tests.test_security_regressions"]

RUN = "019a2900-0000-7000-8000-000000000001"


class Logs:
    def __init__(self, status="Complete", failure=None):
        self.calls = []
        self.status = status
        self.failure = failure

    def describe_log_groups(self, logGroupNamePrefix, limit):
        if self.failure == "describe":
            raise RuntimeError("secret failure details")
        return {"logGroups": [{"logGroupName": logGroupNamePrefix}]}

    def start_query(self, **kwargs):
        self.calls.append(kwargs)
        if self.failure == "start":
            raise RuntimeError("secret failure details")
        return {"queryId": str(len(self.calls))}

    def get_query_results(self, queryId):
        if self.failure == "results":
            raise RuntimeError("secret failure details")
        return {
            "status": self.status,
            "results": [
                [
                    {"field": "@timestamp", "value": "2026-10-29 12:00:00.000"},
                    {"field": "body.policy.decision", "value": "DENY"},
                    {"field": "decision", "value": "DENY"},
                    {
                        "field": "policies",
                        "value": '[{"policyId":"tenant_fence","statement":"secret"}, {"policyId":"unsafe <script>"}]',
                    },
                    {"field": "latency", "value": "31"},
                    {"field": "name", "value": "strands.agent.invoke"},
                    {"field": "scope", "value": "strands.telemetry.tracer"},
                    {"field": "ms", "value": "2.51"},
                    {"field": "@message", "value": "ticket text and bearer token"},
                    {"field": "@ptr", "value": "raw log pointer"},
                    {"field": "tool", "value": "<img src=x onerror=alert(1)>"},
                ]
            ],
        }


def setup(api, monkeypatch, logs):
    api.tables["events"].put_item(
        Item={"run_id": RUN, "sk": api.app.OWNER_SK, "customer_id": "customer-a"}
    )
    monkeypatch.setenv("INVOCATION_LOG_GROUP", "model")
    monkeypatch.setattr(api.app, "agent_config", lambda: {"runtime_arn": "arn:runtime/test"})
    monkeypatch.setattr(
        api.app.boto3, "client", lambda service: logs if service == "logs" else None
    )
    return api.app.run_trace(ALICE, RUN)


def test_queries_use_observed_flattened_session_field_and_project_safe_columns(api, monkeypatch):
    logs = Logs()
    result = setup(api, monkeypatch, logs)
    assert len(logs.calls) == 4
    spans = logs.calls[2]
    assert spans["logGroupNames"] == ["aws/spans"]
    assert f"filter attributes.session.id = '{RUN}'" in spans["queryString"]
    assert "attributes.`sec310.run_id`" not in spans["queryString"]
    assert "@message" not in spans["queryString"].split("| filter")[0]
    assert f"filter requestMetadata.sec310_run = '{RUN}'" in logs.calls[0]["queryString"]
    assert "body.policy.decision as decision" in logs.calls[1]["queryString"]
    assert "body.policy.determiningPolicies as policies" in logs.calls[1]["queryString"]
    assert all(c["startTime"] < c["endTime"] for c in logs.calls)
    assert all("| limit " in c["queryString"] and RUN in c["queryString"] for c in logs.calls)
    gateway = result["sources"][1]
    assert gateway["status"] == "done"
    assert gateway["records"] == [
        {
            "@timestamp": "2026-10-29 12:00:00.000",
            "decision": "DENY",
            "policies": "tenant_fence",
            "latency": "31",
        }
    ]
    assert "ticket text" not in str(result) and "secret" not in str(result)
    assert result["sources"][2]["records"][0]["name"] == "strands.agent.invoke"


def test_owner_fence_before_any_logs_or_ssm(api, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("AWS service accessed before owner check")

    monkeypatch.setattr(api.app.boto3, "client", forbidden)
    monkeypatch.setattr(api.app, "agent_param", forbidden)
    for run, status in [("invalid-run", 400), (RUN, 404)]:
        with pytest.raises(api.app.HttpError) as caught:
            api.app.run_trace(ALICE, run)
        assert caught.value.status == status
    api.tables["events"].put_item(
        Item={"run_id": RUN, "sk": api.app.OWNER_SK, "customer_id": "customer-a"}
    )
    for who, status in [
        ({**ALICE, "customer_id": "customer-b"}, 404),
        ({**ALICE, "role": "customer"}, 403),
    ]:
        with pytest.raises(api.app.HttpError) as caught:
            api.app.run_trace(who, RUN)
        assert caught.value.status == status


@pytest.mark.parametrize(
    "failure,status,error",
    [
        ("describe", "error", "DescribeLogGroups: RuntimeError"),
        ("start", "error", "StartQuery: RuntimeError"),
        ("results", "error", "GetQueryResults: RuntimeError"),
        (None, "error", "Logs Insights: Failed"),
    ],
)
def test_query_failures_not_empty_success(api, monkeypatch, failure, status, error):
    logs = Logs(status="Failed" if failure is None else "Complete", failure=failure)
    result = setup(api, monkeypatch, logs)
    assert all(
        s["status"] == status and s["error"] == error and not s["records"]
        for s in result["sources"]
    )
    assert "secret failure details" not in str(result)


@pytest.mark.parametrize("state", ["Failed", "Cancelled", "Timeout"])
def test_terminal_query_state_is_an_error(api, monkeypatch, state):
    result = setup(api, monkeypatch, Logs(status=state))
    assert all(
        s["status"] == "error" and s["error"] == f"Logs Insights: {state}"
        for s in result["sources"]
    )


def test_unfinished_query_is_reported_as_running(api, monkeypatch):
    logs = Logs(status="Running")
    clock = iter([100.0, 101.0, 121.0])
    monkeypatch.setattr(api.app.time, "time", lambda: next(clock, 121.0))
    monkeypatch.setattr(api.app.time, "sleep", lambda _: None)
    result = setup(api, monkeypatch, logs)
    assert all(s["status"] == "running" and not s["records"] for s in result["sources"])


def test_missing_log_group_is_not_success(api, monkeypatch):
    logs = Logs()
    logs.describe_log_groups = lambda **kwargs: {"logGroups": []}
    result = setup(api, monkeypatch, logs)
    assert not logs.calls
    assert all(s["status"] == "no log group yet" for s in result["sources"])


def test_v5_code_reads_v4_enforce_gateway_policy_not_missing_v5_engine(api, monkeypatch):
    class PolicyClient:
        def list_policies(self, policyEngineId):
            assert policyEngineId == "engine-v4"
            return {"policies": [{"policyId": "fence"}]}

        def get_policy(self, policyEngineId, policyId):
            assert policyEngineId == "engine-v4" and policyId == "fence"
            return {
                "name": "tenant fence",
                "status": "ACTIVE",
                "definition": {"cedar": {"statement": "permit(...)"}},
            }

    params = {
        "policy_engines": {"v1": "engine-v1", "v3": "engine-v3", "v4": "engine-v4"},
        "gateways": {"v4": "gateway-v4"},
    }
    monkeypatch.setattr(api.app, "agent_param", lambda key, default: json.dumps(params[key]))
    monkeypatch.setattr(
        api.app.boto3,
        "client",
        lambda name: PolicyClient() if name == "bedrock-agentcore-control" else None,
    )
    code = api.app.build_code("v5")
    assert code["gateway"] == "gateway-v4" and code["policy_engine"] == "engine-v4"
    assert code["policies"] == [
        {"name": "tenant fence", "status": "ACTIVE", "statement": "permit(...)"}
    ]
    assert all(control["on"] for control in code["controls"])
