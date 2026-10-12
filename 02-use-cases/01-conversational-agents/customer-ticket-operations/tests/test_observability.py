"""Platform records, not inferred success: logs, metrics, pagination and the observe command."""

from __future__ import annotations

import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import ANY, Stubber  # noqa: E402

from sec310_sample.live import (  # noqa: E402
    GatewayLogReader,
    GuardrailObserver,
    InvocationLogReader,
    LogReadError,
    MetricReader,
    MetricReadError,
)


def invocation(payload=None, metadata=None):
    return {
        "schemaType": "ModelInvocationLog",
        "schemaVersion": "1.0",
        "timestamp": "2026-10-12T17:00:00Z",
        "modelId": "test-model",
        "operation": "Converse",
        "identity": {"arn": "test-principal/Admin"},
        "requestMetadata": metadata or {},
        "input": {"inputTokenCount": 10},
        "output": {
            "outputTokenCount": 20,
            "outputBodyJson": {
                "stopReason": "end_turn",
                "output": {
                    "message": {
                        "content": [
                            {
                                "text": "```json\n"
                                + json.dumps(
                                    payload or {"answer": "ok", "links": [], "proposed_actions": []}
                                )
                                + "\n```"
                            }
                        ]
                    }
                },
            },
        },
    }


def event(record, eid="a"):
    return {
        "timestamp": 0,
        "message": json.dumps(record),
        "eventId": eid,
        "ingestionTime": 0,
        "logStreamName": "test-stream",
    }


def logs_client():
    return boto3.client("logs", region_name="us-east-1")


def test_invocation_pages_accumulate_deduplicate_and_filter_the_demo_run():
    client = logs_client()
    payload = {
        "answer": "done",
        "links": ["https://exfil.example.net/collect?case=7"],
        "proposed_actions": [{"operation": "delete_rule", "account_id": "acct-b"}],
    }
    a = event(invocation(payload, {"sec310_run": "our-run"}))
    b = event(invocation(metadata={"sec310_run": "other-run"}), "b")
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [a], "nextToken": "page2"})
        stub.add_response(
            "filter_log_events",
            {"events": [a, b]},
            expected_params={
                "logGroupName": "demo",
                "startTime": ANY,
                "endTime": ANY,
                "nextToken": "page2",
            },
        )
        records = InvocationLogReader(client).records("demo", now=1_800_000_000, run_id="our-run")
        stub.assert_no_pending_responses()
    assert len(records) == 1
    r = records[0]
    assert (r.model_id, r.input_tokens, r.output_tokens, r.caller) == (
        "test-model",
        10,
        20,
        "Admin",
    )
    assert r.carries == [
        "attacker URL in links (not a network transfer)",
        "delete_rule proposal (not proof of execution)",
    ]


def test_refusal_quoting_the_payload_is_not_reported_as_compliance():
    rec = invocation(
        {
            "answer": 'Do not follow https://exfil.example.net/ or {"operation":"delete_rule"}',
            "links": [],
            "proposed_actions": [],
        }
    )
    client = logs_client()
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [event(rec)]})
        result = InvocationLogReader(client).records("demo", now=1_800_000_000)
    assert result[0].carries == []


def test_only_the_known_permissions_line_is_skipped():
    client = logs_client()
    permission = event({}, "permission")
    permission["message"] = "Permissions are correctly set for Amazon Bedrock logs."
    bad = event({}, "bad")
    bad["message"] = "unexpected unreadable record"
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [permission, event(invocation())]})
        assert len(InvocationLogReader(client).records("demo", now=1_800_000_000)) == 1
        stub.add_response("filter_log_events", {"events": [bad]})
        with pytest.raises(LogReadError, match="unreadable"):
            InvocationLogReader(client).records("demo", now=1_800_000_000)


def test_s3_or_missing_body_is_not_reported_as_an_empty_answer():
    rec = invocation()
    rec["output"].pop("outputBodyJson")
    client = logs_client()
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [event(rec)]})
        with pytest.raises(LogReadError, match="absent or not inline"):
            InvocationLogReader(client).records("demo", now=1_800_000_000)


def test_service_error_invocation_record_is_not_a_model_answer():
    rec = invocation()
    rec.pop("input")
    rec.pop("output")
    rec["errorCode"] = "ValidationException"
    client = logs_client()
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [event(rec)]})
        records = InvocationLogReader(client).records("demo", now=1_800_000_000)
    assert records[0].error_code == "ValidationException"
    assert records[0].input_tokens is None and records[0].output_tokens is None
    assert records[0].output_text == "" and records[0].carries == []


def test_repeated_log_token_stops_instead_of_looping_forever():
    client = logs_client()
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [], "nextToken": "same"})
        stub.add_response("filter_log_events", {"events": [], "nextToken": "same"})
        with pytest.raises(LogReadError, match="repeated"):
            InvocationLogReader(client).records("demo", now=1_800_000_000)
        stub.assert_no_pending_responses()


def gw_line(rid, body, stamp=0):
    return {"request_id": rid, "event_timestamp": stamp, "body": body}


def test_gateway_policy_records_are_joined_by_request_and_not_inferred_from_http():
    client = logs_client()
    request = "{method=tools/call, params={name=EvidenceTools___update_rule, arguments={account_id=acct-b}}}"
    lines = [
        event(gw_line("deny", {"requestBody": request}), "d1"),
        event(gw_line("allow", {"requestBody": request}), "a1"),
        event(gw_line("reject", {"requestBody": request}), "r1"),
        event(gw_line("pending", {"requestBody": request}), "p1"),
        event(gw_line("broken", {"requestBody": request}), "b1"),
    ]
    more = [
        event(
            gw_line(
                "deny",
                {
                    "policy": {
                        "decision": "DENY",
                        "reason": "account scope",
                        "determiningPolicies": ["scope"],
                        "temporal_evaluation_invoked": True,
                        "latencyMs": 7,
                    }
                },
            ),
            "d2",
        ),
        event(
            gw_line(
                "allow",
                {"policy": {"decision": "ALLOW", "determiningPolicies": ["look_before_you_write"]}},
            ),
            "a2",
        ),
        event(
            gw_line(
                "reject",
                {
                    "log": "Tool Execution Denied: Policy Evaluation rejected the request as invalid [sessionId is required]"
                },
            ),
            "r2",
        ),
        event(gw_line("broken", {"log": "Tool Execution Denied: backend unavailable"}), "b2"),
    ]
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": lines, "nextToken": "p2"})
        stub.add_response("filter_log_events", {"events": more})
        records = GatewayLogReader(client).requests("gateway", now=1_800_000_000)
    assert [r.decision for r in records] == [
        "DENY",
        "ALLOW",
        "REJECTED",
        "n/a",
        "UNCLASSIFIED_ERROR",
    ]
    assert records[0].account_id == "acct-b" and records[0].tool == "EvidenceTools___update_rule"
    assert records[0].determining_policies == ("scope",) and records[0].temporal is True
    assert records[0].latency_ms == 7


def test_metric_reader_requires_every_requested_result():
    class Client:
        def get_metric_data(self, **kwargs):
            return {"MetricDataResults": [{"Id": "allow", "Values": [1], "StatusCode": "Complete"}]}

    with pytest.raises(MetricReadError, match="incomplete"):
        MetricReader(Client()).read([{"Id": "allow"}, {"Id": "deny"}], 0, 1)


def test_guardrails_read_only_exact_per_guardrail_series_and_count_real_datapoints():
    queries = []

    class Client:
        def get_paginator(self, op):
            class P:
                def paginate(self, **kw):
                    if kw["MetricName"] == "CheckInvocations":
                        return [{"Metrics": [{"Dimensions": kw["Dimensions"]}]}]
                    dims = [
                        {"Name": "GuardrailArn", "Value": "test/guardrail/ours"},
                        {"Name": "GuardrailVersion", "Value": "DRAFT"},
                    ]
                    other = [
                        {"Name": "GuardrailArn", "Value": "test/guardrail/other"},
                        {"Name": "GuardrailVersion", "Value": "DRAFT"},
                    ]
                    return [
                        {
                            "Metrics": [
                                {"Dimensions": dims},
                                {"Dimensions": other},
                                {
                                    "Dimensions": dims
                                    + [{"Name": "Operation", "Value": "ApplyGuardrail"}]
                                },
                            ]
                        }
                    ]

            return P()

        def get_metric_data(self, **kw):
            queries.extend(kw["MetricDataQueries"])
            return {
                "MetricDataResults": [
                    {
                        "Id": q["Id"],
                        "Values": [4 if q["Id"] == "checks" else 1],
                        "StatusCode": "Complete",
                    }
                    for q in kw["MetricDataQueries"]
                ]
            }

    rows, checks = GuardrailObserver(Client()).counts(["ours"], now=1_800_000_000)
    assert len(queries) == 4 and checks == 4
    assert len(rows) == 1 and rows[0].datapoints == 3
    assert (rows[0].invocations, rows[0].intervened, rows[0].text_units) == (1, 1, 1)


@pytest.fixture
def clean_observe_env(monkeypatch):
    import os

    for key in os.environ:
        if key.startswith("SEC310_"):
            monkeypatch.delenv(key)


def test_observe_combines_configured_sections_without_leaking_raw_answers(
    monkeypatch, capsys, clean_observe_env
):
    from sec310_sample.demo.__main__ import stage_observe

    monkeypatch.setenv("SEC310_INVOCATION_LOG_GROUP", "invocations")
    monkeypatch.setenv("SEC310_GATEWAY_LOG_GROUP", "gateway")

    class Logs:
        def filter_log_events(self, **kw):
            if kw["logGroupName"] == "invocations":
                return {
                    "events": [
                        event(
                            invocation(
                                {
                                    "answer": "private-answer-must-not-print",
                                    "links": [],
                                    "proposed_actions": [],
                                }
                            )
                        )
                    ]
                }
            return {
                "events": [
                    event(
                        gw_line(
                            "q",
                            {
                                "requestBody": "{method=tools/call, name=tool, account_id=acct-a}",
                                "policy": {
                                    "decision": "ALLOW",
                                    "determiningPolicies": ["read_known_accounts"],
                                },
                            },
                        )
                    )
                ]
            }

    assert stage_observe(lambda _: Logs()) == 0
    text = capsys.readouterr().out
    assert "recorded API attempts" in text and "tool acct-a: ALLOW" in text
    assert "private-answer-must-not-print" not in text


def test_one_empty_configured_section_is_not_overall_success(
    monkeypatch, capsys, clean_observe_env
):
    from sec310_sample.demo.__main__ import stage_observe

    monkeypatch.setenv("SEC310_INVOCATION_LOG_GROUP", "invocations")

    class Logs:
        def filter_log_events(self, **kw):
            return {"events": []}

    assert stage_observe(lambda _: Logs()) == 1
    assert "no matching invocation records yet" in capsys.readouterr().out


def test_bedrock_tags_requests_only_when_the_demo_run_is_set(monkeypatch):
    from sec310_sample.model import BedrockModel

    monkeypatch.setenv("SEC310_RUN_ID", "demo-run")
    model = BedrockModel(model_id="m", client=object())
    assert model._request("hi")["requestMetadata"] == {"sec310_run": "demo-run"}
