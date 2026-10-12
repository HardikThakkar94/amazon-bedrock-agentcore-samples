"""Focused review regressions: honest state reporting, safe logs, hermetic rehearsal tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

from sec310_sample.demo.__main__ import stage_observe  # noqa: E402
from sec310_sample.live import (  # noqa: E402
    GatewayLogReader,
    InvocationLogReader,
    LogReadError,
    MetricReader,
    MetricReadError,
)
from sec310_sample.model import BedrockModel  # noqa: E402
from tests.test_observability import event, gw_line, invocation, logs_client  # noqa: E402


def test_no_run_id_is_injected_when_it_is_not_configured():
    # The autouse conftest fixture removes ambient rehearsal exports for every unit test.
    assert "requestMetadata" not in BedrockModel("m", client=object())._request("hi")


def test_missing_metric_status_is_a_failure_not_a_count():
    class Client:
        def get_metric_data(self, **kwargs):
            return {"MetricDataResults": [{"Id": "allow", "Values": [1]}]}

    with pytest.raises(MetricReadError, match="incomplete"):
        MetricReader(Client()).read([{"Id": "allow"}], 0, 1)


def test_tool_input_wins_over_text_preamble_and_caller_session_is_not_displayed():
    rec = invocation()
    rec["output"]["outputBodyJson"]["output"]["message"]["content"] = [
        {"text": "Here is my answer:"},
        {
            "toolUse": {
                "input": {
                    "answer": "done",
                    "links": ["https://exfil.example.net/"],
                    "proposed_actions": [{"operation": "delete_rule"}],
                }
            }
        },
    ]
    client = logs_client()
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [event(rec)]})
        records = InvocationLogReader(client).records("demo", now=1_800_000_000)
    assert len(records[0].carries) == 2
    assert records[0].caller == "Admin" and "private-session" not in records[0].caller


def test_account_wide_invocation_display_requires_a_run_id(monkeypatch, capsys):
    monkeypatch.setenv("SEC310_INVOCATION_LOG_GROUP", "demo")

    def no_client(service):
        raise AssertionError("must reject before querying the account's records")

    assert stage_observe(no_client) == 2
    assert "unfiltered account-wide display is disabled" in capsys.readouterr().out


def test_non_object_gateway_record_is_reported_as_log_read_error():
    client = logs_client()
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [event(["invalid"])]})
        with pytest.raises(LogReadError, match="not an object"):
            GatewayLogReader(client).requests("gateway", now=1_800_000_000)


def test_an_older_unclassified_gateway_error_cannot_hide_outside_the_display_limit(monkeypatch):
    monkeypatch.setenv("SEC310_GATEWAY_LOG_GROUP", "gateway")

    class Client:
        def filter_log_events(self, **kwargs):
            records = [
                gw_line(
                    "bad",
                    {
                        "requestBody": "{method=tools/call}",
                        "log": "Tool Execution Denied: backend unavailable",
                    },
                )
            ]
            records += [
                gw_line(
                    str(i),
                    {"requestBody": "{method=tools/call}", "policy": {"decision": "ALLOW"}},
                    i + 1,
                )
                for i in range(13)
            ]
            return {"events": [event(r, str(i)) for i, r in enumerate(records)]}

    with pytest.raises(LogReadError, match="unclassified service error"):
        stage_observe(lambda service: Client())


@pytest.fixture
def logging_obj():
    path = Path(__file__).resolve().parents[1] / "scripts" / "live_logging.py"
    spec = importlib.util.spec_from_file_location("review_logging", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    obj = object.__new__(mod.Logging)
    obj.account = "test-account-1234"
    obj.region = "us-east-1"
    obj.problems = []
    return obj, mod


def test_logging_warning_precedes_setup_and_successful_exports_survive_gateway_failure(
    logging_obj, monkeypatch, capsys
):
    obj, mod = logging_obj

    def invocation_setup():
        assert "ALL text-model inputs/outputs" in capsys.readouterr().err
        return mod.INVOCATION_LOG_GROUP

    def gateway_failure():
        raise RuntimeError("foreign gateway-source collision")

    monkeypatch.setattr(obj, "invocation_logging", invocation_setup)
    monkeypatch.setattr(obj, "gateway_logging", gateway_failure)
    assert obj.up() == 1
    captured = capsys.readouterr()
    assert "SEC310_INVOCATION_LOG_GROUP=" in captured.out
    assert "SEC310_RUN_ID=" in captured.out
    assert "setup incomplete" in captured.err


def test_teardown_foreign_gateway_problem_does_not_prevent_independent_cleanup(
    logging_obj, monkeypatch, capsys
):
    obj, _ = logging_obj
    calls = []

    def foreign_gateway():
        raise RuntimeError("named destination is not a demo gateway log group; leaving it alone")

    monkeypatch.setattr(obj, "remove_gateway_logging", foreign_gateway)
    monkeypatch.setattr(obj, "remove_invocation_logging", lambda: calls.append("invocation"))
    assert obj.down() == 1
    assert calls == ["invocation"]
    assert "cleanup incomplete" in capsys.readouterr().err
