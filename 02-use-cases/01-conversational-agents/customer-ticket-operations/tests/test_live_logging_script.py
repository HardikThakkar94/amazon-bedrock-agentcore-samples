"""Logging setup cannot overwrite account settings or report incomplete cleanup as done."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.exceptions import ClientError  # noqa: E402
from botocore.stub import Stubber  # noqa: E402


@pytest.fixture
def script():
    path = Path(__file__).resolve().parents[1] / "scripts" / "live_logging.py"
    spec = importlib.util.spec_from_file_location("live_logging", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def logging(script):
    obj = object.__new__(script.Logging)
    obj.region = "us-east-1"
    obj.account = "test-account-1234"
    obj.problems = []
    obj.bedrock = boto3.client("bedrock", region_name=obj.region)
    return obj


def error(code, message="test"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Test")


def test_named_profile_required_before_any_aws_client(script, monkeypatch):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with pytest.raises(RuntimeError, match="named"):
        script.Logging()


def test_existing_account_config_is_preserved_and_not_auto_displayed(script):
    obj = logging(script)
    config = {
        "cloudWatchConfig": {
            "logGroupName": "production-log-group",
            "roleArn": "test-role-production",
        },
        "textDataDeliveryEnabled": True,
    }
    with Stubber(obj.bedrock) as stub:
        stub.add_response("get_model_invocation_logging_configuration", {"loggingConfig": config})
        assert obj.invocation_logging() is None
        stub.assert_no_pending_responses()  # any put/delete would be unstubbed and fail


def test_config_with_our_group_but_another_destination_is_not_ours(script):
    obj = logging(script)
    config = obj.invocation_config()
    config["s3Config"] = {"bucketName": "other-owner-bucket", "keyPrefix": "retained"}
    assert not obj.owns_invocation_config(config)
    with Stubber(obj.bedrock) as stub:
        stub.add_response("get_model_invocation_logging_configuration", {"loggingConfig": config})
        obj.remove_invocation_logging()  # no dependencies set: attempting to delete them would fail
        stub.assert_no_pending_responses()


def test_up_confirms_every_setting_not_just_log_group(script, monkeypatch):
    obj = logging(script)
    role_arn = obj.invocation_config()["cloudWatchConfig"]["roleArn"]
    monkeypatch.setattr(obj, "ensure_log_group", lambda _: None)
    monkeypatch.setattr(obj, "role", lambda *args, **kwargs: role_arn)
    wrong = obj.invocation_config()
    wrong["textDataDeliveryEnabled"] = False
    with Stubber(obj.bedrock) as stub:
        stub.add_response("get_model_invocation_logging_configuration", {})
        stub.add_response(
            "put_model_invocation_logging_configuration",
            {},
            expected_params={"loggingConfig": obj.invocation_config()},
        )
        stub.add_response("get_model_invocation_logging_configuration", {"loggingConfig": wrong})
        with pytest.raises(RuntimeError, match="did not take"):
            obj.invocation_logging()


def test_setup_does_not_retry_unrelated_validation_errors(script, monkeypatch):
    obj = logging(script)
    monkeypatch.setattr(obj, "ensure_log_group", lambda _: None)
    monkeypatch.setattr(
        obj, "role", lambda *args, **kwargs: obj.invocation_config()["cloudWatchConfig"]["roleArn"]
    )
    with Stubber(obj.bedrock) as stub:
        stub.add_response("get_model_invocation_logging_configuration", {})
        stub.add_client_error(
            "put_model_invocation_logging_configuration",
            service_error_code="ValidationException",
            service_message="invalid log group",
        )
        with pytest.raises(ClientError, match="invalid log group"):
            obj.invocation_logging()
        stub.assert_no_pending_responses()


def test_iam_propagation_retry_is_bounded_and_confirmed(script, monkeypatch):
    obj = logging(script)
    monkeypatch.setattr(obj, "ensure_log_group", lambda _: None)
    monkeypatch.setattr(
        obj, "role", lambda *args, **kwargs: obj.invocation_config()["cloudWatchConfig"]["roleArn"]
    )
    sleeps = []
    monkeypatch.setattr(script.time, "sleep", sleeps.append)
    with Stubber(obj.bedrock) as stub:
        stub.add_response("get_model_invocation_logging_configuration", {})
        stub.add_client_error(
            "put_model_invocation_logging_configuration",
            service_error_code="ValidationException",
            service_message="cannot assume the role yet",
        )
        stub.add_response("put_model_invocation_logging_configuration", {})
        stub.add_response(
            "get_model_invocation_logging_configuration", {"loggingConfig": obj.invocation_config()}
        )
        assert obj.invocation_logging() == script.INVOCATION_LOG_GROUP
        assert sleeps == [5]
        stub.assert_no_pending_responses()


def test_down_preserves_dependencies_if_the_config_is_still_present(script, monkeypatch):
    obj = logging(script)
    with Stubber(obj.bedrock) as stub:
        stub.add_response(
            "get_model_invocation_logging_configuration", {"loggingConfig": obj.invocation_config()}
        )
        stub.add_response("delete_model_invocation_logging_configuration", {})
        stub.add_response(
            "get_model_invocation_logging_configuration", {"loggingConfig": obj.invocation_config()}
        )
        obj.remove_invocation_logging()
    assert obj.problems == ["model invocation logging configuration: still present after deletion"]


def test_down_removes_dependencies_only_after_config_absence(script, monkeypatch):
    obj = logging(script)
    calls = []
    monkeypatch.setattr(obj, "remove_log_group", lambda name: calls.append(("group", name)))
    monkeypatch.setattr(obj, "remove_role", lambda name: calls.append(("role", name)))
    with Stubber(obj.bedrock) as stub:
        stub.add_response(
            "get_model_invocation_logging_configuration", {"loggingConfig": obj.invocation_config()}
        )
        stub.add_response("delete_model_invocation_logging_configuration", {})
        stub.add_response("get_model_invocation_logging_configuration", {})
        obj.remove_invocation_logging()
    assert calls == [("group", script.INVOCATION_LOG_GROUP), ("role", script.INVOCATION_ROLE)]


def test_delete_denied_or_unconfirmed_is_not_success(script):
    obj = logging(script)

    def denied():
        raise error("AccessDeniedException")

    assert obj.attempt("thing", denied, lambda: None) is False
    assert obj.attempt("other", lambda: None, lambda: {"still": "present"}) is False
    assert len(obj.problems) == 2


def test_down_returns_failure_when_any_resource_remains(script, monkeypatch, capsys):
    obj = logging(script)
    monkeypatch.setattr(
        obj, "remove_gateway_logging", lambda: obj.problems.append("gateway delivery remains")
    )
    monkeypatch.setattr(obj, "remove_invocation_logging", lambda: None)
    assert obj.down() == 1
    assert "cleanup incomplete" in capsys.readouterr().err


def test_foreign_named_gateway_delivery_is_not_repointed(script, monkeypatch):
    obj = logging(script)
    gateway = {"name": script.GATEWAY_NAME, "gatewayId": "sec310-demo-gateway-demo"}
    obj.ctl = SimpleNamespace(get_gateway=lambda **kw: {"gatewayArn": "test-gateway"})
    obj.logs = SimpleNamespace(
        get_delivery_source=lambda **kw: {"deliverySource": {"resourceArns": ["other-gateway"]}}
    )
    monkeypatch.setattr(obj, "each", lambda *a, **kw: iter([gateway]))
    with pytest.raises(RuntimeError, match="another gateway"):
        obj.gateway_logging()


def test_gateway_delivery_must_be_confirmed_on_create(script, monkeypatch):
    obj = logging(script)
    gateway = {"name": script.GATEWAY_NAME, "gatewayId": "sec310-demo-gateway-demo"}
    obj.ctl = SimpleNamespace(get_gateway=lambda **kw: {"gatewayArn": "test-gateway"})

    class Logs:
        def get_delivery_source(self, **kw):
            raise error("ResourceNotFoundException")

        get_delivery_destination = get_delivery_source

        def put_delivery_source(self, **kw):
            return {"deliverySource": {"name": kw["name"]}}

        def put_delivery_destination(self, **kw):
            return {"deliveryDestination": {"arn": "our-destination"}}

        def create_delivery(self, **kw):
            return {"delivery": {"id": "d1"}}

        def get_delivery(self, **kw):
            return {
                "delivery": {
                    "deliverySourceName": script.DELIVERY_NAME,
                    "deliveryDestinationArn": "wrong-destination",
                }
            }

    obj.logs = Logs()
    monkeypatch.setattr(obj, "ensure_log_group", lambda _: None)
    monkeypatch.setattr(
        obj, "each", lambda client, *a, **kw: iter([gateway] if client is obj.ctl else [])
    )
    with pytest.raises(RuntimeError, match="verification failed"):
        obj.gateway_logging()


def test_teardown_failure_keeps_gateway_destination_and_group(script, monkeypatch):
    obj = logging(script)

    class Logs:
        def get_delivery_source(self, **kw):
            return {
                "deliverySource": {
                    "resourceArns": [
                        f"arn:aws:bedrock-agentcore:{obj.region}:{obj.account}:gateway/sec310-demo-gateway-demo"
                    ]
                }
            }

        def get_delivery_destination(self, **kw):
            return {
                "deliveryDestination": {
                    "deliveryDestinationConfiguration": {
                        "destinationResourceArn": obj.log_group_arn(
                            script.GATEWAY_LOG_PREFIX + "sec310-demo-gateway-demo"
                        )
                    }
                }
            }

        def delete_delivery(self, **kw):
            raise error("AccessDeniedException")

    obj.logs = Logs()
    monkeypatch.setattr(
        obj,
        "each",
        lambda *a, **kw: iter([{"id": "d1", "deliverySourceName": script.DELIVERY_NAME}]),
    )
    obj.remove_gateway_logging()  # no delete_* methods for dependants exist on Logs
    assert obj.problems == ["delivery d1: AccessDeniedException"]
