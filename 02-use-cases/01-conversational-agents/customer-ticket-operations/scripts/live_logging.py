"""Turn on (or off) the platform's own records of what the live stage did.

    uv run python scripts/live_logging.py up      # prints the exports for `demo observe`
    uv run python scripts/live_logging.py down    # removes everything it created

Creates, in the current AWS profile/region, all named ``sec310_demo*``:

- **Model invocation logging** (account-level, one configuration per Region): every Converse
  call, with its full input and output, delivered to the CloudWatch log group
  ``/aws/bedrock/sec310_demo_invocations`` through an IAM role Bedrock assumes. If the account
  already logs invocations somewhere else, that configuration is left exactly as it is and
  reported; the stage then reads from there.
- **Gateway vended logs** for the ``sec310-demo-gateway`` created by ``live_gateway.py``: every
  MCP request and response, including the policy engine's denials, delivered to
  ``/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/<gateway id>``.

Guardrails and the policy engine publish their metrics without any setup; ``demo observe`` reads
those directly. Every create is confirmed; every delete is confirmed; anything left behind is
listed with a non-zero exit. Nothing outside the ``sec310_demo`` names is touched, and an
invocation logging configuration that is not ours is never deleted.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

import boto3
from botocore.exceptions import ClientError

PREFIX = "sec310_demo"
GATEWAY_NAME = "sec310-demo-gateway"
INVOCATION_LOG_GROUP = f"/aws/bedrock/{PREFIX}_invocations"
INVOCATION_ROLE = f"{PREFIX}_invocation_logging"
GATEWAY_LOG_PREFIX = "/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/"
DELIVERY_NAME = f"{PREFIX}_gateway_logs"
RETENTION_DAYS = 3


def say(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def masked(account: str) -> str:
    return "****" + account[-4:]


class Logging:
    def __init__(self) -> None:
        profile = os.environ.get("AWS_PROFILE")
        if not profile:
            raise RuntimeError("set AWS_PROFILE to a named development-account profile")
        self.session = boto3.session.Session(profile_name=profile)
        self.region = self.session.region_name
        if not self.region:
            raise RuntimeError("set AWS_REGION or configure a region on the named profile")
        self.account = self.session.client("sts").get_caller_identity()["Account"]
        self.iam = self.session.client("iam")
        self.logs = self.session.client("logs")
        self.bedrock = self.session.client("bedrock")
        self.ctl = self.session.client("bedrock-agentcore-control")
        self.problems: list[str] = []

    def each(self, client, operation: str, key: str, **kwargs):
        """Every page of a list call."""
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(key, [])

    def log_group_arn(self, name: str) -> str:
        return f"arn:aws:logs:{self.region}:{self.account}:log-group:{name}"

    # -- up ----------------------------------------------------------------------------------
    def up(self) -> int:
        say(f"account: {masked(self.account)}  region: {self.region}")
        invocation_group = self.invocation_logging()
        gateway_group = self.gateway_logging()
        say("")
        say("paste these, then (after `demo live`): uv run python -m sec310_sample.demo observe")
        if invocation_group:
            print(f"export SEC310_INVOCATION_LOG_GROUP={invocation_group}")
        if gateway_group:
            print(f"export SEC310_GATEWAY_LOG_GROUP={gateway_group}")
        print("export SEC310_OBSERVE_GUARDRAILS=1")
        print(f"export SEC310_RUN_ID=sec310_{uuid.uuid4().hex}")
        say(
            "WARNING: invocation logging records ALL text-model inputs/outputs in this account/Region."
        )
        say(
            "Use synthetic demo inputs only. Log retention is 3 days; logs must not go in the public zip."
        )
        return 0

    def invocation_logging(self) -> str | None:
        """Account-level: ours only if nobody else's. Returns the log group `observe` should read."""
        current = self.bedrock.get_model_invocation_logging_configuration().get("loggingConfig")
        if current:
            group = current.get("cloudWatchConfig", {}).get("logGroupName")
            if self.owns_invocation_config(current):
                say(f"model invocation logging already set up ({group})")
                return group
            where = group or current.get("s3Config", {}).get("bucketName", "an S3 bucket")
            say(
                f"model invocation logging already goes to {where}; leaving the account's configuration alone"
            )
            # Do not automatically read somebody else's invocation logs on the presentation screen.
            return None
        self.ensure_log_group(INVOCATION_LOG_GROUP)
        role_arn = self.role(
            INVOCATION_ROLE,
            trust={
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{self.region}:{self.account}:*"},
                },
            },
            inline={
                "write_invocation_logs": {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"{self.log_group_arn(INVOCATION_LOG_GROUP)}:log-stream:aws/bedrock/modelinvocations",
                }
            },
        )
        config = self.invocation_config(role_arn)
        # A freshly created role is not assumable for a few seconds; Bedrock checks at put time.
        deadline = time.monotonic() + 90
        while True:
            try:
                self.bedrock.put_model_invocation_logging_configuration(loggingConfig=config)
                break
            except ClientError as exc:
                if (
                    exc.response["Error"]["Code"] != "ValidationException"
                    or "assum" not in exc.response["Error"].get("Message", "").lower()
                    or time.monotonic() > deadline
                ):
                    raise
                time.sleep(5)
        after = self.bedrock.get_model_invocation_logging_configuration().get("loggingConfig", {})
        if after != config:
            raise RuntimeError(f"invocation logging configuration did not take: {after}")
        say(f"model invocation logging on: every Converse call now lands in {INVOCATION_LOG_GROUP}")
        return INVOCATION_LOG_GROUP

    def invocation_config(self, role_arn: str | None = None) -> dict:
        return {
            "cloudWatchConfig": {
                "logGroupName": INVOCATION_LOG_GROUP,
                "roleArn": role_arn or f"arn:aws:iam::{self.account}:role/{INVOCATION_ROLE}",
            },
            "textDataDeliveryEnabled": True,
            "imageDataDeliveryEnabled": False,
            "embeddingDataDeliveryEnabled": False,
            "videoDataDeliveryEnabled": False,
        }

    def owns_invocation_config(self, config: dict) -> bool:
        # Group name alone is NOT ownership: preserve an S3 destination, a different role,
        # or any other configuration someone has added since setup.
        return config == self.invocation_config()

    def optional(self, fetch):
        try:
            return fetch()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "NoSuchEntity"):
                return None
            raise

    def gateway_logging(self) -> str | None:
        gateway = next(
            (g for g in self.each(self.ctl, "list_gateways", "items") if g["name"] == GATEWAY_NAME),
            None,
        )
        if gateway is None:
            say(f"no gateway named {GATEWAY_NAME}: run live_gateway.py up first for gateway logs")
            return None
        gateway_id = gateway["gatewayId"]
        gateway_arn = self.ctl.get_gateway(gatewayIdentifier=gateway_id)["gatewayArn"]
        group = GATEWAY_LOG_PREFIX + gateway_id
        old_source = self.optional(lambda: self.logs.get_delivery_source(name=DELIVERY_NAME))
        if old_source and old_source["deliverySource"].get("resourceArns") != [gateway_arn]:
            raise RuntimeError(
                "named log source points to another gateway; inspect it before changing anything"
            )
        old_destination = self.optional(
            lambda: self.logs.get_delivery_destination(name=DELIVERY_NAME)
        )
        if old_destination and old_destination["deliveryDestination"].get(
            "deliveryDestinationConfiguration", {}
        ).get("destinationResourceArn") != self.log_group_arn(group):
            raise RuntimeError(
                "named log destination points elsewhere; inspect it before changing anything"
            )
        self.ensure_log_group(group)
        source = self.logs.put_delivery_source(
            name=DELIVERY_NAME, logType="APPLICATION_LOGS", resourceArn=gateway_arn
        )
        destination = self.logs.put_delivery_destination(
            name=DELIVERY_NAME,
            deliveryDestinationType="CWL",
            deliveryDestinationConfiguration={"destinationResourceArn": self.log_group_arn(group)},
        )
        existing = [
            d
            for d in self.each(self.logs, "describe_deliveries", "deliveries")
            if d["deliverySourceName"] == DELIVERY_NAME
        ]
        if existing:
            if any(
                d["deliveryDestinationArn"] != destination["deliveryDestination"]["arn"]
                for d in existing
            ):
                raise RuntimeError(
                    "named source has another delivery destination; refusing to repoint it"
                )
            say(f"gateway log delivery already set up ({existing[0]['id']}) -> {group}")
        else:
            delivery = self.logs.create_delivery(
                deliverySourceName=source["deliverySource"]["name"],
                deliveryDestinationArn=destination["deliveryDestination"]["arn"],
            )["delivery"]
            verified = self.logs.get_delivery(id=delivery["id"])["delivery"]
            if (
                verified["deliverySourceName"] != DELIVERY_NAME
                or verified["deliveryDestinationArn"] != destination["deliveryDestination"]["arn"]
            ):
                raise RuntimeError("gateway log delivery verification failed")
            say(
                f"gateway log delivery {delivery['id']}: every MCP request and response now lands in {group}"
            )
        return group

    def ensure_log_group(self, name: str) -> None:
        try:
            self.logs.create_log_group(logGroupName=name)
            say(f"created log group {name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                raise
            say(f"log group {name} exists")
        self.logs.put_retention_policy(logGroupName=name, retentionInDays=RETENTION_DAYS)

    def role(self, name: str, trust: dict, inline: dict[str, dict]) -> str:
        try:
            arn = self.iam.get_role(RoleName=name)["Role"]["Arn"]
            say(f"role {name} exists")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            arn = self.iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(
                    {"Version": "2012-10-17", "Statement": [trust]}
                ),
                Description="SEC310 live stage; lets Bedrock write model invocation logs; throwaway",
            )["Role"]["Arn"]
            say(f"created role {name}")
        for policy_name, statement in inline.items():
            self.iam.put_role_policy(
                RoleName=name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
            )
        return arn

    # -- down --------------------------------------------------------------------------------
    def down(self) -> int:
        say(f"account: {masked(self.account)}  region: {self.region}")
        self.remove_gateway_logging()
        self.remove_invocation_logging()
        if self.problems:
            say("cleanup incomplete:")
            for p in self.problems:
                say(f"  NOT deleted: {p}")
            return 1
        say("done")
        return 0

    def remove_gateway_logging(self) -> None:
        source = self.optional(lambda: self.logs.get_delivery_source(name=DELIVERY_NAME))
        destination = self.optional(lambda: self.logs.get_delivery_destination(name=DELIVERY_NAME))
        group = None
        if destination:
            resource = (
                destination["deliveryDestination"]
                .get("deliveryDestinationConfiguration", {})
                .get("destinationResourceArn", "")
            )
            expected = self.log_group_arn(GATEWAY_LOG_PREFIX + "sec310-demo-gateway-")
            if not resource.startswith(expected):
                raise RuntimeError(
                    "named destination is not a demo gateway log group; leaving it alone"
                )
            group = resource.split(":log-group:", 1)[1]
        if source:
            resources = source["deliverySource"].get("resourceArns", [])
            prefix = f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:gateway/sec310-demo-gateway-"
            if len(resources) != 1 or not resources[0].startswith(prefix):
                raise RuntimeError("named source is not a demo gateway; leaving it alone")
        clean = True
        for d in self.each(self.logs, "describe_deliveries", "deliveries"):
            if d["deliverySourceName"] == DELIVERY_NAME:
                clean = (
                    self.attempt(
                        f"delivery {d['id']}",
                        lambda d=d: self.logs.delete_delivery(id=d["id"]),
                        lambda d=d: self.optional(lambda: self.logs.get_delivery(id=d["id"])),
                    )
                    and clean
                )
        if not clean:
            return  # never tear out a destination while a delivery still references it
        for kind in ("destination", "source"):
            delete = getattr(self.logs, f"delete_delivery_{kind}")
            get = getattr(self.logs, f"get_delivery_{kind}")
            clean = (
                self.attempt(
                    f"delivery {kind} {DELIVERY_NAME}",
                    lambda delete=delete: delete(name=DELIVERY_NAME),
                    lambda get=get: self.optional(lambda: get(name=DELIVERY_NAME)),
                )
                and clean
            )
        if clean:
            # Also recover a log group left by a prior interrupted teardown after the
            # destination was already deleted. Only our demo gateway-name prefix is eligible.
            names = {
                g["logGroupName"]
                for g in self.each(
                    self.logs,
                    "describe_log_groups",
                    "logGroups",
                    logGroupNamePrefix=GATEWAY_LOG_PREFIX + "sec310-demo-gateway-",
                )
            }
            if group:
                names.add(group)
            for name in sorted(names):
                self.remove_log_group(name)

    def remove_invocation_logging(self) -> None:
        current = self.bedrock.get_model_invocation_logging_configuration().get("loggingConfig", {})
        if current and not self.owns_invocation_config(current):
            say(
                "model invocation configuration is not exactly ours: preserving configuration and dependencies"
            )
            return
        if current:
            if not self.attempt(
                "model invocation logging configuration",
                self.bedrock.delete_model_invocation_logging_configuration,
                lambda: self.bedrock.get_model_invocation_logging_configuration().get(
                    "loggingConfig"
                ),
            ):
                return
        self.remove_log_group(INVOCATION_LOG_GROUP)
        self.remove_role(INVOCATION_ROLE)

    def remove_log_group(self, name: str) -> None:
        self.attempt(
            f"log group {name}",
            lambda: self.logs.delete_log_group(logGroupName=name),
            lambda: next(
                (
                    g
                    for g in self.each(
                        self.logs, "describe_log_groups", "logGroups", logGroupNamePrefix=name
                    )
                    if g["logGroupName"] == name
                ),
                None,
            ),
        )

    def remove_role(self, name: str) -> None:
        try:
            for policy_name in self.each(
                self.iam, "list_role_policies", "PolicyNames", RoleName=name
            ):
                self.iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
            self.attempt(
                f"role {name}",
                lambda: self.iam.delete_role(RoleName=name),
                lambda: self.optional(lambda: self.iam.get_role(RoleName=name)),
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                self.problems.append(f"role {name}: {exc.response['Error']['Code']}")

    def attempt(self, what: str, delete, fetch) -> bool:
        """Delete, then verify absence. Failed deletion or verification preserves dependants."""
        try:
            try:
                delete()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ResourceNotFoundException",
                    "NoSuchEntity",
                ):
                    raise
            if fetch():
                self.problems.append(f"{what}: still present after deletion")
                return False
            say(f"deleted {what}")
            return True
        except ClientError as exc:
            self.problems.append(f"{what}: {exc.response['Error']['Code']}")
            return False


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("up", "down"):
        say(__doc__)
        return 2
    logging = Logging()
    return logging.up() if argv[1] == "up" else logging.down()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
