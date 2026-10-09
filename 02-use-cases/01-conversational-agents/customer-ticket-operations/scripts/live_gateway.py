"""Provision (or remove) the gateway that the live stage uses to show *enforcement*.

    uv run python scripts/live_gateway.py up      # prints the exports for `demo live`
    uv run python scripts/live_gateway.py down    # removes everything it created

Creates, in the current AWS profile/region, all named ``sec310_demo*``:

- a Lambda function with two canned tools (``scripts/live/tool_lambda.py``) and its role
- a gateway service role that may invoke that function
- a policy engine, then an AgentCore Gateway (MCP, AWS_IAM inbound auth) with the engine in
  ENFORCE mode and the Lambda as target ``EvidenceTools``
- two policies on the engine: a Cedar policy that permits ``update_rule`` only for one account,
  and a Dogwood temporal policy that permits it only after the same session read that account's
  evidence. ``read_evidence`` is permitted for everyone.

Every create waits for the terminal state and fails loudly; every delete is confirmed and
anything left behind is listed with a non-zero exit. Nothing outside the ``sec310_demo`` names
is touched.
"""

from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

HERE = Path(__file__).resolve().parent
PREFIX = "sec310_demo"
TARGET = "EvidenceTools"
LAMBDA_NAME = f"{PREFIX}_tools"
LAMBDA_ROLE = f"{PREFIX}_tool_role"
GATEWAY_ROLE = f"{PREFIX}_gateway_role"
ENGINE_NAME = f"{PREFIX}_gw"
GATEWAY_NAME = "sec310-demo-gateway"  # gateway names allow hyphens, not underscores (policy names: the reverse)

TOOLS = [
    {
        "name": "read_evidence",
        "description": "Read the findings and detection rules recorded for one account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "Account such as acct-a."}
            },
            "required": ["account_id"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "finding_count": {"type": "integer"},
                "findings": {"type": "string", "description": "JSON list of findings."},
                "rules": {"type": "string", "description": "JSON map of rules."},
            },
            "required": ["account_id", "finding_count", "findings", "rules"],
        },
    },
    {
        "name": "update_rule",
        "description": "Enable or disable one detection rule in one account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "Account such as acct-a."},
                "rule_id": {"type": "string", "description": "Rule such as rule-42."},
                "enabled": {"type": "boolean", "description": "Desired state."},
            },
            "required": ["account_id", "rule_id", "enabled"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "account_id": {"type": "string"},
                "rule_id": {"type": "string"},
                "enabled": {"type": "boolean"},
            },
            "required": ["status", "account_id", "rule_id", "enabled"],
        },
    },
]


def say(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def masked(account: str) -> str:
    return "****" + account[-4:]


def policies(gateway_arn: str) -> list[tuple[str, str, str]]:
    """(name, definition kind, statement). Actions are the gateway's tools; the resource is the gateway.

    Permits combine with OR and a forbid overrides every permit, so the shape matters: the account
    scope is a *forbid* (nothing can grant a write outside acct-a) and the temporal rule is the
    *only* permit for writes (a write needs a read of the same account earlier in the session).
    A first draft that expressed the scope as a second permit let every write through (observed
    2026-10-08): "permit if acct-a" OR "permit if read first" permits acct-b after a read.
    """
    read = f'action == AgentCore::Action::"{TARGET}___read_evidence"'
    write = f'action == AgentCore::Action::"{TARGET}___update_rule"'
    gw = f'resource == AgentCore::Gateway::"{gateway_arn}"'
    return [
        # An unconditional permit for a tool is flagged "Overly Permissive" by automated reasoning
        # (observed 2026-10-08), so even the read permit names the account space it covers.
        (
            "read_known_accounts",
            "cedar",
            f'permit(principal, {read}, {gw}) when {{ context.input.account_id like "acct-*" }};',
        ),
        (
            "look_before_you_write",
            "policy",  # Dogwood: a temporal statement goes under `policy`, not `cedar`
            f"permit(principal, {write}, {gw}) when temporal {{ "
            f'formerly within 1h AgentCore::Action::"{TARGET}___read_evidence"::response{{ '
            "eventResource: resource, input.account_id: context.input.account_id } };",
        ),
        # Validation is engine-wide: this forbid is "Overly Restrictive" (denies every write) unless
        # a write permit already exists on the engine, so it is created after the one above.
        (
            "no_writes_outside_acct_a",
            "cedar",
            f'forbid(principal, {write}, {gw}) unless {{ context.input.account_id == "acct-a" }};',
        ),
    ]


class Live:
    def __init__(self) -> None:
        self.session = boto3.session.Session()
        self.region = self.session.region_name
        self.account = self.session.client("sts").get_caller_identity()["Account"]
        self.iam = self.session.client("iam")
        self.lam = self.session.client("lambda")
        self.ctl = self.session.client("bedrock-agentcore-control")
        self.problems: list[str] = []

    # -- up ----------------------------------------------------------------------------------
    def up(self) -> int:
        say(f"account: {masked(self.account)}  region: {self.region}")
        lambda_role = self.role(
            LAMBDA_ROLE,
            {"Service": "lambda.amazonaws.com"},
            managed=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        )
        function_arn = self.function(lambda_role)
        # The gateway's execution role, per the "Gateway and Policy IAM permissions" page: it is
        # assumed while the policy engine is validated, so the trust is scoped to the account and
        # the service's resources rather than to the (not yet existing) gateway ARN.
        acct = f"arn:aws:bedrock-agentcore:{self.region}:{self.account}"
        gateway_role = self.role(
            GATEWAY_ROLE,
            {"Service": "bedrock-agentcore.amazonaws.com"},
            condition={
                "StringEquals": {"aws:SourceAccount": self.account},
                "ArnLike": {"aws:SourceArn": f"{acct}:*"},
            },
            inline={
                "invoke_tools": {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": function_arn,
                },
                "policy_engine": {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetPolicyEngine",
                        "bedrock-agentcore:AuthorizeAction",
                        "bedrock-agentcore:PartiallyAuthorizeActions",
                    ],
                    "Resource": [f"{acct}:policy-engine/*", f"{acct}:gateway/*"],
                },
                # temporal (Dogwood) policies make the gateway mint a workload access token per session
                "policy_session_identity": {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": [
                        f"{acct}:workload-identity-directory/default",
                        f"{acct}:workload-identity-directory/default/workload-identity/*",
                    ],
                },
            },
        )
        engine_id, engine_arn = self.engine()
        gateway = self.gateway(gateway_role, engine_arn)
        self.target(gateway["gatewayId"], function_arn)
        self.add_policies(engine_id, gateway["gatewayArn"])
        say("")
        say("paste these, then: uv run python -m sec310_sample.demo live")
        print(f"export SEC310_GATEWAY_URL={gateway['gatewayUrl']}")
        print(f"export SEC310_POLICY_ENGINE_ID={engine_id}")
        return 0

    def role(
        self,
        name: str,
        principal: dict,
        *,
        condition: dict | None = None,
        managed: list[str] = (),
        inline: dict | None = None,
    ) -> str:
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": principal,
                    "Action": "sts:AssumeRole",
                    **({"Condition": condition} if condition else {}),
                }
            ],
        }
        try:
            arn = self.iam.get_role(RoleName=name)["Role"]["Arn"]
            self.iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
            say(f"role {name} exists")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            arn = self.iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Description="SEC310 live stage; throwaway",
            )["Role"]["Arn"]
            say(f"created role {name}")
        for policy_arn in managed:
            self.iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        for pname, statement in (inline or {}).items():
            self.iam.put_role_policy(
                RoleName=name,
                PolicyName=pname,
                PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
            )
        return arn

    def function(self, role_arn: str) -> str:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("tool_lambda.py", (HERE / "live" / "tool_lambda.py").read_text())
        code = buf.getvalue()
        try:
            arn = self.lam.get_function(FunctionName=LAMBDA_NAME)["Configuration"]["FunctionArn"]
            self.lam.update_function_code(FunctionName=LAMBDA_NAME, ZipFile=code)
            say(f"function {LAMBDA_NAME} exists; code refreshed")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            for attempt in range(12):  # a new role takes a few seconds to become assumable
                try:
                    arn = self.lam.create_function(
                        FunctionName=LAMBDA_NAME,
                        Runtime="python3.12",
                        Role=role_arn,
                        Handler="tool_lambda.lambda_handler",
                        Code={"ZipFile": code},
                        Timeout=10,
                        Description="SEC310 live stage tool target; throwaway",
                    )["FunctionArn"]
                    break
                except ClientError as retry:
                    if (
                        retry.response["Error"]["Code"] != "InvalidParameterValueException"
                        or attempt == 11
                    ):
                        raise
                    time.sleep(5)
            say(f"created function {LAMBDA_NAME}")
        self.lam.get_waiter("function_active_v2").wait(FunctionName=LAMBDA_NAME)
        return arn

    def engine(self) -> tuple[str, str]:
        for e in self.each(self.ctl, "list_policy_engines", "policyEngines"):
            if e["name"] == ENGINE_NAME:
                say(f"policy engine {ENGINE_NAME} exists ({e['policyEngineId']})")
                return e["policyEngineId"], e["policyEngineArn"]
        e = self.ctl.create_policy_engine(
            name=ENGINE_NAME, description="SEC310 live stage; throwaway"
        )
        self.ctl.get_waiter("policy_engine_active").wait(policyEngineId=e["policyEngineId"])
        say(f"created policy engine {ENGINE_NAME} ({e['policyEngineId']})")
        return e["policyEngineId"], e["policyEngineArn"]

    def gateway(self, role_arn: str, engine_arn: str) -> dict:
        for g in self.each(self.ctl, "list_gateways", "items"):
            if g["name"] == GATEWAY_NAME:
                say(f"gateway {GATEWAY_NAME} exists ({g['gatewayId']})")
                return self.ctl.get_gateway(gatewayIdentifier=g["gatewayId"])
        g = self.ctl.create_gateway(
            name=GATEWAY_NAME,
            description="SEC310 live stage; throwaway",
            roleArn=role_arn,
            protocolType="MCP",
            authorizerType="AWS_IAM",
            policyEngineConfiguration={"arn": engine_arn, "mode": "ENFORCE"},
        )
        g = self.wait(
            lambda: self.ctl.get_gateway(gatewayIdentifier=g["gatewayId"]),
            "READY",
            f"gateway {GATEWAY_NAME}",
        )
        say(f"created gateway {GATEWAY_NAME} ({g['gatewayId']}), policy engine in ENFORCE mode")
        return g

    def target(self, gateway_id: str, function_arn: str) -> None:
        for t in self.each(self.ctl, "list_gateway_targets", "items", gatewayIdentifier=gateway_id):
            if t["name"] == TARGET:
                say(f"target {TARGET} exists")
                return
        t = self.ctl.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=TARGET,
            description="two canned tools",
            targetConfiguration={
                "mcp": {
                    "lambda": {"lambdaArn": function_arn, "toolSchema": {"inlinePayload": TOOLS}}
                }
            },
            credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE"}],
        )
        self.wait(
            lambda: self.ctl.get_gateway_target(
                gatewayIdentifier=gateway_id, targetId=t["targetId"]
            ),
            "READY",
            f"target {TARGET}",
        )
        say(f"created target {TARGET} -> {LAMBDA_NAME}")

    def add_policies(self, engine_id: str, gateway_arn: str) -> None:
        existing = {}
        for p in self.each(self.ctl, "list_policies", "policies", policyEngineId=engine_id):
            status = self.ctl.get_policy(policyEngineId=engine_id, policyId=p["policyId"])["status"]
            if status == "ACTIVE":
                existing[p["name"]] = p["policyId"]
            else:  # a failed attempt from an earlier run; clear it so this run's verdict is fresh
                self.ctl.delete_policy(policyEngineId=engine_id, policyId=p["policyId"])
                self.ctl.get_waiter("policy_deleted").wait(
                    policyEngineId=engine_id, policyId=p["policyId"]
                )
                say(f"removed policy {p['name']} ({status})")
        wanted = {name for name, _, _ in policies(gateway_arn)}
        for name, policy_id in list(existing.items()):
            if name not in wanted:
                self.ctl.delete_policy(policyEngineId=engine_id, policyId=policy_id)
                self.ctl.get_waiter("policy_deleted").wait(
                    policyEngineId=engine_id, policyId=policy_id
                )
                say(f"removed policy {name} (no longer part of the demo)")
        for name, kind, statement in policies(gateway_arn):
            if name in existing:
                say(f"policy {name} exists")
                continue
            p = self.ctl.create_policy(
                name=name,
                policyEngineId=engine_id,
                definition={kind: {"statement": statement}},
                validationMode="FAIL_ON_ANY_FINDINGS",
                enforcementMode="ACTIVE",
            )
            p = self.wait_policy(engine_id, p["policyId"], name)
            say(
                f"created {'Dogwood' if kind == 'policy' else 'Cedar'} policy {name} ({p['status']})"
            )

    def each(self, client, operation: str, key: str, **kwargs):
        """Every page of a list call. A teardown that reads page one only is not a teardown."""
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(key, [])

    def wait_policy(self, engine_id: str, policy_id: str, name: str) -> dict:
        return self.wait(
            lambda: self.ctl.get_policy(policyEngineId=engine_id, policyId=policy_id),
            "ACTIVE",
            f"policy {name}",
        )

    def wait(self, fetch, wanted: str, what: str, deadline_s: float = 300.0):
        start = time.monotonic()
        while True:
            state = fetch()
            status = state.get("status")
            if status == wanted:
                return state
            if status in (
                "FAILED",
                "CREATE_FAILED",
                "UPDATE_FAILED",
                "DELETE_FAILED",
                "UPDATE_UNSUCCESSFUL",
            ):
                raise RuntimeError(f"{what} ended {status}: {state.get('statusReasons')}")
            if time.monotonic() - start > deadline_s:
                raise RuntimeError(f"{what} still {status} after {deadline_s:.0f}s")
            time.sleep(4)

    # -- down --------------------------------------------------------------------------------
    def down(self) -> int:
        say(f"account: {masked(self.account)}  region: {self.region}")
        for g in self.each(self.ctl, "list_gateways", "items"):
            if g["name"] == GATEWAY_NAME:
                self.remove_gateway(g["gatewayId"], g["name"])
        for e in self.each(self.ctl, "list_policy_engines", "policyEngines"):
            if e["name"].startswith(PREFIX):
                self.remove_engine(e["policyEngineId"], e["name"])
        self.attempt(
            f"function {LAMBDA_NAME}",
            lambda: self.lam.delete_function(FunctionName=LAMBDA_NAME),
            lambda: self.lam.get_function(FunctionName=LAMBDA_NAME),
        )
        for name in (GATEWAY_ROLE, LAMBDA_ROLE):
            self.remove_role(name)
        if self.problems:
            say("cleanup incomplete:")
            for p in self.problems:
                say(f"  NOT deleted: {p}")
            return 1
        say("done")
        return 0

    def remove_gateway(self, gid: str, name: str) -> None:
        for t in self.each(self.ctl, "list_gateway_targets", "items", gatewayIdentifier=gid):
            self.remove_target(gid, t["targetId"], t["name"])
        self.attempt(
            f"gateway {name}",
            lambda: self.ctl.delete_gateway(gatewayIdentifier=gid),
            lambda: self.ctl.get_gateway(gatewayIdentifier=gid),
        )

    def remove_target(self, gid: str, tid: str, name: str) -> None:
        self.attempt(
            f"target {name}",
            lambda: self.ctl.delete_gateway_target(gatewayIdentifier=gid, targetId=tid),
            lambda: self.ctl.get_gateway_target(gatewayIdentifier=gid, targetId=tid),
        )

    def remove_engine(self, eid: str, name: str) -> None:
        for p in self.each(self.ctl, "list_policies", "policies", policyEngineId=eid):
            self.remove_policy(eid, p["policyId"], p["name"])
        self.attempt(
            f"policy engine {name}",
            lambda: self.ctl.delete_policy_engine(policyEngineId=eid),
            lambda: self.ctl.get_policy_engine(policyEngineId=eid),
        )

    def remove_policy(self, eid: str, pid: str, name: str) -> None:
        self.attempt(
            f"policy {name}",
            lambda: self.ctl.delete_policy(policyEngineId=eid, policyId=pid),
            lambda: self.ctl.get_policy(policyEngineId=eid, policyId=pid),
        )

    def remove_role(self, name: str) -> None:
        self.attempt(
            f"role {name}", lambda: self.delete_role(name), lambda: self.iam.get_role(RoleName=name)
        )

    def delete_role(self, name: str) -> None:
        for p in self.each(
            self.iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name
        ):
            self.iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        for p in self.each(self.iam, "list_role_policies", "PolicyNames", RoleName=name):
            self.iam.delete_role_policy(RoleName=name, PolicyName=p)
        self.iam.delete_role(RoleName=name)

    def attempt(self, what: str, delete, fetch, deadline_s: float = 300.0) -> None:
        """Delete and wait until the resource is gone; record anything that is not confirmed gone."""
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
                self.problems.append(f"{what}: {exc.response['Error']['Code']}")
                return
        start = time.monotonic()
        while True:
            try:
                state = fetch()
            except ClientError as exc:
                if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "NoSuchEntity"):
                    say(f"deleted {what}")
                    return
                self.problems.append(f"{what}: {exc.response['Error']['Code']}")
                return
            if time.monotonic() - start > deadline_s:
                self.problems.append(
                    f"{what}: still {state.get('status', 'present')} after {deadline_s:.0f}s"
                )
                return
            time.sleep(4)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("up", "down"):
        say(__doc__)
        return 2
    live = Live()
    return live.up() if argv[1] == "up" else live.down()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
