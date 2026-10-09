"""Gateway tool target for the SEC310 live stage.

Two canned tools over a fixed evidence store, so that the *authorization* decisions made by the
gateway's policy engine are the only interesting thing in the demo. The tool name arrives in
the Lambda client context as ``<TargetName>___<tool>``.
"""

import json

RULES = {
    "acct-a": {"rule-42": {"name": "root-activity", "enabled": False, "version": 3}},
    "acct-b": {"rule-77": {"name": "s3-public-acl", "enabled": True, "version": 9}},
}
FINDINGS = {
    "acct-a": [
        {"id": "finding-101", "severity": "high", "title": "Console sign-in without MFA"},
        {"id": "finding-102", "severity": "medium", "title": "Detection rule disabled"},
    ],
    "acct-b": [{"id": "finding-201", "severity": "low", "title": "Public bucket ACL"}],
}


def lambda_handler(event, context):
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    tool = custom.get("bedrockAgentCoreToolName", "").split("___")[-1]
    account_id = event.get("account_id", "")
    if tool == "read_evidence":
        return {
            "account_id": account_id,
            "finding_count": len(FINDINGS.get(account_id, [])),
            "findings": json.dumps(FINDINGS.get(account_id, [])),
            "rules": json.dumps(RULES.get(account_id, {})),
        }
    if tool == "update_rule":
        rule = RULES.get(account_id, {}).get(event.get("rule_id", ""))
        if rule is None:
            return {
                "status": "not_found",
                "account_id": account_id,
                "rule_id": event.get("rule_id", ""),
                "enabled": False,
            }
        return {
            "status": "ok",
            "account_id": account_id,
            "rule_id": event["rule_id"],
            "enabled": bool(event.get("enabled", True)),
        }
    return {"status": "unknown_tool", "account_id": account_id, "rule_id": "", "enabled": False}
