# scripts/live_gateway.py + the gateway half of scripts/live_logging.py: a Lambda with two canned
# tools, an AgentCore Gateway (MCP, AWS_IAM inbound) with a policy engine in ENFORCE mode, two
# Cedar policies and one Dogwood temporal policy, and vended gateway logs to CloudWatch.

locals {
  target       = "EvidenceTools"
  gateway_name = "${replace(var.name_prefix, "_", "-")}-gateway" # gateways allow hyphens; policies underscores
  agentcore    = "arn:aws:bedrock-agentcore:${var.region}:${var.account_id}"

  tools = {
    read_evidence = {
      description = "Read the findings and detection rules recorded for one account."
      input = [
        { name = "account_id", type = "string", description = "Account such as acct-a.", required = true },
      ]
      output = [
        { name = "account_id", type = "string", description = null, required = true },
        { name = "finding_count", type = "integer", description = null, required = true },
        { name = "findings", type = "string", description = "JSON list of findings.", required = true },
        { name = "rules", type = "string", description = "JSON map of rules.", required = true },
      ]
    }
    update_rule = {
      description = "Enable or disable one detection rule in one account."
      input = [
        { name = "account_id", type = "string", description = "Account such as acct-a.", required = true },
        { name = "rule_id", type = "string", description = "Rule such as rule-42.", required = true },
        { name = "enabled", type = "boolean", description = "Desired state.", required = true },
      ]
      output = [
        { name = "status", type = "string", description = null, required = true },
        { name = "account_id", type = "string", description = null, required = true },
        { name = "rule_id", type = "string", description = null, required = true },
        { name = "enabled", type = "boolean", description = null, required = true },
      ]
    }
  }

  read  = "action == AgentCore::Action::\"${local.target}___read_evidence\""
  write = "action == AgentCore::Action::\"${local.target}___update_rule\""
  gw    = "resource == AgentCore::Gateway::\"${aws_bedrockagentcore_gateway.this.gateway_arn}\""
}

# ── Tool Lambda ─────────────────────────────────────────────────────────────
module "build" {
  source      = "../../modules/build_artifacts"
  project     = var.project
  environment = var.environment
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "tools" {
  name               = "${var.name_prefix}_tool_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "tools_logs" {
  role       = aws_iam_role.tools.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "tools" {
  function_name    = "${var.name_prefix}_tools"
  role             = aws_iam_role.tools.arn
  runtime          = "python3.12"
  handler          = "tool_lambda.lambda_handler"
  timeout          = 10
  s3_bucket        = module.build.bucket
  s3_key           = module.build.lambda["evidence_tools"].key
  source_code_hash = module.build.lambda["evidence_tools"].hash
}

# ── Gateway service role ────────────────────────────────────────────────────
data "aws_iam_policy_document" "gateway_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["${local.agentcore}:*"]
    }
  }
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "InvokeTools"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.tools.arn]
  }
  statement {
    sid = "PolicyEngine"
    actions = [
      "bedrock-agentcore:GetPolicyEngine",
      "bedrock-agentcore:AuthorizeAction",
      "bedrock-agentcore:PartiallyAuthorizeActions",
    ]
    resources = ["${local.agentcore}:policy-engine/*", "${local.agentcore}:gateway/*"]
  }
  statement {
    # temporal (Dogwood) policies make the gateway mint a workload access token per session
    sid     = "PolicySessionIdentity"
    actions = ["bedrock-agentcore:GetWorkloadAccessToken"]
    resources = [
      "${local.agentcore}:workload-identity-directory/default",
      "${local.agentcore}:workload-identity-directory/default/workload-identity/*",
    ]
  }
}

resource "aws_iam_role" "gateway" {
  name               = "${var.name_prefix}_gateway_role"
  assume_role_policy = data.aws_iam_policy_document.gateway_trust.json
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

# ── Policy engine, gateway, target ──────────────────────────────────────────
resource "aws_bedrockagentcore_policy_engine" "this" {
  name        = "${var.name_prefix}_gw"
  description = "SEC310 demo; Cedar scope + Dogwood session history for EvidenceTools"
}

resource "aws_bedrockagentcore_gateway" "this" {
  name            = local.gateway_name
  description     = "SEC310 demo; policy engine in ENFORCE mode"
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  role_arn        = aws_iam_role.gateway.arn

  policy_engine_configuration {
    arn  = aws_bedrockagentcore_policy_engine.this.policy_engine_arn
    mode = "ENFORCE"
  }

  depends_on = [aws_iam_role_policy.gateway]
}

resource "aws_bedrockagentcore_gateway_target" "tools" {
  name               = local.target
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.tools.arn
        tool_schema {
          dynamic "inline_payload" {
            for_each = local.tools
            content {
              name        = inline_payload.key
              description = inline_payload.value.description
              input_schema {
                type = "object"
                dynamic "property" {
                  for_each = inline_payload.value.input
                  content {
                    name        = property.value.name
                    type        = property.value.type
                    description = property.value.description
                    required    = property.value.required
                  }
                }
              }
              output_schema {
                type = "object"
                dynamic "property" {
                  for_each = inline_payload.value.output
                  content {
                    name        = property.value.name
                    type        = property.value.type
                    description = property.value.description
                    required    = property.value.required
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# ── Policies ────────────────────────────────────────────────────────────────
# Permits combine with OR and a forbid overrides every permit: the account scope is a *forbid*
# and the temporal rule is the *only* write permit. Validation is engine-wide, so the forbid is
# created after a write permit exists (otherwise it is rejected as "Overly Restrictive").
resource "aws_bedrockagentcore_policy" "read_known_accounts" {
  name             = "read_known_accounts"
  policy_engine_id = aws_bedrockagentcore_policy_engine.this.policy_engine_id
  definition {
    cedar {
      statement = "permit(principal, ${local.read}, ${local.gw}) when { context.input.account_id like \"acct-*\" };"
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.tools]
}

resource "awscc_bedrockagentcore_policy" "look_before_you_write" {
  name             = "look_before_you_write"
  policy_engine_id = aws_bedrockagentcore_policy_engine.this.policy_engine_id
  definition = {
    # Dogwood temporal statement: goes under `policy`, not `cedar` (aws provider has no such block)
    policy = {
      statement = "permit(principal, ${local.write}, ${local.gw}) when temporal { formerly within 1h AgentCore::Action::\"${local.target}___read_evidence\"::response{ eventResource: resource, input.account_id: context.input.account_id } };"
    }
  }
  depends_on = [aws_bedrockagentcore_policy.read_known_accounts]
}

resource "aws_bedrockagentcore_policy" "no_writes_outside_acct_a" {
  name             = "no_writes_outside_acct_a"
  policy_engine_id = aws_bedrockagentcore_policy_engine.this.policy_engine_id
  definition {
    cedar {
      statement = "forbid(principal, ${local.write}, ${local.gw}) unless { context.input.account_id == \"acct-a\" };"
    }
  }
  depends_on = [awscc_bedrockagentcore_policy.look_before_you_write]
}

# ── Gateway vended logs ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/${aws_bedrockagentcore_gateway.this.gateway_id}"
  retention_in_days = 3
}

resource "aws_cloudwatch_log_delivery_source" "gateway" {
  name         = "${var.name_prefix}_gateway_logs"
  log_type     = "APPLICATION_LOGS"
  resource_arn = aws_bedrockagentcore_gateway.this.gateway_arn
}

resource "aws_cloudwatch_log_delivery_destination" "gateway" {
  name                      = "${var.name_prefix}_gateway_logs"
  delivery_destination_type = "CWL"
  delivery_destination_configuration {
    destination_resource_arn = aws_cloudwatch_log_group.gateway.arn
  }
}

resource "aws_cloudwatch_log_delivery" "gateway" {
  delivery_source_name     = aws_cloudwatch_log_delivery_source.gateway.name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.gateway.arn
}
