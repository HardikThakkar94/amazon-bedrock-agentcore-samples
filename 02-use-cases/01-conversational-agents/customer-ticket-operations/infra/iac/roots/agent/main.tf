# The support agent on AgentCore Runtime and the tools it may call through AgentCore Gateway.
#
#   browser ─(Cognito session)─ CloudFront ─ API Lambda ─(user's access token)─▶ Runtime
#   Runtime (JWT authorizer, forwards Authorization) ─▶ Strands agent ─(same token, MCP)─▶ Gateway
#   Gateway (JWT authorizer) ─▶ TicketTools Lambda ─▶ DynamoDB tickets
#
# One gateway per distinct policy set (src/sec310_agent/controls.py maps builds to them):
#   v0  no policy engine: every tool call goes through                      (V0)
#   v1  AgentCore Policy: a call must be for the caller and the caller's tenant (V1, V2)
#   v3  v1's fence + forbid close_ticket for the operator summary task      (V3, V4, V5)

locals {
  ssm          = "/${var.project}/${var.environment}"
  agentcore    = "arn:aws:bedrock-agentcore:${var.region}:${var.account_id}"
  hyphen       = replace(var.name_prefix, "_", "-") # gateways allow hyphens; runtimes underscores
  target       = "TicketTools"
  web_client   = data.aws_ssm_parameter.in["edge/client_id"].value
  discovery    = data.aws_ssm_parameter.in["identity/discovery_url"].value
  tickets_arn  = data.aws_ssm_parameter.in["app/tickets_table_arn"].value
  events_arn   = data.aws_ssm_parameter.in["app/events_table_arn"].value
  model_family = replace(var.model_id, "/^(us|eu|apac|global)\\./", "") # profile -> foundation model
  state_arn    = data.aws_ssm_parameter.in["app/state_table_arn"].value

  gateways = {
    v0 = { policy = false, description = "V0 build: the agent's tools with no policy engine" }
    v1 = { policy = true, description = "V1-V2 builds: AgentCore Policy fences every call to the caller's tenant" }
    v3 = { policy = true, description = "V3-V5 builds: tenant fence plus forbid close_ticket for the summary task" }
  }
  tool_actions = [for t in keys(local.tools) : "AgentCore::Action::\"${local.target}___${t}\""]

  # ``actor`` is filled in by the agent's runtime from the verified token on every call; the
  # Gateway's policies (later builds) compare it with the token's own claims.
  actor = {
    name        = "actor"
    type        = "object"
    description = "Signed-in user the call is made for. Set by the runtime; do not fill in."
    required    = true
    properties = [
      { name = "user_sub", type = "string", description = "Cognito subject of the user.", required = true },
      { name = "customer_id", type = "string", description = "Tenant of the user.", required = true },
    ]
  }
  tools = {
    list_tickets = {
      description = "List one customer's support tickets, including customer-authored text."
      input = [
        { name = "customer_id", type = "string", description = "Customer such as customer-a.", required = true },
      ]
    }
    close_ticket = {
      description = "Close one support ticket."
      input = [
        { name = "customer_id", type = "string", description = "Customer that owns the ticket.", required = true },
        { name = "ticket_id", type = "string", description = "Ticket such as A-42.", required = true },
        { name = "reason", type = "string", description = "Why the ticket is closed.", required = true },
      ]
    }
    add_note = {
      description = "Add an operator note to one support ticket."
      input = [
        { name = "customer_id", type = "string", description = "Customer that owns the ticket.", required = true },
        { name = "ticket_id", type = "string", description = "Ticket such as A-42.", required = true },
        { name = "note", type = "string", description = "Note text, at most 500 characters.", required = true },
      ]
    }
  }
}

data "aws_ssm_parameter" "in" {
  for_each = toset(["edge/client_id", "identity/discovery_url", "app/tickets_table", "app/tickets_table_arn", "app/events_table", "app/events_table_arn", "app/state_table", "app/state_table_arn", "guardrails/prompt_attack_id"])
  name     = "${local.ssm}/${each.key}"
}

module "build" {
  source      = "../../modules/build_artifacts"
  project     = var.project
  environment = var.environment
}

# ── TicketTools Lambda ─────────────────────────────────────────────────────
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ticket_tools" {
  name               = "${var.name_prefix}_ticket_tools"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "ticket_tools_logs" {
  role       = aws_iam_role.ticket_tools.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "ticket_tools" {
  statement {
    sid       = "Tickets"
    actions   = ["dynamodb:Query", "dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [local.tickets_arn]
  }
  statement {
    sid       = "LiveEvents"
    actions   = ["dynamodb:PutItem"]
    resources = [local.events_arn]
  }
}

resource "aws_iam_role_policy" "ticket_tools" {
  name   = "tickets"
  role   = aws_iam_role.ticket_tools.id
  policy = data.aws_iam_policy_document.ticket_tools.json
}

resource "aws_lambda_function" "ticket_tools" {
  function_name    = "${var.name_prefix}_ticket_tools"
  role             = aws_iam_role.ticket_tools.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handler.lambda_handler"
  timeout          = 10
  s3_bucket        = module.build.bucket
  s3_key           = module.build.lambda["ticket_tools"].key
  source_code_hash = module.build.lambda["ticket_tools"].hash

  environment {
    variables = {
      TICKETS_TABLE = data.aws_ssm_parameter.in["app/tickets_table"].value
      EVENTS_TABLE  = data.aws_ssm_parameter.in["app/events_table"].value
    }
  }
}

# ── V0 gateway: user JWT inbound, no policy engine ─────────────────────────
data "aws_iam_policy_document" "agentcore_trust" {
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

resource "aws_iam_role" "gateway" {
  name               = "${var.name_prefix}_v0_gateway"
  assume_role_policy = data.aws_iam_policy_document.agentcore_trust.json
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "InvokeTicketTools"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.ticket_tools.arn]
  }
  statement {
    sid = "PolicyEngine" # V1+ gateways ask AgentCore Policy before every tools/call
    actions = [
      "bedrock-agentcore:GetPolicyEngine",
      "bedrock-agentcore:AuthorizeAction",
      "bedrock-agentcore:PartiallyAuthorizeActions",
    ]
    resources = ["${local.agentcore}:policy-engine/*", "${local.agentcore}:gateway/*"]
  }
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

resource "aws_bedrockagentcore_policy_engine" "build" {
  for_each    = { for k, v in local.gateways : k => v if v.policy }
  name        = "${var.name_prefix}_${each.key}_policy"
  description = local.gateways[each.key].description
}

resource "aws_bedrockagentcore_gateway" "build" {
  for_each        = local.gateways
  name            = "${local.hyphen}-${each.key}-gw"
  description     = each.value.description
  protocol_type   = "MCP"
  authorizer_type = "CUSTOM_JWT"
  role_arn        = aws_iam_role.gateway.arn

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url   = local.discovery
      allowed_clients = [local.web_client] # Cognito access tokens carry client_id, not aud
    }
  }

  dynamic "policy_engine_configuration" {
    for_each = each.value.policy ? [1] : []
    content {
      arn  = aws_bedrockagentcore_policy_engine.build[each.key].policy_engine_arn
      mode = "ENFORCE"
    }
  }

  depends_on = [aws_iam_role_policy.gateway]
}

moved {
  from = aws_bedrockagentcore_gateway.v0
  to   = aws_bedrockagentcore_gateway.build["v0"]
}

resource "aws_bedrockagentcore_gateway_target" "tickets" {
  for_each           = local.gateways
  name               = local.target
  gateway_identifier = aws_bedrockagentcore_gateway.build[each.key].gateway_id

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.ticket_tools.arn
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
                property {
                  name        = "run_id"
                  type        = "string"
                  description = "Run being traced. Set by the runtime; do not fill in."
                  required    = false
                }
                property {
                  name        = local.actor.name
                  type        = local.actor.type
                  description = local.actor.description
                  required    = local.actor.required
                  dynamic "property" {
                    for_each = local.actor.properties
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
}

moved {
  from = aws_bedrockagentcore_gateway_target.tickets
  to   = aws_bedrockagentcore_gateway_target.tickets["v0"]
}

# ── AgentCore Policy (Cedar). Deny by default; a forbid overrides every permit. ──
# Tool arguments are context.input.*; the caller is AgentCore::OAuthUser with id = the token's
# sub and every other claim as a tag. ``actor`` is set by the agent runtime from the same token,
# so the fence checks that the call is for the signed-in user and stays in their tenant.
resource "aws_bedrockagentcore_policy" "tenant_fence" {
  for_each         = aws_bedrockagentcore_policy_engine.build
  name             = "${var.name_prefix}_${each.key}_tenant_fence" # policy names are unique per account
  policy_engine_id = each.value.policy_engine_id
  description      = "Calls only for the signed-in user, only on their own tenant's tickets"
  definition {
    cedar {
      statement = <<-CEDAR
        permit(
          principal is AgentCore::OAuthUser,
          action in [${join(", ", local.tool_actions)}],
          resource == AgentCore::Gateway::"${aws_bedrockagentcore_gateway.build[each.key].gateway_arn}"
        ) when {
          principal.hasTag("customer_id") &&
          context.input has customer_id &&
          context.input.customer_id == principal.getTag("customer_id") &&
          context.input has actor &&
          context.input.actor has user_sub &&
          context.input.actor.user_sub == principal.id
        };
      CEDAR
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.tickets]
}

# V3: summarizing tickets for an operator never closes one. Conditioned on the operator role so
# close_ticket stays listed (the model can still propose it, and the denial is visible) and the
# policy passes validation (an unconditional forbid is rejected as overly restrictive).
resource "aws_bedrockagentcore_policy" "no_close_in_summary" {
  name             = "${var.name_prefix}_v3_no_close_in_summary"
  policy_engine_id = aws_bedrockagentcore_policy_engine.build["v3"].policy_engine_id
  description      = "The operator summary task may read and annotate tickets, never close them"
  definition {
    cedar {
      statement = <<-CEDAR
        forbid(
          principal is AgentCore::OAuthUser,
          action == AgentCore::Action::"${local.target}___close_ticket",
          resource == AgentCore::Gateway::"${aws_bedrockagentcore_gateway.build["v3"].gateway_arn}"
        ) when {
          principal.hasTag("role") && principal.getTag("role") == "operator"
        };
      CEDAR
    }
  }
  depends_on = [aws_bedrockagentcore_policy.tenant_fence]
}

# Gateway application logs (each tools/call and its outcome) to CloudWatch. The runtime's own
# stdout goes to /aws/bedrock-agentcore/runtimes/<id>-DEFAULT without extra configuration.
resource "aws_cloudwatch_log_group" "gateway" {
  for_each          = aws_bedrockagentcore_gateway.build
  name              = "/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/${each.value.gateway_id}"
  retention_in_days = 3
}

resource "aws_cloudwatch_log_delivery_source" "gateway" {
  for_each     = aws_bedrockagentcore_gateway.build
  name         = "${var.name_prefix}_${each.key}_gateway_logs"
  log_type     = "APPLICATION_LOGS"
  resource_arn = each.value.gateway_arn
}

resource "aws_cloudwatch_log_delivery_destination" "gateway" {
  for_each                  = aws_bedrockagentcore_gateway.build
  name                      = "${var.name_prefix}_${each.key}_gateway_logs"
  delivery_destination_type = "CWL"
  delivery_destination_configuration {
    destination_resource_arn = aws_cloudwatch_log_group.gateway[each.key].arn
  }
}

resource "aws_cloudwatch_log_delivery" "gateway" {
  for_each                 = aws_bedrockagentcore_gateway.build
  delivery_source_name     = aws_cloudwatch_log_delivery_source.gateway[each.key].name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.gateway[each.key].arn
}

moved {
  from = aws_cloudwatch_log_group.gateway
  to   = aws_cloudwatch_log_group.gateway["v0"]
}
moved {
  from = aws_cloudwatch_log_delivery_source.gateway
  to   = aws_cloudwatch_log_delivery_source.gateway["v0"]
}
moved {
  from = aws_cloudwatch_log_delivery_destination.gateway
  to   = aws_cloudwatch_log_delivery_destination.gateway["v0"]
}
moved {
  from = aws_cloudwatch_log_delivery.gateway
  to   = aws_cloudwatch_log_delivery.gateway["v0"]
}

# ── Agent runtime ──────────────────────────────────────────────────────────
resource "aws_iam_role" "runtime" {
  name               = "${var.name_prefix}_agent_runtime"
  assume_role_policy = data.aws_iam_policy_document.agentcore_trust.json
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid       = "PullImage"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["arn:aws:ecr:${var.region}:${var.account_id}:repository/${split("/", split("@", module.build.images["agent"])[0])[1]}"]
  }
  statement {
    sid       = "EcrToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"]
  }
  statement {
    sid       = "LogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:*"]
  }
  statement {
    sid       = "Traces"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
  statement {
    sid       = "Metrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["bedrock-agentcore"]
    }
  }
  statement {
    sid     = "WorkloadIdentity"
    actions = ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT", "bedrock-agentcore:GetWorkloadAccessTokenForUserId"]
    resources = [
      "${local.agentcore}:workload-identity-directory/default",
      "${local.agentcore}:workload-identity-directory/default/workload-identity/*",
    ]
  }
  statement {
    sid       = "LiveEvents"
    actions   = ["dynamodb:PutItem"]
    resources = [local.events_arn]
  }
  statement {
    sid       = "DurableStop" # V4+: read at admission, written on the first denial
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [local.state_arn]
  }
  statement {
    sid       = "ScreenTicketText" # V2+: prompt-attack screen on list_tickets results
    actions   = ["bedrock:ApplyGuardrail"]
    resources = ["arn:aws:bedrock:${var.region}:${var.account_id}:guardrail/${data.aws_ssm_parameter.in["guardrails/prompt_attack_id"].value}"]
  }
  statement {
    sid     = "OneModel"
    actions = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = concat(
      ["arn:aws:bedrock:${var.region}:${var.account_id}:inference-profile/${var.model_id}"],
      [for r in var.model_regions : "arn:aws:bedrock:${r}::foundation-model/${local.model_family}"],
    )
  }
}

resource "aws_iam_role_policy" "runtime" {
  name   = "runtime"
  role   = aws_iam_role.runtime.id
  policy = data.aws_iam_policy_document.runtime.json
}

# A new role is not assumable by the service for a few seconds (IAM eventual consistency).
resource "time_sleep" "runtime_role" {
  depends_on      = [aws_iam_role_policy.runtime]
  create_duration = "15s"
}

resource "aws_bedrockagentcore_agent_runtime" "agent" {
  agent_runtime_name = "${var.name_prefix}_agent"
  description        = "Support agent (Strands); tools via the build's gateway"
  role_arn           = aws_iam_role.runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = module.build.images["agent"]
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  protocol_configuration {
    server_protocol = "HTTP"
  }

  # AgentCore Identity, inbound: only a valid Cognito access token from the web client may invoke.
  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url   = local.discovery
      allowed_clients = [local.web_client]
    }
  }

  # Forward the caller's token to the agent so it can call the Gateway as that user.
  request_header_configuration {
    request_header_allowlist = ["Authorization"]
  }

  environment_variables = {
    GATEWAY_URLS      = jsonencode({ for k, g in aws_bedrockagentcore_gateway.build : k => g.gateway_url })
    MODEL_ID          = var.model_id
    EVENTS_TABLE      = data.aws_ssm_parameter.in["app/events_table"].value
    STATE_TABLE       = data.aws_ssm_parameter.in["app/state_table"].value
    GUARDRAIL_ID      = data.aws_ssm_parameter.in["guardrails/prompt_attack_id"].value
    GUARDRAIL_VERSION = "DRAFT"
    # OpenTelemetry (ADOT, opentelemetry-instrument in the image) -> CloudWatch Transaction Search
    AGENT_OBSERVABILITY_ENABLED = "true"
    OTEL_RESOURCE_ATTRIBUTES    = "service.name=${var.name_prefix}_agent,deployment.environment=${var.environment}"
  }

  depends_on = [time_sleep.runtime_role]
}
