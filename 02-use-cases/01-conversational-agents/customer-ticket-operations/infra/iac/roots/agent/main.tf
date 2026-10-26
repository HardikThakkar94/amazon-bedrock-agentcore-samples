# The support agent on AgentCore Runtime and the tools it may call through AgentCore Gateway.
#
#   browser ─(Cognito session)─ CloudFront ─ API Lambda ─(user's access token)─▶ Runtime
#   Runtime (JWT authorizer, forwards Authorization) ─▶ Strands agent ─(same token, MCP)─▶ Gateway
#   Gateway (JWT authorizer) ─▶ TicketTools Lambda ─▶ DynamoDB tickets
#
# This root holds the V0 build's gateway: no policy engine, so every tool call goes through.
# Later builds add their own gateways with AgentCore Policy attached (one gateway per build).

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
  for_each = toset(["edge/client_id", "identity/discovery_url", "app/tickets_table", "app/tickets_table_arn", "app/events_table", "app/events_table_arn"])
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
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

resource "aws_bedrockagentcore_gateway" "v0" {
  name            = "${local.hyphen}-v0-gw"
  description     = "V0 build: the agent's tools with no policy engine"
  protocol_type   = "MCP"
  authorizer_type = "CUSTOM_JWT"
  role_arn        = aws_iam_role.gateway.arn

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url   = local.discovery
      allowed_clients = [local.web_client] # Cognito access tokens carry client_id, not aud
    }
  }

  depends_on = [aws_iam_role_policy.gateway]
}

resource "aws_bedrockagentcore_gateway_target" "tickets" {
  name               = local.target
  gateway_identifier = aws_bedrockagentcore_gateway.v0.gateway_id

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

# Gateway application logs (each tools/call and its outcome) to CloudWatch. The runtime's own
# stdout goes to /aws/bedrock-agentcore/runtimes/<id>-DEFAULT without extra configuration.
resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/${aws_bedrockagentcore_gateway.v0.gateway_id}"
  retention_in_days = 3
}

resource "aws_cloudwatch_log_delivery_source" "gateway" {
  name         = "${var.name_prefix}_v0_gateway_logs"
  log_type     = "APPLICATION_LOGS"
  resource_arn = aws_bedrockagentcore_gateway.v0.gateway_arn
}

resource "aws_cloudwatch_log_delivery_destination" "gateway" {
  name                      = "${var.name_prefix}_v0_gateway_logs"
  delivery_destination_type = "CWL"
  delivery_destination_configuration {
    destination_resource_arn = aws_cloudwatch_log_group.gateway.arn
  }
}

resource "aws_cloudwatch_log_delivery" "gateway" {
  delivery_source_name     = aws_cloudwatch_log_delivery_source.gateway.name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.gateway.arn
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
  description        = "Support agent (Strands); tools via the V0 gateway"
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
    GATEWAY_URL  = aws_bedrockagentcore_gateway.v0.gateway_url
    MODEL_ID     = var.model_id
    EVENTS_TABLE = data.aws_ssm_parameter.in["app/events_table"].value
  }

  depends_on = [time_sleep.runtime_role]
}
