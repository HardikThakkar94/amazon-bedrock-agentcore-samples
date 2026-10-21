# Application state and the presenter API. Tickets live in DynamoDB (the agent's tools read and
# change them through the Gateway); the API is a Lambda function URL that only CloudFront can call.

locals {
  ssm = "/${var.project}/${var.environment}"
  seed = {
    "A-41" = { customer_id = "customer-a", subject = "Package arrived late", body = "Please explain the delay." }
    "A-42" = { customer_id = "customer-a", subject = "Correct billing address", body = "Please update the postal code on my next invoice." }
    "B-77" = { customer_id = "customer-b", subject = "Refund status", body = "When will my refund arrive?" }
  }
}

data "aws_ssm_parameter" "user_pool_arn" {
  name = "${local.ssm}/identity/user_pool_arn"
}

data "aws_ssm_parameter" "issuer" {
  name = "${local.ssm}/identity/issuer"
}

data "aws_ssm_parameter" "invocation_log_group" {
  name = "${local.ssm}/observability/invocation_log_group"
}

# ── Tables ─────────────────────────────────────────────────────────────────
resource "aws_dynamodb_table" "tickets" {
  name         = "${var.name_prefix}_tickets"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "customer_id"
  range_key    = "ticket_id"

  attribute {
    name = "customer_id"
    type = "S"
  }
  attribute {
    name = "ticket_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "state" {
  name         = "${var.name_prefix}_state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "customer_id"

  attribute {
    name = "customer_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table_item" "seed" {
  for_each   = local.seed
  table_name = aws_dynamodb_table.tickets.name
  hash_key   = aws_dynamodb_table.tickets.hash_key
  range_key  = aws_dynamodb_table.tickets.range_key
  item = jsonencode({
    customer_id  = { S = each.value.customer_id }
    ticket_id    = { S = each.key }
    subject      = { S = each.value.subject }
    body         = { S = each.value.body }
    status       = { S = "OPEN" }
    submitted_by = { S = "customer" }
    untrusted    = { BOOL = true }
    origin       = { S = "seed" }
  })

  lifecycle {
    ignore_changes = [item] # the demo changes ticket state; reset is an API action, not a deploy
  }
}

# ── Presenter API ──────────────────────────────────────────────────────────
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

resource "aws_iam_role" "api" {
  name               = "${var.name_prefix}_api"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "api_logs" {
  role       = aws_iam_role.api.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "api" {
  statement {
    sid = "Tables"
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
      "dynamodb:DeleteItem", "dynamodb:Query",
    ]
    resources = [aws_dynamodb_table.tickets.arn, aws_dynamodb_table.state.arn]
  }
  statement {
    sid       = "WebClientId"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${var.account_id}:parameter${local.ssm}/edge/client_id"]
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "api"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.api.json
}

resource "aws_lambda_function" "api" {
  function_name    = "${var.name_prefix}_api"
  role             = aws_iam_role.api.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "app.lambda_handler"
  timeout          = 30
  memory_size      = 256
  s3_bucket        = module.build.bucket
  s3_key           = module.build.lambda["api"].key
  source_code_hash = module.build.lambda["api"].hash

  environment {
    variables = {
      TICKETS_TABLE        = aws_dynamodb_table.tickets.name
      STATE_TABLE          = aws_dynamodb_table.state.name
      INVOCATION_LOG_GROUP = data.aws_ssm_parameter.invocation_log_group.value
      ISSUER               = data.aws_ssm_parameter.issuer.value
      CLIENT_ID_PARAM      = "${local.ssm}/edge/client_id"
    }
  }
}

resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "AWS_IAM" # only principals with lambda:InvokeFunctionUrl: CloudFront via OAC
}
