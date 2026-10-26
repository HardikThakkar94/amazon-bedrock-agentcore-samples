# Account/Region-wide Bedrock model invocation logging (scripts/live_logging.py equivalent).
# Every text-model call in this account and Region lands here: synthetic demo inputs only.

locals {
  log_group = "/aws/bedrock/${var.name_prefix}_invocations"
}

resource "aws_cloudwatch_log_group" "invocations" {
  name              = local.log_group
  retention_in_days = 3
}

data "aws_iam_policy_document" "bedrock_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock:${var.region}:${var.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "invocation_logging" {
  name               = "${var.name_prefix}_invocation_logging"
  description        = "SEC310 demo; lets Bedrock write model invocation logs"
  assume_role_policy = data.aws_iam_policy_document.bedrock_trust.json
}

data "aws_iam_policy_document" "write_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.invocations.arn}:log-stream:aws/bedrock/modelinvocations"]
  }
}

resource "aws_iam_role_policy" "write_logs" {
  name   = "write_invocation_logs"
  role   = aws_iam_role.invocation_logging.id
  policy = data.aws_iam_policy_document.write_logs.json
}

# A new role is not usable by Bedrock for a few seconds (IAM eventual consistency).
resource "time_sleep" "iam_propagation" {
  depends_on      = [aws_iam_role_policy.write_logs]
  create_duration = "20s"
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  depends_on = [time_sleep.iam_propagation]

  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = false
    embedding_data_delivery_enabled = false
    video_data_delivery_enabled     = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.invocations.name
      role_arn       = aws_iam_role.invocation_logging.arn
    }
  }
}

# ── CloudWatch Transaction Search: X-Ray spans land in CloudWatch Logs (aws/spans), 100% indexed ──
# AgentCore Runtime exports the agent's OpenTelemetry spans; GenAI Observability, the console's
# Trace view and AgentCore Evaluations all read them from here.
data "aws_iam_policy_document" "xray_to_logs" {
  statement {
    sid     = "TransactionSearchXRayAccess"
    actions = ["logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:aws/spans:*",
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/application-signals/data:*",
    ]
    principals {
      type        = "Service"
      identifiers = ["xray.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:xray:${var.region}:${var.account_id}:*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "xray" {
  policy_name     = "${var.name_prefix}_transaction_search"
  policy_document = data.aws_iam_policy_document.xray_to_logs.json
}

resource "aws_xray_trace_segment_destination" "this" {
  destination = "CloudWatchLogs"
  depends_on  = [aws_cloudwatch_log_resource_policy.xray]
}

resource "aws_xray_indexing_rule" "default" {
  name = "Default"
  rule {
    probabilistic {
      desired_sampling_percentage = 100 # every demo span is searchable
    }
  }
  depends_on = [aws_xray_trace_segment_destination.this]
}
