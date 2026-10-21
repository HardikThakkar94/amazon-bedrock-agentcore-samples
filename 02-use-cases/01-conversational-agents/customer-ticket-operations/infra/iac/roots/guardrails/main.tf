# scripts/live_setup.sh equivalent: a prompt-attack guardrail, an Automated Reasoning policy
# and a second guardrail with that policy attached.
#
# The AR policy is loaded from a fixed English definition (exported from a reviewed build) instead
# of being re-extracted from the source document on every deploy: the build step is an LLM and its
# output varies (including, for this document, Spanish variable names).

locals {
  ar_definition = jsondecode(file("${path.module}/ar-definition.en.json"))
  # Cross-Region inference profile required for Automated Reasoning checks in a guardrail.
  guardrail_profile_arn = "arn:aws:bedrock:${var.region}:${var.account_id}:guardrail-profile/${var.guardrail_profile_id}"
}

variable "guardrail_profile_id" {
  description = "Cross-Region guardrail profile used by the Automated Reasoning guardrail."
  type        = string
  default     = "us.guardrail.v1:0"
}

resource "aws_bedrock_guardrail" "prompt_attack" {
  name                      = var.name_prefix
  description               = "SEC310 demo; prompt-attack screening on input"
  blocked_input_messaging   = "Blocked by guardrail."
  blocked_outputs_messaging = "Blocked by guardrail."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
  }
}

resource "awscc_bedrock_automated_reasoning_policy" "rule_change" {
  name         = "${var.name_prefix}_ar"
  description  = "SEC310 demo; rule-change rules (scripts/live/rule-change-policy.txt)"
  force_delete = true

  policy_definition = {
    version = try(local.ar_definition.version, null)
    types = [for t in try(local.ar_definition.types, []) : {
      name        = t.name
      description = try(t.description, null)
      values      = [for v in t.values : { value = v.value, description = try(v.description, null) }]
    }]
    variables = [for v in local.ar_definition.variables : {
      name        = v.name
      type        = v.type
      description = v.description
    }]
    rules = [for r in local.ar_definition.rules : {
      id                   = r.id
      expression           = r.expression
      alternate_expression = try(r.alternateExpression, null)
    }]
  }
}

resource "awscc_bedrock_automated_reasoning_policy_version" "rule_change" {
  policy_arn                   = awscc_bedrock_automated_reasoning_policy.rule_change.policy_arn
  last_updated_definition_hash = awscc_bedrock_automated_reasoning_policy.rule_change.definition_hash
}

resource "awscc_bedrock_guardrail" "automated_reasoning" {
  name                      = "${var.name_prefix}_ar"
  description               = "SEC310 demo; Automated Reasoning policy attached (detect mode)"
  blocked_input_messaging   = "Blocked."
  blocked_outputs_messaging = "Blocked."

  cross_region_config = {
    guardrail_profile_arn = local.guardrail_profile_arn
  }

  automated_reasoning_policy_config = {
    policies = [
      "${awscc_bedrock_automated_reasoning_policy.rule_change.policy_arn}:${awscc_bedrock_automated_reasoning_policy_version.rule_change.version}"
    ]
    confidence_threshold = 0.5
  }
}
