locals {
  outputs = {
    runtime_arn = aws_bedrockagentcore_agent_runtime.agent.agent_runtime_arn
    gateway_url = aws_bedrockagentcore_gateway.v0.gateway_url
    model_id    = var.model_id
    gateway_log = aws_cloudwatch_log_group.gateway.name
  }
}

# Read by the API Lambda at request time (the API is deployed before this root).
resource "aws_ssm_parameter" "agent" {
  for_each = local.outputs
  name     = "${local.ssm}/agent/${each.key}"
  type     = "String"
  value    = each.value
}

output "agent" {
  value = local.outputs
}
