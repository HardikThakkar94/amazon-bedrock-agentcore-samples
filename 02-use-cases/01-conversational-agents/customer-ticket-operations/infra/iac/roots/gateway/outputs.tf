resource "aws_ssm_parameter" "gateway_url" {
  name  = "/${var.project}/${var.environment}/gateway/url"
  type  = "String"
  value = aws_bedrockagentcore_gateway.this.gateway_url
}

resource "aws_ssm_parameter" "policy_engine_id" {
  name  = "/${var.project}/${var.environment}/gateway/policy_engine_id"
  type  = "String"
  value = aws_bedrockagentcore_policy_engine.this.policy_engine_id
}

output "gateway_url" {
  value = aws_bedrockagentcore_gateway.this.gateway_url
}

output "policy_engine_id" {
  value = aws_bedrockagentcore_policy_engine.this.policy_engine_id
}

output "gateway_log_group" {
  value = aws_cloudwatch_log_group.gateway.name
}
