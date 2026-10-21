resource "aws_ssm_parameter" "invocation_log_group" {
  name  = "/${var.project}/${var.environment}/observability/invocation_log_group"
  type  = "String"
  value = aws_cloudwatch_log_group.invocations.name
}

output "invocation_log_group" {
  value = aws_cloudwatch_log_group.invocations.name
}
