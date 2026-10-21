locals {
  issuer = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
  outputs = {
    user_pool_id  = aws_cognito_user_pool.this.id
    user_pool_arn = aws_cognito_user_pool.this.arn
    issuer        = local.issuer
    discovery_url = "${local.issuer}/.well-known/openid-configuration"
    domain        = "${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com"
  }
}

resource "aws_ssm_parameter" "identity" {
  for_each = local.outputs
  name     = "${local.ssm}/${each.key}"
  type     = "String"
  value    = each.value
}

output "identity" {
  value = local.outputs
}

output "persona_secrets" {
  value = { for k, s in aws_secretsmanager_secret.persona : k => s.name }
}
