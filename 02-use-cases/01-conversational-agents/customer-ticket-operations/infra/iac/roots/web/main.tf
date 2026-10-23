# The presenter UI on CloudFront. Nothing is public:
#   /*       -> private S3 bucket (origin access control)
#   /api/*   -> Lambda function URL with AuthType=AWS_IAM (origin access control signs the request)
# Lambda@Edge checks a Cognito session on every request before either origin is reached.

locals {
  ssm           = "/${var.project}/${var.environment}"
  edge_ssm_path = "${local.ssm}/edge/"
  host          = aws_cloudfront_distribution.this.domain_name
}

data "aws_ssm_parameter" "identity" {
  for_each = toset(["user_pool_id", "issuer", "domain"])
  name     = "${local.ssm}/identity/${each.key}"
}

data "aws_ssm_parameter" "app" {
  for_each = toset(["api_function_name", "api_function_url"])
  name     = "${local.ssm}/app/${each.key}"
}

# ── Cognito app client for this site (needs the CloudFront host for its URLs) ──
resource "aws_cognito_user_pool_client" "web" {
  name                                 = "${var.name_prefix}_web"
  user_pool_id                         = data.aws_ssm_parameter.identity["user_pool_id"].value
  generate_secret                      = false # public client; PKCE protects the code exchange
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["https://${local.host}/auth/callback"]
  logout_urls                          = ["https://${local.host}/auth/login", "https://${local.host}/signed-out"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  access_token_validity                = 60
  id_token_validity                    = 60
  refresh_token_validity               = 1
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

resource "aws_ssm_parameter" "edge" {
  for_each = {
    client_id = aws_cognito_user_pool_client.web.id
    domain    = data.aws_ssm_parameter.identity["domain"].value
    issuer    = data.aws_ssm_parameter.identity["issuer"].value
  }
  name  = "${local.edge_ssm_path}${each.key}"
  type  = "String"
  value = each.value
}

# ── Lambda@Edge auth ───────────────────────────────────────────────────────
module "build" {
  source      = "../../modules/build_artifacts"
  project     = var.project
  environment = var.environment
}

data "aws_iam_policy_document" "edge_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "edge" {
  name               = "${var.name_prefix}_edge_auth"
  assume_role_policy = data.aws_iam_policy_document.edge_trust.json
}

data "aws_iam_policy_document" "edge" {
  statement {
    sid       = "ReadEdgeConfig"
    actions   = ["ssm:GetParameter"]
    resources = [for k in ["client_id", "domain", "issuer"] : "arn:aws:ssm:us-east-1:${var.account_id}:parameter${local.edge_ssm_path}${k}"]
  }
  statement {
    sid       = "Logs" # Lambda@Edge logs in the Region nearest the viewer
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:${var.account_id}:log-group:/aws/lambda/us-east-1.${var.name_prefix}_edge_auth:*"]
  }
}

resource "aws_iam_role_policy" "edge" {
  name   = "edge"
  role   = aws_iam_role.edge.id
  policy = data.aws_iam_policy_document.edge.json
}

resource "aws_lambda_function" "edge" {
  function_name    = "${var.name_prefix}_edge_auth"
  role             = aws_iam_role.edge.arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  timeout          = 5
  memory_size      = 256
  publish          = true                # Lambda@Edge needs a numbered version
  s3_bucket        = module.build.bucket # us-east-1, as Lambda@Edge requires
  s3_key           = module.build.lambda["edge_auth"].key
  source_code_hash = module.build.lambda["edge_auth"].hash
  depends_on       = [aws_iam_role_policy.edge]
}

# ── Private UI bucket ──────────────────────────────────────────────────────
resource "aws_s3_bucket" "web" {
  bucket        = "${replace(var.name_prefix, "_", "-")}-web-${var.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "web" {
  bucket                  = aws_s3_bucket.web.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "web" {
  bucket = aws_s3_bucket.web.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "web" {
  bucket = aws_s3_bucket.web.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object_copy" "web" {
  for_each     = { for f in module.build.web : f.path => f }
  bucket       = aws_s3_bucket.web.id
  key          = each.key
  source       = "${module.build.bucket}/${each.value.key}"
  content_type = each.value.content_type
  # copy again whenever a new build is deployed
  metadata           = { build = module.build.build_id }
  metadata_directive = "REPLACE"
}

data "aws_iam_policy_document" "web_bucket" {
  statement {
    sid       = "CloudFrontOnly"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.web.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this.arn]
    }
  }
  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.web.arn, "${aws_s3_bucket.web.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "web" {
  bucket     = aws_s3_bucket.web.id
  policy     = data.aws_iam_policy_document.web_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.web]
}

# ── CloudFront ─────────────────────────────────────────────────────────────
resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${var.name_prefix}_s3"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_origin_access_control" "api" {
  name                              = "${var.name_prefix}_api"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_response_headers_policy" "security" {
  name = "${var.name_prefix}_security"
  # Every response is per-user and changes with each deploy: browsers must revalidate, never guess.
  custom_headers_config {
    items {
      header   = "Cache-Control"
      value    = "no-cache"
      override = false # keep the API's and the edge's own no-store
    }
  }
  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'self' vscode-webview: vscode-file:"
      override                = true
    }
  }
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  comment             = "SEC310 demo presenter UI (authenticated)"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  http_version        = "http2and3"

  origin {
    origin_id                = "web"
    domain_name              = aws_s3_bucket.web.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  origin {
    origin_id                = "api"
    domain_name              = trimsuffix(trimprefix(data.aws_ssm_parameter.app["api_function_url"].value, "https://"), "/")
    origin_access_control_id = aws_cloudfront_origin_access_control.api.id
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 60
    }
  }

  default_cache_behavior {
    target_origin_id           = "web"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true
    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.edge.qualified_arn
      include_body = false
    }
  }

  ordered_cache_behavior {
    path_pattern               = "/api/*"
    target_origin_id           = "api"
    viewer_protocol_policy     = "https-only"
    allowed_methods            = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_except_host.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.edge.qualified_arn
      include_body = false
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }
}

# Only this distribution may call the API function URL.
resource "aws_lambda_permission" "cloudfront_url" {
  statement_id           = "cloudfront-oac-url"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = data.aws_ssm_parameter.app["api_function_name"].value
  principal              = "cloudfront.amazonaws.com"
  source_arn             = aws_cloudfront_distribution.this.arn
  function_url_auth_type = "AWS_IAM"
}

resource "aws_lambda_permission" "cloudfront_invoke" {
  statement_id             = "cloudfront-oac-invoke"
  action                   = "lambda:InvokeFunction"
  function_name            = data.aws_ssm_parameter.app["api_function_name"].value
  principal                = "cloudfront.amazonaws.com"
  source_arn               = aws_cloudfront_distribution.this.arn
  invoked_via_function_url = true
}

# ── Managed login branding (AWS + re:Invent 2026 theme) ─────────────────────
resource "aws_cognito_managed_login_branding" "web" {
  user_pool_id = data.aws_ssm_parameter.identity["user_pool_id"].value
  client_id    = aws_cognito_user_pool_client.web.id
  settings     = jsonencode(jsondecode(file("${path.module}/branding/settings.json")))

  # Official AWS logo (reverse) and AWS re:Invent wordmark, from the re:Invent 2026 deck template.
  asset {
    category   = "PAGE_HEADER_LOGO"
    color_mode = "DARK"
    extension  = "SVG"
    bytes      = filebase64("${path.module}/branding/aws-logo.svg")
  }
  asset {
    category   = "FORM_LOGO"
    color_mode = "DARK"
    extension  = "PNG"
    bytes      = filebase64("${path.module}/branding/reinvent-wordmark.png")
  }
  # Smooth crimson → violet → blue field, generated once (same palette as the customer portal hero).
  asset {
    category   = "PAGE_BACKGROUND"
    color_mode = "DARK"
    extension  = "JPEG"
    bytes      = filebase64("${path.module}/branding/page-background.jpg")
  }
}
