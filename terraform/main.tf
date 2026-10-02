locals {
  lambda_bucket = "lambda-deployments-${var.workload_account_id}"
  resource_url  = "https://${module.api.api_id}.execute-api.${var.region}.amazonaws.com/mcp"
  issuer_url    = "https://${module.api.api_id}.execute-api.${var.region}.amazonaws.com"
}

data "aws_caller_identity" "current" {}

check "workload_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.workload_account_id
    error_message = "Unexpected workload account."
  }
}

resource "aws_kms_key" "oauth" {
  description              = "${var.app_name} OAuth signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "oauth" {
  name          = "alias/${var.app_name}-oauth-${var.environment}"
  target_key_id = aws_kms_key.oauth.key_id
}

resource "aws_dynamodb_table" "oauth_codes" {
  name         = "${var.app_name}-oauth-codes-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }

  deletion_protection_enabled = false
}

resource "aws_iam_role" "lambda_role" {
  name               = "${var.app_name}-lambda-${var.environment}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }] })
}

resource "aws_iam_role_policy" "runtime" {
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = var.jev_secret_arn },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:${var.region}:${var.workload_account_id}:log-group:/aws/lambda/${var.app_name}-mcp-${var.environment}:*" },
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], Resource = aws_dynamodb_table.oauth_codes.arn },
      { Effect = "Allow", Action = ["kms:Sign", "kms:GetPublicKey"], Resource = aws_kms_key.oauth.arn }
      ], var.jev_kms_key_arn == null ? [] : [
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.jev_kms_key_arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com", "kms:EncryptionContext:SecretARN" = var.jev_secret_arn } } }
    ])
  })
  lifecycle {
    precondition {
      condition     = startswith(var.jev_secret_arn, "arn:aws:secretsmanager:${var.region}:${var.workload_account_id}:secret:")
      error_message = "Secret must belong to this workload account and region."
    }
  }
}

module "mcp" {
  source             = "git::https://github.com/josephwegner/family-paas.git//terraform/modules/lambda-function?ref=a59d41e0469d1a1336110fa2d6e46ee07f2eb168"
  function_name      = "mcp"
  app_name           = var.app_name
  environment        = var.environment
  lambda_role_arn    = aws_iam_role.lambda_role.arn
  s3_bucket          = local.lambda_bucket
  s3_key             = "${var.app_name}/${var.environment}/mcp.zip"
  timeout            = 25
  memory_size        = 256
  log_retention_days = 7
  environment_variables = {
    ALLOWED_SUBJECTS    = jsonencode(var.allowed_subjects)
    ALLOWED_ORIGINS     = jsonencode(var.allowed_origins)
    OAUTH_PASSWORD_HASH = var.oauth_password_hash
    OAUTH_KMS_KEY_ID    = aws_kms_key.oauth.arn
    OAUTH_CODE_TABLE    = aws_dynamodb_table.oauth_codes.name
    JEV_SECRET_ARN      = var.jev_secret_arn
    JEV_MODEL           = var.jev_model
  }
}

module "api" {
  source                 = "git::https://github.com/josephwegner/family-paas.git//terraform/modules/api-gateway?ref=a59d41e0469d1a1336110fa2d6e46ee07f2eb168"
  app_name               = var.app_name
  environment            = var.environment
  throttling_rate_limit  = 1
  throttling_burst_limit = 2
  cors_allowed_origins   = var.allowed_origins
  enable_access_logging  = false
  routes = [for route in [
    "ANY /mcp",
    "GET /.well-known/oauth-protected-resource/mcp",
    "GET /.well-known/oauth-authorization-server",
    "GET /.well-known/jwks.json",
    "GET /authorize",
    "POST /authorize",
    "POST /token",
    "POST /revoke",
    ] : {
    route_key     = route
    function_arn  = module.mcp.alias_invoke_arn
    function_name = module.mcp.qualified_arn
  }]
}

output "mcp_url" {
  value = local.resource_url
}

output "issuer_url" {
  value = local.issuer_url
}
