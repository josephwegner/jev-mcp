locals {
  lambda_bucket = "lambda-deployments-${var.workload_account_id}"
  # Used only as an output; Lambda derives its resource from trusted requestContext.
  resource_url = "https://${module.api.api_id}.execute-api.${var.region}.amazonaws.com/mcp"
}

data "aws_caller_identity" "current" {}

check "workload_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.workload_account_id
    error_message = "Unexpected workload account."
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "${var.app_name}-lambda-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "runtime" {
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = var.jev_secret_arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.workload_account_id}:log-group:/aws/lambda/${var.app_name}-mcp-${var.environment}:*"
      }
      ], var.jev_kms_key_arn == null ? [] : [
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.jev_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
            "kms:EncryptionContext:SecretARN" = var.jev_secret_arn
          }
        }
      }
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
    OAUTH_ISSUER     = var.oauth_issuer
    OAUTH_JWKS_URL   = var.oauth_jwks_url
    ALLOWED_SUBJECTS = jsonencode(var.allowed_subjects)
    ALLOWED_ORIGINS  = jsonencode(var.allowed_origins)
    JEV_SECRET_ARN   = var.jev_secret_arn
    JEV_MODEL        = var.jev_model
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
  # Authentication is enforced in Lambda BEFORE MCP discovery or inference.
  # Gateway JWT errors cannot supply the required RFC 9728 challenge header.
  routes = [for route in ["ANY /mcp", "GET /.well-known/oauth-protected-resource/mcp"] : {
    route_key     = route
    function_arn  = module.mcp.alias_invoke_arn
    function_name = module.mcp.qualified_arn
  }]
}

output "mcp_url" {
  value = local.resource_url
}
