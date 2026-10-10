variable "workload_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.workload_account_id))
    error_message = "Supply the workload account ID."
  }
}
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "app_name" {
  type    = string
  default = "jev-mcp"
}
variable "environment" {
  type    = string
  default = "prod"
}
variable "allowed_subjects" {
  type = list(string)
  validation {
    condition     = length(var.allowed_subjects) > 0 && alltrue([for s in var.allowed_subjects : length(s) > 0 && length(s) <= 128])
    error_message = "Explicit authorized usernames are required."
  }
}
variable "allowed_origins" {
  type    = list(string)
  default = []
  validation {
    condition     = alltrue([for o in var.allowed_origins : can(regex("^https://[^/]+$", o))])
    error_message = "Use explicit HTTPS origins; no wildcard."
  }
}
variable "oauth_password_hash" {
  description = "SHA-256 hex digest of the single operator login password. Generate with: printf '%s' 'password' | shasum -a 256"
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.oauth_password_hash))
    error_message = "Supply a 64-character lowercase SHA-256 hex digest."
  }
}
variable "jev_secret_arn" {
  description = "Existing workload-local Secrets Manager ARN; raw SecretString is populated by the user outside Terraform."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[^*?]+$", var.jev_secret_arn))
    error_message = "Supply one exact Secrets Manager secret ARN."
  }
}
variable "jev_kms_key_arn" {
  description = "Optional customer-managed key for this secret only; null for the AWS managed key."
  type        = string
  default     = null
}
variable "jev_model" {
  type    = string
  default = "jev-latest"
}
