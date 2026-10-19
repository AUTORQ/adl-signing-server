variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environments" {
  description = "Certificate environments; see modules/core for the attributes."
  type        = any
}

variable "cert_organization" {
  description = "O= of issued device certificates, e.g. your company name."
  type        = string
}

variable "name" {
  type    = string
  default = "adl-signer"
}

variable "deployment_mode" {
  description = "lambda, ec2, or both. Both share the same keys, registry and archive."
  type        = string
  default     = "lambda"
  validation {
    condition     = contains(["lambda", "ec2", "both"], var.deployment_mode)
    error_message = "deployment_mode must be lambda, ec2 or both."
  }
}

variable "auth_bindings" {
  description = "Extra identity bindings, e.g. IAM Identity Center permission sets. See modules/core."
  type = list(object({
    roles       = optional(list(string), [])
    users       = optional(list(string), [])
    permissions = list(string)
  }))
  default = []
}

variable "break_glass_role_arns" {
  type    = list(string)
  default = []
}

variable "kms_admin_principal_arns" {
  type    = list(string)
  default = []
}

variable "create_client_roles" {
  type    = bool
  default = false
}

variable "client_role_trusted_principal_arns" {
  type    = list(string)
  default = []
}

variable "factory_station_trust_anchor_arns" {
  type    = list(string)
  default = []
}

variable "enable_ssm_session_access" {
  type    = bool
  default = false
}

variable "backup_copy_vault_arn" {
  type    = string
  default = ""
}

# Lambda
variable "lambda_package_path" {
  type    = string
  default = "../../../../dist/adl-signer-lambda.zip"
}

variable "lambda_domain_name" {
  type    = string
  default = ""
}

variable "lambda_certificate_arn" {
  type    = string
  default = ""
}

# EC2
variable "ec2_binary_path" {
  type    = string
  default = "../../../../dist/adl-signer-linux-arm64"
}

variable "vpc_id" {
  type    = string
  default = ""
}

variable "instance_subnet_ids" {
  type    = list(string)
  default = []
}

variable "alb_subnet_ids" {
  type    = list(string)
  default = []
}

variable "internal_alb" {
  type    = bool
  default = false
}

variable "allowed_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "ec2_certificate_arn" {
  type    = string
  default = ""
}
