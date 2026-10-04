variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "adl-signer"
}

variable "environments" {
  description = <<-EOT
    Certificate environments. Each gets its own KMS CA key and its own
    intermediate certificate. Environments sharing a device_prefix share the
    device ID counter (dev and prod both used DVTADL on the old droplet).
  EOT
  type = map(object({
    device_prefix      = string
    validity_days      = number
    allow_key_escrow   = bool
    require_chip_id    = optional(bool, false)
    device_id_digits   = optional(number, 3)
    crl_validity_hours = optional(number, 168)
    ca_key_spec        = optional(string, "RSA_4096")
  }))
  default = {
    dev = {
      device_prefix    = "DVTADL"
      validity_days    = 3650
      allow_key_escrow = true
    }
    prod = {
      device_prefix    = "DVTADL"
      validity_days    = 3650
      allow_key_escrow = false
      require_chip_id  = true
    }
  }

  validation {
    condition     = alltrue([for k, v in var.environments : can(regex("^[a-z][a-z0-9-]{0,15}$", k))])
    error_message = "Environment names must be short lowercase identifiers."
  }
  validation {
    condition     = alltrue([for v in values(var.environments) : contains(["RSA_2048", "RSA_3072", "RSA_4096", "ECC_NIST_P256", "ECC_NIST_P384"], v.ca_key_spec)])
    error_message = "ca_key_spec must be an RSA or NIST ECC signing key spec."
  }
}

variable "enable_lambda" {
  description = "Create the execution role for the Lambda deployment."
  type        = bool
  default     = true
}

variable "enable_ec2" {
  description = "Create the instance role for the EC2 deployment."
  type        = bool
  default     = false
}

variable "kms_admin_principal_arns" {
  description = <<-EOT
    Principals allowed to administer (not use) the KMS keys, e.g. the role
    Terraform runs as. Defaults to the account root, which defers to IAM.
  EOT
  type        = list(string)
  default     = []
}

variable "break_glass_role_arns" {
  description = <<-EOT
    Roles that may read escrowed private keys straight from S3 if the service
    itself is down. Keep this list short and alarm on its use.
  EOT
  type        = list(string)
  default     = []
}

variable "auth_audience" {
  description = "Audience string that client tokens are bound to. Defaults to adl-signing-server:<account id>."
  type        = string
  default     = ""
}

variable "auth_sts_regions" {
  description = "Regions clients may sign their STS token for. Defaults to the deployment region."
  type        = list(string)
  default     = []
}

variable "auth_allowed_account_ids" {
  description = "Accounts whose principals may call the service. Defaults to this account."
  type        = list(string)
  default     = []
}

variable "auth_bindings" {
  description = <<-EOT
    Extra role/user to permission bindings, on top of the ones for the client
    roles created here. Role patterns are globs, which is how you bind IAM
    Identity Center permission sets, e.g. "AWSReservedSSO_ADLDeveloper_*".
    Permissions: <env>:issue|read|key-read|provision|revoke, <env>:*,
    ca:admin, audit:read, admin:import, *.
  EOT
  type = list(object({
    roles       = optional(list(string), [])
    users       = optional(list(string), [])
    permissions = list(string)
  }))
  default = []
}

variable "create_client_roles" {
  description = "Create the adl-developer, adl-factory-station and adl-ca-admin roles."
  type        = bool
  default     = true
}

variable "client_role_trusted_principal_arns" {
  description = "Who may assume the client roles. Defaults to this account (i.e. anyone IAM allows)."
  type        = list(string)
  default     = []
}

variable "client_role_require_mfa" {
  description = "Require MFA to assume the developer and CA admin roles."
  type        = bool
  default     = true
}

variable "object_lock_retention_days" {
  description = "Governance-mode Object Lock retention for archived certificates and keys."
  type        = number
  default     = 3650
}

variable "access_log_bucket" {
  description = "Optional bucket name for S3 server access logs of the archive bucket."
  type        = string
  default     = ""
}

variable "enable_backup" {
  description = "Back up the registry table and archive bucket with AWS Backup."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  type    = number
  default = 35
}

variable "backup_copy_vault_arn" {
  description = "Optional vault in another region/account to copy backups to."
  type        = string
  default     = ""
}

variable "cert_organization" {
  description = "O= of issued device certificates."
  type        = string
  default     = "EDGE Labs"
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "tags" {
  type    = map(string)
  default = {}
}
