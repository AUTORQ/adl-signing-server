data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  root_arn   = "arn:${local.partition}:iam::${local.account_id}:root"

  kms_admins = length(var.kms_admin_principal_arns) > 0 ? var.kms_admin_principal_arns : [local.root_arn]

  service_role_arns = compact([
    var.enable_lambda ? aws_iam_role.lambda[0].arn : "",
    var.enable_ec2 ? aws_iam_role.ec2[0].arn : "",
  ])

  audience = var.auth_audience != "" ? var.auth_audience : "adl-signing-server:${local.account_id}"

  bucket_name = "${var.name}-archive-${local.account_id}-${local.region}"
  table_name  = "${var.name}-registry"

  tags = merge({ "app" = var.name }, var.tags)
}

# The variable shape mirrors what the server reads from ADL_ENVIRONMENTS.
locals {
  server_environments = [for name, e in var.environments : {
    name               = name
    kms_key_id         = aws_kms_key.ca[name].arn
    device_prefix      = e.device_prefix
    device_id_digits   = e.device_id_digits
    validity_days      = e.validity_days
    allow_key_escrow   = e.allow_key_escrow
    require_chip_id    = e.require_chip_id
    crl_validity_hours = e.crl_validity_hours
  }]

  client_bindings = var.create_client_roles ? [
    {
      roles       = [aws_iam_role.client["developer"].name]
      users       = []
      permissions = ["dev:issue", "dev:read", "dev:key-read"]
    },
    {
      roles       = [aws_iam_role.client["factory-station"].name]
      users       = []
      permissions = ["prod:issue", "prod:read", "prod:provision"]
    },
    {
      roles       = [aws_iam_role.client["ca-admin"].name]
      users       = []
      permissions = ["*"]
    },
  ] : []

  auth_policy = {
    accounts = length(var.auth_allowed_account_ids) > 0 ? var.auth_allowed_account_ids : [local.account_id]
    bindings = concat(local.client_bindings, var.auth_bindings)
  }

  server_environment = {
    ADL_TABLE_NAME        = aws_dynamodb_table.registry.name
    ADL_ARCHIVE_BUCKET    = aws_s3_bucket.archive.bucket
    ADL_DATA_KMS_KEY_ID   = aws_kms_key.data.arn
    ADL_ESCROW_KMS_KEY_ID = aws_kms_key.escrow.arn
    ADL_ENVIRONMENTS      = jsonencode(local.server_environments)
    ADL_AUTH_AUDIENCE     = local.audience
    ADL_AUTH_STS_REGIONS  = join(",", length(var.auth_sts_regions) > 0 ? var.auth_sts_regions : [local.region])
    ADL_AUTH_POLICY       = jsonencode(local.auth_policy)
    ADL_CERT_ORGANIZATION = var.cert_organization
    ADL_LOG_LEVEL         = "info"
  }
}
