# What the server itself may do. Note there is no delete anywhere: the
# service only ever adds records and objects.
data "aws_iam_policy_document" "service" {
  statement {
    sid = "Registry"
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
      "dynamodb:Query", "dynamodb:Scan", "dynamodb:ConditionCheckItem",
    ]
    resources = [aws_dynamodb_table.registry.arn, "${aws_dynamodb_table.registry.arn}/index/*"]
  }

  statement {
    sid       = "Archive"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/certificates/*", "${aws_s3_bucket.archive.arn}/escrow/*", "${aws_s3_bucket.archive.arn}/ca/*"]
  }

  statement {
    sid       = "CASign"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = [for k in aws_kms_key.ca : k.arn]
  }

  statement {
    sid       = "DataAndEscrowKeys"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.data.arn, aws_kms_key.escrow.arn]
  }
}

resource "aws_iam_policy" "service" {
  name        = "${var.name}-service"
  description = "Runtime permissions for the ADL signing server"
  policy      = data.aws_iam_policy_document.service.json
  tags        = local.tags
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "lambda" {
  count              = var.enable_lambda ? 1 : 0
  name               = "${var.name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "lambda_service" {
  count      = var.enable_lambda ? 1 : 0
  role       = aws_iam_role.lambda[0].name
  policy_arn = aws_iam_policy.service.arn
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  count              = var.enable_ec2 ? 1 : 0
  name               = "${var.name}-ec2"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ec2_service" {
  count      = var.enable_ec2 ? 1 : 0
  role       = aws_iam_role.ec2[0].name
  policy_arn = aws_iam_policy.service.arn
}

# Client roles. They carry no AWS permissions at all: the only thing a caller
# does with them is sign sts:GetCallerIdentity, which needs none. What they
# can do in the signing service is decided by the auth policy above.
locals {
  client_roles = var.create_client_roles ? {
    "developer"       = { mfa = var.client_role_require_mfa, description = "Mint and recover dev device certificates" }
    "factory-station" = { mfa = false, description = "End-of-line provisioning of production devices" }
    "ca-admin"        = { mfa = var.client_role_require_mfa, description = "CA ceremony, revocation, import, audit" }
  } : {}

  client_trust = length(var.client_role_trusted_principal_arns) > 0 ? var.client_role_trusted_principal_arns : [local.root_arn]
}

data "aws_iam_policy_document" "client_trust" {
  for_each = local.client_roles

  statement {
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = local.client_trust
    }
    dynamic "condition" {
      for_each = each.value.mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "client" {
  for_each             = local.client_roles
  name                 = "adl-${each.key}"
  description          = each.value.description
  assume_role_policy   = data.aws_iam_policy_document.client_trust[each.key].json
  max_session_duration = 3600 * 8
  tags                 = local.tags
}

# AWS Backup
data "aws_iam_policy_document" "backup_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  count              = var.enable_backup ? 1 : 0
  name               = "${var.name}-backup"
  assume_role_policy = data.aws_iam_policy_document.backup_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = var.enable_backup ? toset([
    "service-role/AWSBackupServiceRolePolicyForBackup",
    "service-role/AWSBackupServiceRolePolicyForRestores",
    "AWSBackupServiceRolePolicyForS3Backup",
    "AWSBackupServiceRolePolicyForS3Restore",
  ]) : toset([])
  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/${each.value}"
}
