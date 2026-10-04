# Three kinds of key:
#
#   ca[env]  asymmetric signing keys that ARE the intermediate CAs. Only the
#            service role can Sign. Nobody, including admins, can export them.
#   escrow   wraps escrowed developer private keys in S3. Only the service
#            and break-glass roles can decrypt.
#   data     everything else at rest: DynamoDB, the archive bucket, logs.

locals {
  # Admins can manage keys (rotate policy, schedule deletion, tag) but none
  # of these actions use key material.
  kms_admin_actions = [
    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
    "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
    "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
    "kms:RotateKeyOnDemand",
  ]
}

data "aws_iam_policy_document" "ca_key" {
  statement {
    sid       = "KeyAdministration"
    actions   = local.kms_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.kms_admins
    }
  }

  statement {
    sid       = "ServiceSigns"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.service_role_arns
    }
  }

  # Extra guard: even if someone later adds a broad statement, only the
  # service roles can produce signatures with the CA key.
  statement {
    sid       = "OnlyServiceSigns"
    effect    = "Deny"
    actions   = ["kms:Sign"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = local.service_role_arns
    }
  }
}

resource "aws_kms_key" "ca" {
  for_each = var.environments

  description              = "${var.name} ${each.key} intermediate CA signing key"
  customer_master_key_spec = each.value.ca_key_spec
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.ca_key.json
  tags                     = merge(local.tags, { "adl:env" = each.key, "adl:purpose" = "ca" })

  lifecycle {
    # Destroying this key orphans every certificate the CA ever issued.
    prevent_destroy = true

    precondition {
      condition     = var.enable_lambda || var.enable_ec2
      error_message = "Enable at least one of enable_lambda / enable_ec2, otherwise nothing can use the CA keys."
    }
  }
}

resource "aws_kms_alias" "ca" {
  for_each      = var.environments
  name          = "alias/${var.name}-ca-${each.key}"
  target_key_id = aws_kms_key.ca[each.key].key_id
}

data "aws_iam_policy_document" "escrow_key" {
  statement {
    sid       = "KeyAdministration"
    actions   = local.kms_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.kms_admins
    }
  }

  statement {
    sid       = "ServiceUse"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.service_role_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.escrow_readers_extra) > 0 ? [1] : []
    content {
      sid       = "BreakGlassAndBackupDecrypt"
      actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = local.escrow_readers_extra
      }
    }
  }

  statement {
    sid       = "NobodyElseDecrypts"
    effect    = "Deny"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = concat(local.service_role_arns, local.escrow_readers_extra)
    }
  }
}

locals {
  escrow_readers_extra = concat(
    var.break_glass_role_arns,
    var.enable_backup ? [aws_iam_role.backup[0].arn] : [],
  )
}

resource "aws_kms_key" "escrow" {
  description             = "${var.name} escrowed device private keys"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.escrow_key.json
  tags                    = merge(local.tags, { "adl:purpose" = "escrow" })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "escrow" {
  name          = "alias/${var.name}-escrow"
  target_key_id = aws_kms_key.escrow.key_id
}

data "aws_iam_policy_document" "data_key" {
  # Standard account delegation so IAM policies (service role, backup
  # role) govern use of this key.
  statement {
    sid       = "AccountDelegation"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*${var.name}*"]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${var.name} data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.data_key.json
  tags                    = merge(local.tags, { "adl:purpose" = "data" })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}
