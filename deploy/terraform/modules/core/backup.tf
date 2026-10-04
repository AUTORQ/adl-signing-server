resource "aws_backup_vault" "this" {
  count       = var.enable_backup ? 1 : 0
  name        = "${var.name}-vault"
  kms_key_arn = aws_kms_key.data.arn
  tags        = local.tags
}

resource "aws_backup_plan" "this" {
  count = var.enable_backup ? 1 : 0
  name  = "${var.name}-daily"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this[0].name
    schedule          = "cron(0 5 * * ? *)"

    lifecycle {
      delete_after = var.backup_retention_days
    }

    dynamic "copy_action" {
      for_each = var.backup_copy_vault_arn != "" ? [1] : []
      content {
        destination_vault_arn = var.backup_copy_vault_arn
        lifecycle {
          delete_after = var.backup_retention_days
        }
      }
    }
  }

  tags = local.tags
}

resource "aws_backup_selection" "this" {
  count        = var.enable_backup ? 1 : 0
  name         = "${var.name}-registry-and-archive"
  plan_id      = aws_backup_plan.this[0].id
  iam_role_arn = aws_iam_role.backup[0].arn
  resources    = [aws_dynamodb_table.registry.arn, aws_s3_bucket.archive.arn]
}
