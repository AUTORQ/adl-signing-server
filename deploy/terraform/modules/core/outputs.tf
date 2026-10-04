output "server_environment" {
  description = "Environment variables for adl-signer, consumed by the lambda and ec2 modules."
  value       = local.server_environment
}

output "service_policy_arn" {
  value = aws_iam_policy.service.arn
}

output "lambda_role_arn" {
  value = var.enable_lambda ? aws_iam_role.lambda[0].arn : null
}

output "lambda_role_name" {
  value = var.enable_lambda ? aws_iam_role.lambda[0].name : null
}

output "ec2_role_name" {
  value = var.enable_ec2 ? aws_iam_role.ec2[0].name : null
}

output "data_kms_key_arn" {
  value = aws_kms_key.data.arn
}

output "ca_kms_key_arns" {
  value = { for k, v in aws_kms_key.ca : k => v.arn }
}

output "escrow_kms_key_arn" {
  value = aws_kms_key.escrow.arn
}

output "registry_table_name" {
  value = aws_dynamodb_table.registry.name
}

output "archive_bucket" {
  value = aws_s3_bucket.archive.bucket
}

output "auth_audience" {
  value = local.audience
}

output "client_role_arns" {
  value = { for k, v in aws_iam_role.client : k => v.arn }
}

output "region" {
  value = local.region
}
