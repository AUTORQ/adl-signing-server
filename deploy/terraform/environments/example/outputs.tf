output "lambda_url" {
  value = local.lambda ? module.lambda[0].url : null
}

output "ec2_url" {
  value = local.ec2 ? module.ec2[0].url : null
}

output "auth_audience" {
  value = module.core.auth_audience
}

output "client_role_arns" {
  value = module.core.client_role_arns
}

output "ca_kms_key_arns" {
  value = module.core.ca_kms_key_arns
}

output "archive_bucket" {
  value = module.core.archive_bucket
}

output "cli_configure" {
  description = "What developers and stations run once (add --profile for their AWS profile)."
  value = format("adl configure --url %s --region %s --audience %s",
    local.lambda ? module.lambda[0].url : module.ec2[0].url,
    module.core.region,
  module.core.auth_audience)
}
