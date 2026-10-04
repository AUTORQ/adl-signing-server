locals {
  lambda = contains(["lambda", "both"], var.deployment_mode)
  ec2    = contains(["ec2", "both"], var.deployment_mode)
}

module "core" {
  source = "../../modules/core"

  name                               = var.name
  enable_lambda                      = local.lambda
  enable_ec2                         = local.ec2
  auth_bindings                      = var.auth_bindings
  break_glass_role_arns              = var.break_glass_role_arns
  kms_admin_principal_arns           = var.kms_admin_principal_arns
  client_role_trusted_principal_arns = var.client_role_trusted_principal_arns
  backup_copy_vault_arn              = var.backup_copy_vault_arn
}

module "lambda" {
  source = "../../modules/lambda"
  count  = local.lambda ? 1 : 0

  name            = var.name
  role_arn        = module.core.lambda_role_arn
  role_name       = module.core.lambda_role_name
  package_path    = var.lambda_package_path
  environment     = module.core.server_environment
  domain_name     = var.lambda_domain_name
  certificate_arn = var.lambda_certificate_arn
  log_kms_key_arn = module.core.data_kms_key_arn
}

module "ec2" {
  source = "../../modules/ec2"
  count  = local.ec2 ? 1 : 0

  name                = var.name
  role_name           = module.core.ec2_role_name
  binary_path         = var.ec2_binary_path
  environment         = module.core.server_environment
  vpc_id              = var.vpc_id
  instance_subnet_ids = var.instance_subnet_ids
  alb_subnet_ids      = var.alb_subnet_ids
  internal_alb        = var.internal_alb
  allowed_cidrs       = var.allowed_cidrs
  certificate_arn     = var.ec2_certificate_arn
  log_kms_key_arn     = module.core.data_kms_key_arn
}
