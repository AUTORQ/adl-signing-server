# Plans the stack against a mocked AWS provider for each deployment mode.
# Plan only: an apply would hit prevent_destroy on teardown, which is the
# point of prevent_destroy. Run with: terraform test

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { insecure_value = "ami-0123456789abcdef0" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mocked" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/mocked" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/mocked" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mocked" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:mocked" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/mocked/1", dns_name = "mocked.elb.amazonaws.com" }
  }
  mock_resource "aws_iam_instance_profile" {
    defaults = { arn = "arn:aws:iam::123456789012:instance-profile/mocked" }
  }
  mock_resource "aws_apigatewayv2_api" {
    defaults = { api_endpoint = "https://abc123.execute-api.us-east-1.amazonaws.com", execution_arn = "arn:aws:execute-api:us-east-1:123456789012:abc123" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { invoke_arn = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/mocked/invocations" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::123456789012:policy/mocked" }
  }
  mock_resource "aws_backup_vault" {
    defaults = { arn = "arn:aws:backup:us-east-1:123456789012:backup-vault:mocked" }
  }
  mock_resource "aws_backup_plan" {
    defaults = { arn = "arn:aws:backup:us-east-1:123456789012:backup-plan:mocked" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/mocked/1" }
  }
  mock_resource "aws_launch_template" {
    defaults = { arn = "arn:aws:ec2:us-east-1:123456789012:launch-template/lt-0123456789abcdef0", id = "lt-0123456789abcdef0", latest_version = 1 }
  }
  mock_resource "aws_security_group" {
    defaults = { arn = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-mocked", id = "sg-0123456789abcdef0" }
  }
  mock_resource "aws_autoscaling_group" {
    defaults = { arn = "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:x:autoScalingGroupName/mocked" }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/mocked/1" }
  }
}

variables {
  lambda_package_path = "tests/fixtures/lambda.zip"
  ec2_binary_path     = "tests/fixtures/adl-signer"
  vpc_id              = "vpc-123"
  instance_subnet_ids = ["subnet-a", "subnet-b"]
  alb_subnet_ids      = ["subnet-c", "subnet-d"]
  ec2_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/mocked"
}

run "lambda_only" {
  command = plan
  variables {
    deployment_mode = "lambda"
  }
  assert {
    condition     = length(module.lambda) == 1 && length(module.ec2) == 0
    error_message = "lambda mode should only create the lambda module"
  }
  assert {
    condition     = length(module.core.ca_kms_key_arns) == 2
    error_message = "expected a CA key for dev and prod"
  }
  assert {
    condition     = jsondecode(module.core.server_environment["ADL_AUTH_POLICY"]).bindings[0].roles[0] == "adl-developer" && !contains(jsondecode(module.core.server_environment["ADL_AUTH_POLICY"]).bindings[0].permissions, "prod:issue")
    error_message = "developer role must be bound to dev permissions only"
  }
  assert {
    condition     = module.core.server_environment["ADL_AUTH_STS_REGIONS"] == "us-east-1"
    error_message = "sts regions should default to the deployment region"
  }
  assert {
    condition     = length(jsondecode(module.core.server_environment["ADL_AUTH_POLICY"]).bindings) == 3
    error_message = "expected bindings for the three client roles"
  }
  assert {
    condition     = module.core.auth_audience == "adl-signing-server:123456789012"
    error_message = "unexpected default audience"
  }
}

run "ec2_only" {
  command = plan
  variables {
    deployment_mode = "ec2"
  }
  assert {
    condition     = length(module.lambda) == 0 && length(module.ec2) == 1
    error_message = "ec2 mode should only create the ec2 module"
  }
}

run "both" {
  command = plan
  variables {
    deployment_mode = "both"
    auth_bindings = [
      { roles = ["AWSReservedSSO_ADLDeveloper_*"], permissions = ["dev:issue", "dev:read", "dev:key-read"] },
    ]
  }
  assert {
    condition     = length(module.lambda) == 1 && length(module.ec2) == 1
    error_message = "both mode should create both"
  }
  assert {
    condition     = length(jsondecode(module.core.server_environment["ADL_AUTH_POLICY"]).bindings) == 4
    error_message = "extra bindings should be appended"
  }
}

run "bad_mode" {
  command = plan
  variables {
    deployment_mode = "kubernetes"
  }
  expect_failures = [var.deployment_mode]
}
