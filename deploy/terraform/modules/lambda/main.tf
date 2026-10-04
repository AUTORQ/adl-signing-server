terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name" {
  type    = string
  default = "adl-signer"
}

variable "role_arn" {
  description = "Execution role from the core module."
  type        = string
}

variable "role_name" {
  type = string
}

variable "package_path" {
  description = "Zip containing the linux/arm64 'bootstrap' binary (make lambda)."
  type        = string
}

variable "environment" {
  description = "server_environment output of the core module."
  type        = map(string)
}

variable "memory_mb" {
  type    = number
  default = 256
}

variable "reserved_concurrency" {
  description = "Hard cap on concurrent executions, which also caps KMS signing rate and cost if something goes wrong."
  type        = number
  default     = 10
}

variable "throttle_rate" {
  description = "Steady-state requests per second allowed through API Gateway."
  type        = number
  default     = 10
}

variable "throttle_burst" {
  type    = number
  default = 20
}

variable "domain_name" {
  description = "Optional custom domain (e.g. signer.example.com). When set the default execute-api endpoint is disabled."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ACM certificate for domain_name, in the same region."
  type        = string
  default     = ""
}

variable "log_kms_key_arn" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "tags" {
  type    = map(string)
  default = {}
}


resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn.arn}:*"]
  }
}

resource "aws_iam_role_policy" "logs" {
  name   = "logs"
  role   = var.role_name
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_lambda_function" "this" {
  function_name                  = var.name
  role                           = var.role_arn
  filename                       = var.package_path
  source_code_hash               = filebase64sha256(var.package_path)
  runtime                        = "provided.al2023"
  handler                        = "bootstrap"
  architectures                  = ["arm64"]
  memory_size                    = var.memory_mb
  timeout                        = 29
  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = var.environment
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.fn.name
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy.logs]
}

resource "aws_apigatewayv2_api" "this" {
  name                         = var.name
  protocol_type                = "HTTP"
  description                  = "ADL device certificate signing"
  disable_execute_api_endpoint = var.domain_name != ""
  tags                         = var.tags
}

resource "aws_apigatewayv2_integration" "this" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.this.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.this.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = var.throttle_rate
    throttling_burst_limit = var.throttle_burst
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      path           = "$context.path"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      latency        = "$context.integrationLatency"
      userAgent      = "$context.identity.userAgent"
    })
  }

  tags = var.tags
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*"
}

resource "aws_apigatewayv2_domain_name" "this" {
  count       = var.domain_name != "" ? 1 : 0
  domain_name = var.domain_name

  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.certificate_arn != ""
      error_message = "certificate_arn is required when domain_name is set."
    }
  }
}

resource "aws_apigatewayv2_api_mapping" "this" {
  count       = var.domain_name != "" ? 1 : 0
  api_id      = aws_apigatewayv2_api.this.id
  domain_name = aws_apigatewayv2_domain_name.this[0].id
  stage       = aws_apigatewayv2_stage.default.id
}

output "url" {
  description = "Base URL for `adl configure --url`."
  value       = var.domain_name != "" ? "https://${var.domain_name}" : aws_apigatewayv2_api.this.api_endpoint
}

output "domain_target" {
  description = "Point a CNAME/alias for domain_name here."
  value       = var.domain_name != "" ? aws_apigatewayv2_domain_name.this[0].domain_name_configuration[0].target_domain_name : null
}

output "function_name" {
  value = aws_lambda_function.this.function_name
}
