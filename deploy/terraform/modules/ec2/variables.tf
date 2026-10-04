variable "name" {
  type    = string
  default = "adl-signer"
}

variable "role_name" {
  description = "Instance role from the core module (ec2_role_name)."
  type        = string
}

variable "binary_path" {
  description = "Local path to the linux/arm64 adl-signer binary (make ec2)."
  type        = string
}

variable "environment" {
  description = "server_environment output of the core module."
  type        = map(string)
}

variable "vpc_id" {
  type = string
}

variable "instance_subnet_ids" {
  description = "Private subnets for the instances. They need outbound HTTPS (NAT or VPC endpoints for STS, KMS, DynamoDB, S3, SSM, logs)."
  type        = list(string)
}

variable "alb_subnet_ids" {
  description = "Subnets for the load balancer (public subnets unless internal_alb is true)."
  type        = list(string)
}

variable "internal_alb" {
  description = "Only reachable from inside the VPC / over VPN. Recommended when the factory and office have a VPN into the VPC."
  type        = bool
  default     = false
}

variable "allowed_cidrs" {
  description = "Who can reach the load balancer on 443. Lock this to office/factory egress IPs where possible."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "certificate_arn" {
  description = "ACM certificate for the load balancer listener."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "instance_count" {
  description = "Instances behind the load balancer. Two spreads across AZs; the service is stateless."
  type        = number
  default     = 2
}

variable "enable_waf" {
  description = "Attach a WAF web ACL with a per-IP rate limit and AWS bad-input rules."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Requests per 5 minutes per source IP."
  type        = number
  default     = 600
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

variable "enable_ssm_session_access" {
  description = <<-EOT
    Attach AmazonSSMManagedInstanceCore so admins can open a shell with
    Session Manager. Off by default: a shell on the instance is a shell
    holding the role that can sign with the CA keys. Turn on temporarily
    for debugging and restrict ssm:StartSession to a break-glass role.
  EOT
  type        = bool
  default     = false
}
