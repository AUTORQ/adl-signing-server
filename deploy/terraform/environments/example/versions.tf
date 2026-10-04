terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Keep state somewhere durable and locked. Fill in and uncomment:
  # backend "s3" {
  #   bucket       = "autorq-terraform-state"
  #   key          = "adl-signing-server/prod.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      app       = "adl-signing-server"
      managedby = "terraform"
    }
  }
}
