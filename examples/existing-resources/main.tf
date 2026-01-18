# Aurora PostgreSQL with Existing Resources Example
# Using existing KMS keys and security groups

terraform {
  required_version = ">= 1.14.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.28"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Data sources for existing resources
data "aws_vpc" "existing" {
  filter {
    name   = "tag:Name"
    values = ["existing-vpc"]
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.existing.id]
  }
  filter {
    name   = "tag:Type"
    values = ["private"]
  }
}

data "aws_kms_key" "existing" {
  key_id = "alias/existing-aurora-key"
}

data "aws_security_group" "existing_db" {
  filter {
    name   = "tag:Name"
    values = ["existing-db-sg"]
  }
}

data "aws_security_group" "existing_vpce" {
  filter {
    name   = "tag:Name"
    values = ["existing-vpce-sg"]
  }
}

data "aws_security_group" "existing_lambda" {
  filter {
    name   = "tag:Name"
    values = ["existing-lambda-sg"]
  }
}

module "aurora_postgres_cluster" {
  source = "../../aurorapostgreSQL"

  # Basic Configuration
  name     = "existing-resources-app"
  vpc_id   = data.aws_vpc.existing.id
  vpc_cidr = data.aws_vpc.existing.cidr_block

  # Network Configuration
  aurora_db_subnet_ids    = data.aws_subnets.private.ids
  vpc_endpoint_subnet_ids = data.aws_subnets.private.ids
  lambda_subnet_ids       = data.aws_subnets.private.ids

  # Database Configuration
  db_master_username = "dbadmin"
  database_name      = "appdb"

  # Security Configuration - Using Existing Resources
  allowed_other_ingress_cidrs = [] # Using security groups instead
  use_existing_kms_key        = true
  existing_kms_key_arn        = data.aws_kms_key.existing.arn

  use_existing_aurora_db_sg      = true
  use_existing_vpce_sg           = true
  use_existing_lambda_rotator_sg = true

  existing_aurora_db_security_group_ids      = [data.aws_security_group.existing_db.id]
  existing_lambda_rotator_security_group_ids = [data.aws_security_group.existing_lambda.id]
  existing_vpce_security_group_ids           = [data.aws_security_group.existing_vpce.id]

  # Secrets Management
  enable_auto_secrets_rotation = true
  rotation_days                = 90

  # Monitoring
  enable_metrics              = true
  enable_comprehensive_alarms = true

  tags = {
    Environment = "staging"
    Project     = "existing-resources-app"
    Owner       = "platform-team"
  }
}

# Outputs
output "cluster_endpoint" {
  description = "Aurora PostgreSQL cluster writer endpoint"
  value       = module.aurora_postgres_cluster.cluster_endpoint
}

output "reader_endpoint" {
  description = "Aurora PostgreSQL cluster reader endpoint"
  value       = module.aurora_postgres_cluster.reader_endpoint
}

output "secret_arn" {
  description = "Secrets Manager secret ARN"
  value       = module.aurora_postgres_cluster.secret_arn
  sensitive   = true
}

output "existing_kms_key_arn" {
  description = "Existing KMS key ARN used"
  value       = data.aws_kms_key.existing.arn
}
