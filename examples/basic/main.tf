# Basic Aurora PostgreSQL Cluster Example

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

# Data sources for existing VPC and subnets
data "aws_vpc" "existing" {
  filter {
    name   = "tag:Name"
    values = ["my-vpc"]
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

module "aurora_postgres_cluster" {
  source = "../../aurorapostgreSQL"

  # Basic Configuration
  name     = "basic-app"
  vpc_id   = data.aws_vpc.existing.id
  vpc_cidr = data.aws_vpc.existing.cidr_block

  # Network Configuration
  aurora_db_subnet_ids    = data.aws_subnets.private.ids
  vpc_endpoint_subnet_ids = data.aws_subnets.private.ids
  lambda_subnet_ids       = data.aws_subnets.private.ids

  # Database Configuration
  db_master_username = "dbadmin"
  database_name      = "appdb"

  # Security Configuration
  allowed_other_ingress_cidrs    = [data.aws_vpc.existing.cidr_block]
  use_existing_kms_key           = false
  existing_kms_key_arn           = null
  use_existing_aurora_db_sg      = false
  use_existing_vpce_sg           = false
  use_existing_lambda_rotator_sg = false

  existing_aurora_db_security_group_ids      = []
  existing_lambda_rotator_security_group_ids = []
  existing_vpce_security_group_ids           = []

  # Secrets Management
  enable_auto_secrets_rotation = true
  rotation_days                = 90

  # Basic Monitoring
  enable_metrics              = true
  enable_comprehensive_alarms = false

  tags = {
    Environment = "development"
    Project     = "basic-app"
    Owner       = "dev-team"
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
