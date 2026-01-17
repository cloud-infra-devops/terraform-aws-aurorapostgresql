terraform {
  required_version = ">= 1.14.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.28.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
  }
  cloud {
    organization = "cloud-infra-dev"
    workspaces {
      name    = "testing-terraform-aws-modules" # Workspace with VCS driven workflow
      project = "AWS-Cloud-IaC"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  # allowed_account_ids = ["211125325120"]
}

module "aurora_postgres_cluster" {
  source                                     = "./aurorapostgreSQL"
  name                                       = "duke-app"
  vpc_id                                     = "vpc-07b3e9e8021bfb088"
  vpc_cidr                                   = "172.16.0.0/16"
  allowed_other_ingress_cidrs                = ["10.0.0.0/8", "192.168.0.0/16"]
  use_existing_aurora_db_sg                  = false
  use_existing_lambda_rotator_sg             = false
  use_existing_vpce_sg                       = false
  existing_aurora_db_security_group_ids      = []
  existing_lambda_rotator_security_group_ids = []
  existing_vpce_security_group_ids           = []
  aurora_db_subnet_ids                       = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  vpc_endpoint_subnet_ids                    = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  lambda_subnet_ids                          = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  db_master_username                         = "postgreSQLdbAdmin"
  enable_auto_secrets_rotation               = true
  rotation_days                              = 90
  use_existing_kms_key                       = false
  existing_kms_key_arn                       = null
  instance_count                             = 2
  instance_class                             = "db.r6g.large"
  backup_retention_days                      = 7
  deletion_protection                        = true
  skip_final_snapshot                        = false
  enable_metrics                             = true
  enable_comprehensive_alarms                = true
  tags = {
    Environment = "production"
    Owner       = "cloud-infra-devops"
    Project     = "aurora-postgresql"
    Region      = "us-east-1"
  }
}

# Additional CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "aurora_dashboard" {
  dashboard_name = "Aurora-PostgreSQL-${module.aurora_postgres_cluster.cluster_arn}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBClusterIdentifier", module.aurora_postgres_cluster.cluster_arn],
            [".", "DatabaseConnections", ".", "."],
            [".", "FreeableMemory", ".", "."],
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Aurora PostgreSQL Performance Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Outputs
output "cluster_arn" {
  description = "Aurora PostgreSQL cluster ARN"
  value       = module.aurora_postgres_cluster.cluster_arn
}

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

output "kms_key_arn" {
  description = "KMS key ARN used for encryption"
  value       = module.aurora_postgres_cluster.kms_key_arn
}

# output "sns_topic_arn" {
#   description = "SNS topic ARN for alerts"
#   value       = module.aurora_postgres_cluster.alerts.arn
# }
