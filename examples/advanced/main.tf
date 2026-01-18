# Advanced Aurora PostgreSQL Cluster Example
# Production-ready configuration with all features enabled

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

# SNS Topic for CloudWatch Alarms
resource "aws_sns_topic" "alerts" {
  name = "aurora-postgres-alerts"

  tags = {
    Environment = "production"
    Project     = "advanced-app"
  }
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "pratik.das@duke-energy.com"
}

# Data sources for existing VPC and subnets
data "aws_vpc" "existing" {
  filter {
    name   = "tag:Name"
    values = ["production-vpc"]
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
  name               = "production-app"
  cluster_identifier = "prod-app-aurora-pg"
  vpc_id             = data.aws_vpc.existing.id
  vpc_cidr           = data.aws_vpc.existing.cidr_block

  # Network Configuration
  aurora_db_subnet_ids    = data.aws_subnets.private.ids
  vpc_endpoint_subnet_ids = data.aws_subnets.private.ids
  lambda_subnet_ids       = data.aws_subnets.private.ids

  # Database Configuration
  db_master_username = "dbadmin"
  database_name      = "proddb"
  port               = 5432
  engine_version     = "17.7"
  instance_class     = "db.r6g.xlarge"
  instance_count     = 3 # 1 writer + 2 readers

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

  # Backup Configuration
  backup_retention_days        = 30
  preferred_backup_window      = "03:00-04:00"
  preferred_maintenance_window = "sun:06:00-sun:11:00"
  skip_final_snapshot          = false
  deletion_protection          = true

  # Monitoring Configuration
  enable_metrics              = true
  enable_comprehensive_alarms = true
  enable_error_logs           = true
  enable_slow_query_logs      = true
  log_retention_days          = 30

  # Performance Configuration
  performance_insights_enabled        = true
  monitoring_interval                 = 60
  iam_database_authentication_enabled = true

  # Alarm Configuration
  alarm_action_arns = [aws_sns_topic.alerts.arn]
  ok_action_arns    = [aws_sns_topic.alerts.arn]

  # Custom Alarm Thresholds
  cpu_high_threshold               = 75
  memory_freeable_threshold        = 2147483648 # 2GB
  database_connections_threshold   = 100
  read_latency_threshold           = 0.15
  write_latency_threshold          = 0.15
  deadlock_threshold               = 3
  replica_lag_threshold            = 10
  buffer_cache_hit_ratio_threshold = 98
  disk_queue_depth_threshold       = 32
  swap_usage_threshold             = 134217728 # 128MB

  # Slow Query Monitoring
  enable_slow_query_metrics = true
  slow_query_threshold      = 50

  tags = {
    Environment = "production"
    Project     = "advanced-app"
    Owner       = "platform-team"
    Backup      = "required"
    Monitoring  = "critical"
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

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = aws_sns_topic.alerts.arn
}
