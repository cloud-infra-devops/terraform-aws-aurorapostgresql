data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
# Generate a secure initial master password (will be stored in Secrets Manager and used to configure the cluster)
resource "random_password" "master" {
  length           = 24
  override_special = "!@#$%&*()-_=+[]{}<>?"
  special          = true
}
resource "random_id" "id" {
  byte_length = var.byte_length
}
locals {
  kms_key_arn        = var.use_existing_kms_key ? var.existing_kms_key_arn : aws_kms_key.this[0].arn
  cluster_identifier = var.cluster_identifier != null ? var.cluster_identifier : "${var.name}-aurora-pg"
  # Secrets Manager name
  secret_name = var.secret_name != null ? var.secret_name : "${local.cluster_identifier}/master"
  log_types = compact([
    var.enable_error_logs ? "postgresql" : null, # Aurora Postgres error logs written to CloudWatch Logs "postgresql"
    var.enable_slow_query_logs ? "postgresql" : null
  ])
}

# Optionally create a new KMS CMK
resource "aws_kms_key" "this" {
  count                   = var.use_existing_kms_key ? 0 : 1
  description             = "KMS CMK for Aurora PostgreSQL cluster ${local.cluster_identifier}"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true
  # Least privilege: Key policy allows account root and optional roles as needed for RDS, Secrets Manager
  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "aurora-postgres-kms-policy",
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowRDSUseOfTheKey"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDSProxy"
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "rds.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "AllowSecretsManagerUseOfTheKey"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      }
    ]
  })
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-kms" })
}

# Security group for the cluster
resource "aws_security_group" "db" {
  name        = "${local.cluster_identifier}-sg"
  description = "Security group for Aurora PostgreSQL cluster"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${local.cluster_identifier}-db-sg" })
}

# Inbound rules for the DB SG (principle of least privilege: only provided CIDRs/SGs)
resource "aws_security_group_rule" "db_ingress_cidrs" {
  count             = length(var.allowed_cidr_blocks)
  type              = "ingress"
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = [var.allowed_cidr_blocks[count.index]]
  security_group_id = aws_security_group.db.id
}

resource "aws_security_group_rule" "db_ingress_sg" {
  count                    = length(var.allowed_security_group_ids)
  type                     = "ingress"
  from_port                = var.port
  to_port                  = var.port
  protocol                 = "tcp"
  source_security_group_id = var.allowed_security_group_ids[count.index]
  security_group_id        = aws_security_group.db.id
}

# Subnet group
resource "aws_db_subnet_group" "this" {
  name       = "${local.cluster_identifier}-subnet-group"
  subnet_ids = var.subnet_ids
  tags       = merge(var.tags, { Name = "${local.cluster_identifier}-subnet-group" })
}

# Optionally create a CloudWatch Logs group for PostgreSQL logs
resource "aws_cloudwatch_log_group" "postgresql" {
  count             = var.enable_error_logs || var.enable_slow_query_logs ? 1 : 0
  name              = "/aws/rds/cluster/${local.cluster_identifier}/postgresql"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn
  tags              = merge(var.tags, { Name = "${local.cluster_identifier}-postgresql-logs" })
}

# Parameter group for enabling logging parameters for Aurora PostgreSQL
resource "aws_rds_cluster_parameter_group" "this" {
  name        = "${local.cluster_identifier}-pg"
  family      = var.cluster_parameter_family
  description = "Aurora PostgreSQL parameter group for ${local.cluster_identifier}"

  parameter {
    name  = "rds.enable_log_types"
    value = join(",", local.log_types)
  }

  dynamic "parameter" {
    for_each = var.additional_cluster_parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply_method", null)
    }
  }

  tags = merge(var.tags, { Name = "${local.cluster_identifier}-cluster-params" })
}

# Cluster
resource "aws_rds_cluster" "this" {
  cluster_identifier                  = local.cluster_identifier
  engine                              = "aurora-postgresql"
  engine_version                      = var.engine_version
  master_username                     = var.db_master_username
  master_password                     = random_password.master.result
  database_name                       = var.database_name
  port                                = var.port
  db_subnet_group_name                = aws_db_subnet_group.this.name
  vpc_security_group_ids              = concat([aws_security_group.db.id], var.allowed_security_group_ids)
  storage_encrypted                   = true
  kms_key_id                          = local.kms_key_arn
  backup_retention_period             = var.backup_retention_days
  preferred_backup_window             = var.preferred_backup_window
  preferred_maintenance_window        = var.preferred_maintenance_window
  apply_immediately                   = var.apply_immediately
  deletion_protection                 = var.deletion_protection
  copy_tags_to_snapshot               = true
  allow_major_version_upgrade         = var.allow_major_version_upgrade
  enabled_cloudwatch_logs_exports     = var.enable_error_logs || var.enable_slow_query_logs ? ["postgresql"] : []
  iam_database_authentication_enabled = var.iam_database_authentication_enabled
  db_cluster_parameter_group_name     = aws_rds_cluster_parameter_group.this.name
  tags                                = merge(var.tags, { Name = local.cluster_identifier })
}

# Instances
resource "aws_rds_cluster_instance" "this" {
  count                           = var.instance_count
  identifier                      = "${local.cluster_identifier}-${count.index}"
  cluster_identifier              = aws_rds_cluster.this.id
  instance_class                  = var.instance_class
  engine                          = aws_rds_cluster.this.engine
  engine_version                  = aws_rds_cluster.this.engine_version
  publicly_accessible             = var.publicly_accessible
  auto_minor_version_upgrade      = var.auto_minor_version_upgrade
  monitoring_interval             = var.monitoring_interval
  performance_insights_enabled    = var.performance_insights_enabled
  performance_insights_kms_key_id = var.performance_insights_enabled ? local.kms_key_arn : null
  promotion_tier                  = count.index + 1
  apply_immediately               = var.apply_immediately
  tags                            = merge(var.tags, { Name = "${local.cluster_identifier}-${count.index}" })
}

# Secrets Manager secret for DB master credentials (encrypted with KMS)
resource "aws_secretsmanager_secret" "db_master" {
  name        = "${local.secret_name}-${random_id.index.hex}"
  description = "Aurora PostgreSQL master credentials for ${local.cluster_identifier}"
  kms_key_id  = local.kms_key_arn
  tags        = merge(var.tags, { Name = "${local.secret_name}" })
}

# Secret value
resource "aws_secretsmanager_secret_version" "db_master" {
  depends_on = [aws_rds_cluster.this, aws_secretsmanager_secret.db_master]
  secret_id  = aws_secretsmanager_secret.db_master.id
  secret_string = jsonencode({
    username            = var.db_master_username
    password            = random_password.master.result
    engine              = "postgres"
    host                = aws_rds_cluster.this.endpoint
    port                = var.port
    dbname              = var.database_name
    dbClusterIdentifier = aws_rds_cluster.this.id
  })
}

# VPC endpoint for Secrets Manager to keep rotation traffic inside VPC
resource "aws_security_group" "vpce" {
  name        = "${local.cluster_identifier}-secretsmanager-vpce-sg"
  description = "SG for Secrets Manager VPC endpoint interface"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${local.cluster_identifier}-vpce-sg" })
}

resource "aws_security_group_rule" "vpce_ingress" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.db.id
  security_group_id        = aws_security_group.vpce.id
}

resource "aws_security_group_rule" "vpce_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.vpce.id
}

# data "aws_vpc_endpoint_service" "secretsmanager" {
#   service = "com.amazonaws.${data.aws_region.current.region}.secretsmanager"
# }

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id = var.vpc_id
  # service_name        = data.aws_vpc_endpoint_service.secretsmanager.service_name
  service_name        = "com.amazonaws.${data.aws_region.current.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.vpc_endpoint_subnet_ids
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true
  tags                = merge(var.tags, { Name = "${local.cluster_identifier}-sm-vpce" })
}

# IAM role used by Secrets Manager rotation function (least privilege)
resource "aws_iam_role" "rotation" {
  name = "${local.cluster_identifier}-secret-rotation-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-rotation-role" })
}

# Managed policy attachments and a minimal inline policy restricted to the secret and cluster
resource "aws_iam_role_policy" "rotation_inline" {
  name = "${local.cluster_identifier}-rotation-inline"
  role = aws_iam_role.rotation.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowSecretAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = aws_secretsmanager_secret.db_master.arn
      },
      {
        Sid    = "AllowKMSForSecret"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = local.kms_key_arn
      },
      {
        Sid    = "AllowRDSPasswordUpdate"
        Effect = "Allow"
        Action = [
          "rds:ModifyDBCluster",
          "rds:DescribeDBClusters"
        ]
        Resource = aws_rds_cluster.this.arn
      },
      {
        Sid    = "AllowNetworkingToSecretsManager"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_security_group" "rotator_lambda_security_group" {
  name   = "rotator_lambda_security_group"
  vpc_id = var.vpc_id

  tags = {
    Name = "rotator_lambda_security_group"
  }
}

resource "aws_security_group_rule" "lambda_security_group_egress_rule1" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rotator_lambda_security_group.id
}

resource "aws_security_group_rule" "lambda_security_group_egress_rule2" {
  type              = "egress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rotator_lambda_security_group.id
}

resource "aws_security_group_rule" "lambda_security_group_ingress_rule" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rotator_lambda_security_group.id
}

resource "random_id" "index" {
  byte_length = 2
}

locals {
  # region -> AWS account IDs that host the AWS-managed Secrets Manager rotation functions
  # This mapping is used to construct the ARN for the single-user RDS PostgreSQL rotation function:
  # SecretsManagerRDSPostgreSQLRotationSingleUser
  # Source: AWS Secrets Manager rotation function templates (AWS docs) / community references.
  aws_rotation_accounts = {
    "us-east-1"      = "297356227824"
    "us-east-2"      = "272243774136"
    "us-west-1"      = "074427151427"
    "us-west-2"      = "679388152427"
    "af-south-1"     = "837727923574"
    "ap-east-1"      = "568494199844"
    "ap-south-1"     = "980640731160"
    "ap-northeast-1" = "249141392436"
    "ap-northeast-2" = "819880672187"
    "ap-northeast-3" = "075579246818"
    "ap-southeast-1" = "718646579143"
    "ap-southeast-2" = "568782711913"
    "ca-central-1"   = "680589152509"
    "eu-central-1"   = "537616424511"
    "eu-west-1"      = "985815780053"
    "eu-west-2"      = "434816350285"
    "eu-west-3"      = "644151839549"
    "eu-north-1"     = "365925373257"
    "eu-south-1"     = "054676820928"
    "me-south-1"     = "772402452960"
    "sa-east-1"      = "856723963003"
  }
}

resource "aws_serverlessapplicationrepository_cloudformation_stack" "secrets_rotator" {
  name           = "Rotator-${random_id.id.hex}"
  application_id = "arn:aws:serverlessrepo:${data.aws_region.current.region}:${local.aws_rotation_accounts[data.aws_region.current.region]}:applications/SecretsManagerRDSPostgreSQLRotationSingleUser"
  # application_id = "arn:aws:serverlessrepo:${data.aws_region.current.region}:297356227824:applications/SecretsManagerRDSPostgreSQLRotationSingleUser"
  capabilities = [
    "CAPABILITY_IAM",
    "CAPABILITY_RESOURCE_POLICY",
  ]
  parameters = {
    functionName        = "LambdaRotator-${random_id.id.hex}"
    endpoint            = "https://secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
    secretArn           = aws_secretsmanager_secret.db_master.arn
    vpcSubnetIds        = join(",", var.vpc_endpoint_subnet_ids)
    vpcSecurityGroupIds = aws_security_group.rotator_lambda_security_group.id
  }
}

# If user wants manual rotation only, set enable_auto_secrets_rotation=false and they can trigger rotation manually in console/CLI.
# Rotation using AWS managed single-user rotation Lambda function
resource "aws_secretsmanager_secret_rotation" "this" {
  depends_on = [aws_secretsmanager_secret_version.db_master]
  count      = var.enable_auto_secrets_rotation ? 1 : 0
  secret_id  = aws_secretsmanager_secret.db_master.id
  # rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotation_lambda_arn = aws_serverlessapplicationrepository_cloudformation_stack.secrets_rotator.outputs.RotationLambdaARN
  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# # AWS managed single-user rotation Lambda function code via Lambda ARN or deploying from AWS provided blueprint
# # Here we use the AWS managed rotation function hosted as a Lambda in your account via a published blueprint package.
# # For portability, we deploy a minimal lambda with VPC config, using container image or zip from AWS sample S3.
# resource "aws_iam_role" "lambda_exec" {
#   name = "${local.cluster_identifier}-lambda-exec-role"
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [{
#       Effect    = "Allow",
#       Principal = { Service = "lambda.amazonaws.com" },
#       Action    = "sts:AssumeRole"
#     }]
#   })
#   tags = merge(var.tags, { Name = "${local.cluster_identifier}-lambda-exec" })
# }

# resource "aws_iam_role_policy_attachment" "lambda_basic" {
#   role       = aws_iam_role.lambda_exec.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
# }

# # Allow Lambda access to VPC for Secrets Manager VPCE
# resource "aws_iam_role_policy" "lambda_vpc" {
#   name = "${local.cluster_identifier}-lambda-vpc"
#   role = aws_iam_role.lambda_exec.id
#   policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Action = [
#           "ec2:CreateNetworkInterface",
#           "ec2:DescribeNetworkInterfaces",
#           "ec2:DeleteNetworkInterface"
#         ],
#         Resource = "*"
#       }
#     ]
#   })
# }

# # Minimal lambda function stub; in practice use AWS sample for single-user rotation from Secrets Manager docs.
# resource "aws_lambda_function" "rotation" {
#   function_name    = "${local.cluster_identifier}-rotation"
#   role             = aws_iam_role.lambda_exec.arn
#   runtime          = "python3.12"
#   handler          = "lambda_function.lambda_handler"
#   filename         = var.rotation_lambda_zip
#   source_code_hash = filebase64sha256(var.rotation_lambda_zip)
#   timeout          = 900
#   memory_size      = 256

#   vpc_config {
#     subnet_ids         = var.lambda_subnet_ids
#     security_group_ids = [aws_security_group.db.id]
#   }

#   environment {
#     variables = {
#       SECRET_ARN      = aws_secretsmanager_secret.db_master.arn
#       RDS_CLUSTER_ARN = aws_rds_cluster.this.arn
#       KMS_KEY_ARN     = local.kms_key_arn
#       DB_ENGINE       = "postgres"
#       VPC_ENDPOINT_SM = aws_vpc_endpoint.secretsmanager.id
#     }
#   }

#   depends_on = [aws_vpc_endpoint.secretsmanager]
#   tags       = merge(var.tags, { Name = "${local.cluster_identifier}-rotation-lambda" })
# }

# Resource policy for the secret limiting access to rotation role and account root
resource "aws_secretsmanager_secret_policy" "secret_policy" {
  secret_arn = aws_secretsmanager_secret.db_master.arn
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowRotationRoleAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.rotation.arn
        }
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = aws_secretsmanager_secret.db_master.arn
      },
      {
        Sid    = "AllowAccountAdminRead"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.db_master.arn
      }
    ]
  })
}

# CloudWatch metrics and alarms examples (optional)
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count               = var.enable_metrics ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-CPUUtilization-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = var.cpu_high_threshold
  alarm_description   = "High CPU utilization on Aurora PG cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

# Optional: publish slow query/error metrics via Logs Insights -> Metric Filters
resource "aws_cloudwatch_log_metric_filter" "slow_query" {
  count          = var.enable_slow_query_metrics && (var.enable_error_logs || var.enable_slow_query_logs) ? 1 : 0
  name           = "${local.cluster_identifier}-slow-query"
  log_group_name = aws_cloudwatch_log_group.postgresql[0].name
  pattern        = var.slow_query_filter_pattern
  metric_transformation {
    name      = "${local.cluster_identifier}-SlowQueryCount"
    namespace = "Custom/AuroraPostgres"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "slow_query_alarm" {
  count               = var.enable_slow_query_metrics && (var.enable_error_logs || var.enable_slow_query_logs) ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-SlowQuery-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "${local.cluster_identifier}-SlowQueryCount"
  namespace           = "Custom/AuroraPostgres"
  period              = 300
  statistic           = "Sum"
  threshold           = var.slow_query_threshold
  alarm_actions       = var.alarm_action_arns
  ok_actions          = var.ok_action_arns
  tags                = var.tags
}
