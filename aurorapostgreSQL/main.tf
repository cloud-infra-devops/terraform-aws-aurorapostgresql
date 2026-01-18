# ----------- Security Groups ------------ #
# Security group for the Aurora DB cluster
resource "aws_security_group" "db" {
  name        = "${local.cluster_identifier}-sg"
  description = "Security group for Aurora PostgreSQL cluster"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${local.cluster_identifier}-db-sg" })

  dynamic "ingress" {
    for_each = distinct(compact(var.allowed_other_ingress_cidrs))
    content {
      description = "DB access from allowed other ingress CIDRs-(${ingress.value})"
      from_port   = var.port
      to_port     = var.port
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }
  dynamic "ingress" {
    for_each = distinct(compact(var.existing_aurora_db_security_group_ids))
    content {
      description     = "DB access from allowed existing SG-(${ingress.value})"
      from_port       = var.port
      to_port         = var.port
      protocol        = "tcp"
      security_groups = [ingress.value]
    }
  }
  # Restrict egress to only necessary traffic
  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    description = "DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }
}

# Security group for the VPC Interface Endpoint
resource "aws_security_group" "vpce" {
  depends_on  = [aws_security_group.db]
  name        = "${local.cluster_identifier}-secretsmanager-vpce-sg"
  description = "SG for Secrets Manager VPC endpoint interface"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${local.cluster_identifier}-vpce-sg" })
}

resource "aws_security_group_rule" "vpce_ingress" {
  type                     = "ingress"
  description              = "HTTPS from Lambda and DB security groups"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.db.id
  security_group_id        = aws_security_group.vpce.id
}

resource "aws_security_group_rule" "vpce_ingress_lambda" {
  type                     = "ingress"
  description              = "HTTPS from Lambda rotator"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rotator_lambda_security_group.id
  security_group_id        = aws_security_group.vpce.id
}

resource "aws_security_group_rule" "vpce_egress" {
  type              = "egress"
  description       = "All outbound traffic"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.vpce.id
}

# Security group for the Rotator Lambda Function
resource "aws_security_group" "rotator_lambda_security_group" {
  name        = "${local.cluster_identifier}-rotator-lambda-sg"
  description = "Security group for Lambda rotation function"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${local.cluster_identifier}-rotator-lambda-sg" })
}

resource "aws_security_group_rule" "lambda_security_group_egress_https" {
  type              = "egress"
  description       = "HTTPS to VPC endpoints"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rotator_lambda_security_group.id
}

resource "aws_security_group_rule" "lambda_security_group_egress_postgres" {
  type              = "egress"
  description       = "PostgreSQL to Aurora cluster"
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rotator_lambda_security_group.id
}

resource "aws_security_group_rule" "lambda_security_group_egress_dns" {
  type              = "egress"
  description       = "DNS resolution"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rotator_lambda_security_group.id
}

# Allow Lambda to connect to Aurora DB
resource "aws_security_group_rule" "db_ingress_from_lambda" {
  type                     = "ingress"
  description              = "PostgreSQL from Lambda rotator"
  from_port                = var.port
  to_port                  = var.port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rotator_lambda_security_group.id
  security_group_id        = aws_security_group.db.id
}

# Optionally create a new KMS CMK
resource "aws_kms_key" "this" {
  count                   = var.use_existing_kms_key ? 0 : 1
  description             = "KMS CMK for Aurora PostgreSQL cluster ${local.cluster_identifier}"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true

  # Corrected key policy: use service principals, not account SLR ARNs
  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "aurora-postgres-kms-policy",
    Statement = [
      {
        Sid       = "EnableRootPermissions",
        Effect    = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = "kms:*",
        Resource  = "*"
      },
      {
        Sid       = "AllowRDSUseOfTheKey",
        Effect    = "Allow",
        Principal = { Service = "rds.amazonaws.com" },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "kms:ViaService" = "rds.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "AllowSecretsManagerUseOfTheKey",
        Effect    = "Allow",
        Principal = { Service = "secretsmanager.amazonaws.com" },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "AllowCloudWatchLogsUseOfTheKey",
        Effect    = "Allow",
        Principal = { Service = "logs.amazonaws.com" },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "kms:ViaService" = "logs.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "AllowLambdaUseOfTheKey",
        Effect    = "Allow",
        Principal = { Service = "lambda.amazonaws.com" },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
          "kms:ReEncrypt*"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "kms:ViaService" = "lambda.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      }
    ]
  })
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-kms" })
}

# Generate password that excludes '/', '@', '\"', and space
resource "random_password" "db_master" {
  count            = var.db_master_password == null && var.generate_master_password ? 1 : 0
  length           = var.generated_password_length
  special          = true
  override_special = "!#$%&()*+,-.:;<=>?[\\]^_{|}~" # excludes / @ " and includes allowed specials
}

# Optionally create a CloudWatch Logs group for PostgreSQL logs
resource "aws_cloudwatch_log_group" "postgresql" {
  count             = var.enable_error_logs || var.enable_slow_query_logs ? 1 : 0
  name              = "/aws/rds/cluster/${local.cluster_identifier}/postgresql"
  retention_in_days = var.log_retention_days
  tags              = merge(var.tags, { Name = "${local.cluster_identifier}-postgresql-logs" })
}

# Subnet group
resource "aws_db_subnet_group" "this" {
  name       = "${local.cluster_identifier}-subnet-group"
  subnet_ids = var.aurora_db_subnet_ids
  tags       = merge(var.tags, { Name = "${local.cluster_identifier}-subnet-group" })
}

resource "aws_rds_cluster_parameter_group" "this" {
  name        = local.cluster_identifier
  family      = local.cluster_parameter_family_effective
  description = "Aurora PostgreSQL parameter group for ${local.cluster_identifier}"
  # parameters = concat(
  #   [
  #     { name = "log_statement", value = var.log_statement },
  #     { name = "log_min_duration_statement", value = tostring(var.log_min_duration_statement_ms) },
  #     { name = "log_min_error_statement", value = var.log_min_error_statement },
  #     { name = "log_error_verbosity", value = var.log_error_verbosity }
  #   ],
  #   var.additional_cluster_parameters
  # )
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-cluster-params" })
}

# Cluster (ensure CloudWatch Logs export is enabled)
resource "aws_rds_cluster" "this" {
  depends_on                   = [aws_cloudwatch_log_group.postgresql, local.effective_master_password, local.kms_key_arn]
  cluster_identifier           = local.cluster_identifier
  engine                       = "aurora-postgresql"
  engine_version               = local.selected_engine_version
  master_username              = var.db_master_username
  master_password              = local.effective_master_password
  database_name                = var.database_name
  port                         = var.port
  db_subnet_group_name         = aws_db_subnet_group.this.name
  vpc_security_group_ids       = local.aurora_db_sg_ids
  storage_encrypted            = true
  kms_key_id                   = local.kms_key_arn
  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = var.preferred_backup_window
  preferred_maintenance_window = var.preferred_maintenance_window
  skip_final_snapshot          = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : coalesce(
    var.final_snapshot_identifier,
    "${local.cluster_identifier}-final-${replace(timestamp(), "/[: T-]/", "")}" # fallback unique name
  )
  apply_immediately                   = var.apply_immediately
  deletion_protection                 = var.deletion_protection
  copy_tags_to_snapshot               = true
  allow_major_version_upgrade         = var.allow_major_version_upgrade
  enabled_cloudwatch_logs_exports     = (var.enable_error_logs || var.enable_slow_query_logs) ? ["postgresql"] : []
  iam_database_authentication_enabled = var.iam_database_authentication_enabled
  db_cluster_parameter_group_name     = aws_rds_cluster_parameter_group.this.name
  tags                                = merge(var.tags, { Name = local.cluster_identifier })
}

# Instances
resource "aws_rds_cluster_instance" "this" {
  depends_on                      = [aws_rds_cluster.this]
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

resource "random_id" "index" {
  byte_length = 2
}

# VPC endpoint for Secrets Manager to keep rotation traffic inside VPC
resource "aws_vpc_endpoint" "secretsmanager" {
  # depends_on         = [aws_secretsmanager_secret.db_master, aws_lambda_function.rotation, local.kms_key_arn]
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.secretsmanager"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.vpc_endpoint_subnet_ids
  security_group_ids = local.vpce_sg_ids
  # private_dns_enabled = true
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-sm-vpce" })
}

# VPC endpoint for Lambda (for rotation function)
resource "aws_vpc_endpoint" "lambda" {
  # depends_on         = [aws_secretsmanager_secret.db_master, aws_lambda_function.rotation, local.kms_key_arn]
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.lambda"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.vpc_endpoint_subnet_ids
  security_group_ids = local.vpce_sg_ids
  # private_dns_enabled = true
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-lambda-vpce" })
}

# VPC endpoint for CloudWatch Logs
resource "aws_vpc_endpoint" "logs" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.logs"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.vpc_endpoint_subnet_ids
  security_group_ids = local.vpce_sg_ids
  # private_dns_enabled = true
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-logs-vpce" })
}

# VPC endpoint for KMS
resource "aws_vpc_endpoint" "kms" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.kms"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.vpc_endpoint_subnet_ids
  security_group_ids = local.vpce_sg_ids
  # private_dns_enabled = true
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-kms-vpce" })
}

# Secrets Manager secret for DB master credentials (encrypted with KMS)
resource "aws_secretsmanager_secret" "db_master" {
  depends_on  = [local.kms_key_arn]
  name        = "${local.secret_name}-${random_id.index.hex}"
  description = "Aurora PostgreSQL master credentials for ${local.cluster_identifier}"
  kms_key_id  = local.kms_key_arn
  tags        = merge(var.tags, { Name = "${local.secret_name}-${random_id.index.hex}" })
}

# Secret value
resource "aws_secretsmanager_secret_version" "db_master" {
  depends_on = [aws_secretsmanager_secret.db_master, aws_rds_cluster.this, local.kms_key_arn]
  secret_id  = aws_secretsmanager_secret.db_master.id
  secret_string = jsonencode({
    username            = var.db_master_username
    password            = local.effective_master_password
    engine              = "postgres"
    host                = aws_rds_cluster.this.endpoint
    port                = var.port
    dbname              = var.database_name
    dbClusterIdentifier = aws_rds_cluster.this.id
  })
}

# # IAM role to be assumed by Lambda rotation function (least privilege)
# resource "aws_iam_role" "rotation" {
#   name = "${local.cluster_identifier}-secret-rotation-role"
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [{
#       Effect    = "Allow",
#       Principal = { Service = "lambda.amazonaws.com" },
#       Action    = "sts:AssumeRole"
#     }]
#   })
#   tags = merge(var.tags, { Name = "${local.cluster_identifier}-rotation-role" })
# }

# AWS managed single-user rotation Lambda function code via Lambda ARN or deploying from AWS provided blueprint
# Here we use the AWS managed rotation function hosted as a Lambda in your account via a published blueprint package.
# For portability, we deploy a minimal lambda with VPC config, using container image or zip from AWS sample S3.
resource "aws_iam_role" "lambda_exec" {
  name = "${local.cluster_identifier}-lambda-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Name = "${local.cluster_identifier}-lambda-exec" })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  depends_on = [aws_iam_role.lambda_exec]
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Managed policy attachments and a minimal inline policy restricted to the secret and cluster
# Allow Lambda access to VPC for Secrets Manager VPC Endpoint
resource "aws_iam_role_policy" "lambda_vpc" {
  depends_on = [local.kms_key_arn, aws_iam_role.lambda_exec]
  name       = "${local.cluster_identifier}-lambda-vpc"
  role       = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowKMSForLambdaEnv",
        Effect = "Allow",
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ],
        Resource = local.kms_key_arn
      }
    ]
  })
}
# Inline policy for rotation role with least privilege
resource "aws_iam_role_policy" "rotation_inline" {
  depends_on = [aws_secretsmanager_secret.db_master, local.kms_key_arn, aws_rds_cluster.this, aws_cloudwatch_log_group.postgresql]
  name       = "${local.cluster_identifier}-rotation-inline"
  role       = aws_iam_role.lambda_exec.id
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

# Minimal lambda function stub; in practice use AWS sample for single-user rotation from Secrets Manager docs.
resource "aws_lambda_function" "rotation" {
  depends_on       = [aws_iam_role.lambda_exec, local.kms_key_arn, aws_rds_cluster.this, aws_secretsmanager_secret.db_master]
  function_name    = "${local.cluster_identifier}-rotation"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.lambda_function_zip.output_path
  source_code_hash = filebase64sha256(data.archive_file.lambda_function_zip.output_path)
  timeout          = 900
  memory_size      = 256
  kms_key_arn      = local.kms_key_arn
  architectures    = ["x86_64"]
  ephemeral_storage {
    size = 1024
  }
  dynamic "vpc_config" {
    for_each = local.lambda_has_vpc ? [1] : []
    content {
      subnet_ids         = var.lambda_subnet_ids
      security_group_ids = local.lambda_rotator_sg_ids
    }
  }
  environment {
    variables = {
      SECRET_ARN                 = aws_secretsmanager_secret.db_master.arn
      RDS_CLUSTER_ARN            = aws_rds_cluster.this.arn
      KMS_KEY_ARN                = local.kms_key_arn
      DB_ENGINE                  = "postgres"
      SECRETS_MANAGER_ENDPOINT   = "https://secretsmanager.${data.aws_region.current.region}.amazonaws.com"
      EXCLUDE_CHARACTERS         = ":/@\"'\\"
      PASSWORD_LENGTH            = "32"
      EXCLUDE_NUMBERS            = "false"
      EXCLUDE_PUNCTUATION        = "false"
      EXCLUDE_UPPERCASE          = "false"
      EXCLUDE_LOWERCASE          = "false"
      REQUIRE_EACH_INCLUDED_TYPE = "true"
    }
  }
  tags    = merge(var.tags, { Name = "${local.cluster_identifier}-rotation-lambda" })
  publish = "true"
  lifecycle {
    ignore_changes = [
      last_modified,
      source_code_hash,
      version,
      environment
    ]
  }
}

# Resource policy for the secret limiting access to rotation role and account root
resource "aws_secretsmanager_secret_policy" "secret_policy" {
  depends_on = [aws_secretsmanager_secret.db_master, aws_iam_role.lambda_exec]
  secret_arn = aws_secretsmanager_secret.db_master.arn
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowRotationRoleAccess"
        Effect = "Allow"
        Principal = {
          # AWS = aws_iam_role.rotation.arn
          AWS = aws_iam_role.lambda_exec.arn
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

# Optional: Enable automatic rotation (default true)
# If user wants manual rotation only, set enable_auto_secrets_rotation=false and they can trigger rotation manually in console/CLI.

# Allow Secrets Manager to invoke the rotation Lambda for this secret
resource "aws_lambda_permission" "allow_secretsmanager_invoke" {
  depends_on    = [aws_secretsmanager_secret.db_master, aws_lambda_function.rotation, aws_secretsmanager_secret_policy.secret_policy]
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
  source_arn    = aws_secretsmanager_secret.db_master.arn
}

# Rotation using AWS managed single-user rotation Lambda function
resource "aws_secretsmanager_secret_rotation" "this" {
  depends_on          = [aws_secretsmanager_secret.db_master, aws_lambda_function.rotation, aws_lambda_permission.allow_secretsmanager_invoke]
  count               = var.enable_auto_secrets_rotation ? 1 : 0
  secret_id           = aws_secretsmanager_secret.db_master.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# CloudWatch metrics and alarms examples (optional)
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  depends_on          = [aws_rds_cluster.this, aws_rds_cluster_instance.this]
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

# Comprehensive CloudWatch Alarms for Aurora PostgreSQL
resource "aws_cloudwatch_metric_alarm" "freeable_memory_low" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-FreeableMemory-Low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.memory_freeable_threshold
  alarm_description   = "Low freeable memory on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "database_connections_high" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-DatabaseConnections-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.database_connections_threshold
  alarm_description   = "High number of database connections on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "read_latency_high" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-ReadLatency-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ReadLatency"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.read_latency_threshold
  alarm_description   = "High read latency on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "write_latency_high" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-WriteLatency-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "WriteLatency"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.write_latency_threshold
  alarm_description   = "High write latency on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "deadlocks_high" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-Deadlocks-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Deadlocks"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Sum"
  threshold           = var.deadlock_threshold
  alarm_description   = "High number of deadlocks on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "aurora_replica_lag_high" {
  count               = var.enable_comprehensive_alarms && var.instance_count > 1 ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-AuroraReplicaLag-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "AuroraReplicaLag"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.replica_lag_threshold
  alarm_description   = "High Aurora replica lag on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "buffer_cache_hit_ratio_low" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-BufferCacheHitRatio-Low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "BufferCacheHitRatio"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.buffer_cache_hit_ratio_threshold
  alarm_description   = "Low buffer cache hit ratio on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "disk_queue_depth_high" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-DiskQueueDepth-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DiskQueueDepth"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.disk_queue_depth_threshold
  alarm_description   = "High disk queue depth on Aurora PostgreSQL cluster"
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.id
  }
  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "swap_usage_high" {
  count               = var.enable_comprehensive_alarms ? 1 : 0
  alarm_name          = "${local.cluster_identifier}-SwapUsage-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "SwapUsage"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.swap_usage_threshold
  alarm_description   = "High swap usage on Aurora PostgreSQL cluster"
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
