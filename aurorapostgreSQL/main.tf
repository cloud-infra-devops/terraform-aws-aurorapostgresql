data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
# Prefix list for Secrets Manager regional endpoints (used to restrict SG egress)
data "aws_prefix_list" "secretsmanager" {
  name = "com.amazonaws.${data.aws_region.current.region}.secretsmanager"
}

# Generate secure initial DB master password
resource "random_password" "master" {
  length           = 24
  override_special = "!@#$%&*()-_=+[]{}<>?"
  special          = true
  min_special      = 5
}

# Optional KMS key
resource "aws_kms_key" "this" {
  count = var.create_kms_key ? 1 : 0

  description             = "KMS key for ${var.name} RDS cluster and Secrets Manager secret"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = merge({ "Name" = "${var.name}-rds-kms" }, var.tags)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAdminsFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowSecretsManagerUse"
        Effect    = "Allow"
        Principal = { Service = "secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.partition}.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid       = "AllowRDSUse"
        Effect    = "Allow"
        Principal = { Service = "rds.${data.aws_region.current.region}.${data.aws_partition.current.partition}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid       = "AllowRotationLambdaAccountUse"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.rotation_lambda_account}:root" }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

locals {
  kms_key_id = var.create_kms_key ? aws_kms_key.this[0].arn : (length(var.existing_kms_key_id) > 0 ? var.existing_kms_key_id : null)
}

# DB subnet group
resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-db-subnet-group"
  subnet_ids = var.subnet_ids
  tags       = merge({ Name = "${var.name}-db-subnet-group" }, var.tags)
}

# DB Security group
resource "aws_security_group" "db_sec_grp" {
  name   = "${var.name}-AuroraPostgreSQL-sg"
  vpc_id = var.vpc_id
  tags   = merge({ Name = "${var.name}-AuroraPostgreSQL-sg" }, var.tags)
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # ingress {
  #   from_port       = -1
  #   to_port         = -1
  #   protocol        = "icmp"
  #   security_groups = [aws_security_group.bastion_sec_grp.id]
  # }

  # ingress {
  #   from_port   = 0
  #   to_port     = 0
  #   protocol    = "-1"
  #   cidr_blocks = [aws_vpc.aws-secrets-manager-vpc.cidr_block]
  # }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS cluster
resource "aws_rds_cluster" "this" {
  cluster_identifier              = var.name
  engine                          = var.engine
  engine_version                  = length(var.engine_version) > 0 ? var.engine_version : null
  database_name                   = var.database_name
  master_username                 = var.master_username
  master_password                 = random_password.master.result
  storage_encrypted               = true
  kms_key_id                      = local.kms_key_id
  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = concat([aws_security_group.db_sec_grp.id], var.vpc_security_group_ids)
  enabled_cloudwatch_logs_exports = length(local.enabled_cloudwatch_logs_exports) > 0 ? local.enabled_cloudwatch_logs_exports : null
  skip_final_snapshot             = true
  tags                            = merge({ Name = var.name }, var.tags)
}

resource "aws_rds_cluster_instance" "instances" {
  depends_on          = [aws_rds_cluster.this]
  count               = var.instance_count
  identifier          = "${var.name}-instance-${count.index + 1}"
  cluster_identifier  = aws_rds_cluster.this.id
  instance_class      = var.instance_class
  engine              = aws_rds_cluster.this.engine
  engine_version      = aws_rds_cluster.this.engine_version != "" ? aws_rds_cluster.this.engine_version : null
  publicly_accessible = false
  tags                = merge({ Name = "${var.name}-instance-${count.index + 1}" }, var.tags)
}
locals {
  # If you only want to test for a non-empty existing secret ARN:
  existing_secret_provided = length(trimspace(var.existing_secret_arn)) > 0 ? true : false

  # Example usage: choose existing secret ARN if provided, otherwise use the one created by this module
  secret_arn_to_use = length(trimspace(var.existing_secret_arn)) > 0 ? var.existing_secret_arn : aws_secretsmanager_secret.db_secret.arn

  # If module creates the rotation lambda, use that ARN; otherwise prefer an explicitly provided ARN
  # Use coalesce + trimspace to safely handle empty string or null values (trimspace is single-arg)
  rotation_lambda_final_arn = var.create_rotation_lambda ? aws_lambda_function.rotation_lambda[0].arn : (length(trimspace(coalesce(var.existing_rotation_lambda_arn, ""))) > 0 ? var.existing_rotation_lambda_arn : local.managed_rotation_lambda_arn)
}

# Remove any data "aws_prefix_list" lookup for Secrets Manager.
# --- Secrets Manager endpoint SG egress (use supplied prefix list id if available) ---
resource "aws_security_group_rule" "endpoint_egress_to_secretsmanager_prefix" {
  count = var.create_secretsmanager_vpc_endpoint && length(trimspace(coalesce(var.secretsmanager_prefix_list_id, ""))) > 0 ? 1 : 0

  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.secretsmanager_endpoint_sg[0].id

  # Use the user-provided regional prefix list id to limit egress to the Secrets Manager service
  prefix_list_ids = [var.secretsmanager_prefix_list_id]
  description     = "Allow egress to AWS Secrets Manager via provided prefix list"
}

# Fallback egress rule when no prefix list id is provided. This is less restrictive:
resource "aws_security_group_rule" "endpoint_egress_to_secretsmanager_fallback" {
  count = var.create_secretsmanager_vpc_endpoint && length(trimspace(coalesce(var.secretsmanager_prefix_list_id, ""))) == 0 ? 1 : 0

  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.secretsmanager_endpoint_sg[0].id

  cidr_blocks = ["0.0.0.0/0"]
  description = "Fallback: allow egress 443 to anywhere (no Secrets Manager prefix list provided). Replace with prefix-list id for least-privilege."
}

# --- Rotation Lambda SG egress to Secrets Manager: similar conditional approach ---
resource "aws_security_group_rule" "rotation_lambda_egress_to_secretsmanager_prefix" {
  count = var.create_rotation_lambda && length(trimspace(coalesce(var.secretsmanager_prefix_list_id, ""))) > 0 ? 1 : 0

  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.rotation_lambda_sg[0].id

  prefix_list_ids = [var.secretsmanager_prefix_list_id]
  description     = "Allow rotation Lambda egress to Secrets Manager via provided prefix list"
}

resource "aws_security_group_rule" "rotation_lambda_egress_to_secretsmanager_fallback" {
  count = var.create_rotation_lambda && length(trimspace(coalesce(var.secretsmanager_prefix_list_id, ""))) == 0 ? 1 : 0

  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.rotation_lambda_sg[0].id

  cidr_blocks = ["0.0.0.0/0"]
  description = "Fallback: allow rotation Lambda egress 443 to anywhere (no Secrets Manager prefix list provided). Replace with prefix-list id for least-privilege."
}

# IAM role and policy for RDS to publish logs (optional if logs enabled)
resource "aws_iam_role" "rds_cloudwatch_logs_role" {
  count = (var.enable_error_log_export || var.enable_slow_log_export) ? 1 : 0
  name  = "${var.name}-rds-cloudwatch-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "rds_cloudwatch_logs_policy" {
  count = length(aws_iam_role.rds_cloudwatch_logs_role) > 0 ? 1 : 0

  name = "${var.name}-rds-cloudwatch-logs-policy"
  role = aws_iam_role.rds_cloudwatch_logs_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCreateLogGroupAndStream"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:CreateLogGroup",
          "logs:PutLogEvents"
        ]
        Resource = [
          var.enable_error_log_export ? aws_cloudwatch_log_group.errors[0].arn : "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/rds/cluster/${aws_rds_cluster.this.cluster_identifier}:*",
          var.enable_slow_log_export ? aws_cloudwatch_log_group.slow_queries[0].arn : "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/rds/cluster/${aws_rds_cluster.this.cluster_identifier}:*"
        ]
      }
    ]
  })
  lifecycle {
    ignore_changes = [policy]
  }
}

# Secrets Manager secret & initial version
resource "aws_secretsmanager_secret" "db_secret" {
  name        = "${var.name}-db-credentials"
  description = "Master DB credentials for ${var.name} (managed by Terraform)"
  kms_key_id  = local.kms_key_id
  tags        = merge({ Name = "${var.name}-db-credentials" }, var.tags)
}

resource "aws_secretsmanager_secret_version" "initial" {
  secret_id = aws_secretsmanager_secret.db_secret.id

  secret_string = jsonencode({
    username            = var.master_username
    password            = random_password.master.result
    engine              = var.engine
    host                = aws_rds_cluster.this.endpoint
    port                = var.port
    dbname              = var.database_name
    dbClusterIdentifier = aws_rds_cluster.this.cluster_identifier
  })
}

# Construct default rotation lambda ARN if not provided and not creating rotation lambda in-module
locals {
  default_rotation_lambda_arn = var.existing_rotation_lambda_arn != "" ? var.existing_rotation_lambda_arn : "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${var.rotation_lambda_account}:function:SecretsManagerPostgreSQLRotationSingleUser"
  rotation_lambda_to_use      = var.create_rotation_lambda ? "" : (var.existing_rotation_lambda_arn != "" ? var.existing_rotation_lambda_arn : local.default_rotation_lambda_arn)
}

# --- Secrets Manager VPC endpoint and SGs ---

# SG for the Secrets Manager interface endpoint
resource "aws_security_group" "secretsmanager_endpoint_sg" {
  count = var.create_secretsmanager_vpc_endpoint ? 1 : 0

  name        = "${var.name}-secrets-endpoint-sg"
  description = "SG for Secrets Manager interface VPC endpoint - allows TCP/443 from allowed sources"
  vpc_id      = var.vpc_id
  tags        = merge({ Name = "${var.name}-secrets-endpoint-sg" }, var.tags)

  # Inline ingress for allowed CIDR blocks (if any)
  ingress {
    description      = "Allow HTTPS from allowed CIDR blocks"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = var.allowed_vpc_endpoint_source_cidr_blocks
    ipv6_cidr_blocks = []
  }

  # No inline egress here - egress is created as separate aws_security_group_rule using prefix list (to restrict to Secrets Manager service)
}

# Egress from the endpoint SG restricted to Secrets Manager prefix-list (port 443)
resource "aws_security_group_rule" "endpoint_egress_to_secretsmanager" {
  count = var.create_secretsmanager_vpc_endpoint ? 1 : 0

  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.secretsmanager_endpoint_sg[0].id

  # Use regional prefix list id for Secrets Manager service
  prefix_list_ids = [data.aws_prefix_list.secretsmanager.id]
  description     = "Allow egress to AWS Secrets Manager via prefix list"
}

# Additional ingress rules referencing provided SGs (one per SG)
resource "aws_security_group_rule" "allow_sg_to_secrets_endpoint" {
  count = var.create_secretsmanager_vpc_endpoint ? length(var.allowed_vpc_endpoint_source_security_group_ids) : 0

  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.secretsmanager_endpoint_sg[0].id
  source_security_group_id = var.allowed_vpc_endpoint_source_security_group_ids[count.index]
  description              = "Allow SG ${var.allowed_vpc_endpoint_source_security_group_ids[count.index]} to access Secrets Manager endpoint on 443"
}

# Build effective allowed SGs list for endpoint (merge user provided + rotation lambda SG when created)
locals {
  effective_allowed_sg_ids = concat(
    var.allowed_vpc_endpoint_source_security_group_ids,
    var.create_rotation_lambda ? [aws_security_group.rotation_lambda_sg[0].id] : []
  )
}

# If user provided additional CIDRs, they remain in aws_security_group.secretsmanager_endpoint_sg.ingress above.

# Create the interface VPC endpoint for Secrets Manager
resource "aws_vpc_endpoint" "secretsmanager" {
  # Ensure SG ingress rules are created first
  depends_on = [aws_security_group_rule.allow_sg_to_secrets_endpoint, aws_security_group_rule.endpoint_egress_to_secretsmanager]
  count      = var.create_secretsmanager_vpc_endpoint ? 1 : 0

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = var.create_secretsmanager_vpc_endpoint ? [aws_security_group.secretsmanager_endpoint_sg[0].id] : []
  private_dns_enabled = true
  tags                = merge({ Name = "${var.name}-secrets-endpoint" }, var.tags)
}

# --- Optional: rotation Lambda deployed inside module ---
# Create SG for rotation Lambda (if requested)
resource "aws_security_group" "rotation_lambda_sg" {
  count = var.create_rotation_lambda ? 1 : 0

  name        = "${var.name}-rotation-lambda-sg"
  description = "Security group for Secrets Manager rotation Lambda (allows outbound to DB and Secrets Manager)"
  vpc_id      = var.vpc_id
  tags        = merge({ Name = "${var.name}-rotation-lambda-sg" }, var.tags)

  # No ingress - Lambda does not accept inbound connections
  # We'll add egress rules below
}

# Allow inbound from rotation Lambda SG to DB security groups on DB port (ingress on DB SGs)
resource "aws_security_group_rule" "rotation_lambda_egress_to_db_sgs" {
  count = var.create_rotation_lambda ? length(var.vpc_security_group_ids) : 0

  type                     = "ingress"
  from_port                = var.port
  to_port                  = var.port
  protocol                 = "tcp"
  security_group_id        = var.vpc_security_group_ids[count.index]
  source_security_group_id = aws_security_group.rotation_lambda_sg[0].id
  description              = "Allow rotation Lambda SG ${aws_security_group.rotation_lambda_sg[0].id} to access DB SG ${var.vpc_security_group_ids[count.index]} on port ${var.port}"
}

# Allow outbound to Secrets Manager service via prefix list (443) from rotation Lambda SG
resource "aws_security_group_rule" "rotation_lambda_egress_to_secretsmanager" {
  count = var.create_rotation_lambda ? 1 : 0

  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.rotation_lambda_sg[0].id
  prefix_list_ids   = [data.aws_prefix_list.secretsmanager.id]
  description       = "Allow rotation Lambda egress to Secrets Manager regional endpoints"
}

# IAM role for the rotation Lambda (least-privilege-ish - review & tighten)
resource "aws_iam_role" "rotation_lambda_role" {
  count = var.create_rotation_lambda ? 1 : 0
  name  = "${var.name}-rotation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Attach managed policy for basic Lambda logging
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  count      = var.create_rotation_lambda ? 1 : 0
  role       = aws_iam_role.rotation_lambda_role[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Inline policy with specific permissions for rotation actions (Secrets Manager + RDS describe + KMS decrypt if key exists)
resource "aws_iam_role_policy" "rotation_lambda_inline" {
  count = var.create_rotation_lambda ? 1 : 0
  name  = "${var.name}-rotation-lambda-inline-policy"
  role  = aws_iam_role.rotation_lambda_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerAccessForRotation"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets"
        ]
        Resource = [
          aws_secretsmanager_secret.db_secret.arn,
          # Allow access to secret versions and other related ARNs
          "${aws_secretsmanager_secret.db_secret.arn}/*"
        ]
      },
      {
        Sid    = "RDSDescribe"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:DescribeDBSubnetGroups"
        ]
        Resource = ["*"]
      },
      {
        Sid    = "KMSDecryptIfNeeded"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.create_kms_key ? [aws_kms_key.this[0].arn] : (length(var.existing_kms_key_id) > 0 ? [var.existing_kms_key_id] : ["*"])
      }
    ]
  })
}

# Lambda function - requires code to be present in S3 bucket/key provided by user
resource "aws_lambda_function" "rotation_lambda" {
  count = var.create_rotation_lambda ? 1 : 0

  function_name     = "${var.name}-secrets-rotation"
  s3_bucket         = var.rotation_lambda_s3_bucket
  s3_key            = var.rotation_lambda_s3_key
  s3_object_version = length(var.rotation_lambda_s3_object_version) > 0 ? var.rotation_lambda_s3_object_version : null
  handler           = var.rotation_lambda_handler
  runtime           = var.rotation_lambda_runtime
  role              = aws_iam_role.rotation_lambda_role[0].arn
  filename          = null
  source_code_hash  = null

  environment {
    variables = var.rotation_lambda_environment
  }

  vpc_config {
    subnet_ids         = var.rotation_lambda_subnet_ids
    security_group_ids = [aws_security_group.rotation_lambda_sg[0].id]
  }

  tags = var.tags

  depends_on = [aws_iam_role_policy_attachment.lambda_basic_execution]
}

# Allow Secrets Manager to invoke the rotation Lambda
resource "aws_lambda_permission" "allow_secretsmanager_invoke" {
  count = var.create_rotation_lambda ? 1 : 0

  statement_id  = "AllowExecutionFromSecretsManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation_lambda[0].function_name
  principal     = "secretsmanager.amazonaws.com"
  # Source ARN not strictly required but helps scope permission to this secret
  source_arn = aws_secretsmanager_secret.db_secret.arn
  # source_arn = local.secret_arn_used
}

# If rotation lambda created then use it as rotation lambda ARN (defined earlier in locals to avoid duplicate definition)

# Secret rotation configuration (use created lambda ARN when present)
resource "aws_secretsmanager_secret_rotation" "db_rotation" {
  # make sure that the initial value is saved before setting up rotation, otherwise, it can result in a ResourceNotFoundException: An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation:Secrets Manager can't find the specified secret value for staging label: AWSCURRENT
  depends_on          = [aws_secretsmanager_secret_version.initial]
  secret_id           = aws_secretsmanager_secret.db_secret.id
  rotation_lambda_arn = local.rotation_lambda_final_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
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

  # The secret ARN used by the module (created or provided)
  secret_arn_used = var.use_secrets_manager ? (
    length(trim(var.existing_secret_arn)) > 0 ? var.existing_secret_arn :
    aws_secretsmanager_secret.db_secret.arn
  ) : ""

  # Managed rotation lambda account & ARN for this region (if present in the map)
  managed_rotation_account    = lookup(local.aws_rotation_accounts, data.aws_region.current.region, null)
  managed_rotation_lambda_arn = local.managed_rotation_account != null ? "arn:aws:lambda:${data.aws_region.current.region}:${local.managed_rotation_account}:function:SecretsManagerRDSPostgreSQLRotationSingleUser" : null

  # Conditions for choosing which rotation implementation to attach:
  use_managed_rotation      = var.secret_rotation_enabled && length(trim(var.existing_rotation_lambda_arn)) == 0 && var.use_aws_managed_rotation && local.managed_rotation_lambda_arn != null && length(local.secret_arn_used) > 0
  use_existing_lambda       = var.secret_rotation_enabled && length(trim(var.existing_rotation_lambda_arn)) > 0 && length(local.secret_arn_used) > 0
  use_module_managed_lambda = var.secret_rotation_enabled && length(trim(var.existing_rotation_lambda_arn)) == 0 && (!var.use_aws_managed_rotation || local.managed_rotation_lambda_arn == null) && var.create_rotation_lambda && length(local.secret_arn_used) > 0
}

# Attach AWS-managed rotation Lambda (single-user) when available and requested
resource "aws_secretsmanager_secret_rotation" "aws_managed" {
  count               = local.use_managed_rotation ? 1 : 0
  secret_id           = local.secret_arn_used
  rotation_lambda_arn = local.managed_rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# Attach an existing user-supplied rotation Lambda (if user provided an ARN)
resource "aws_secretsmanager_secret_rotation" "existing_lambda" {
  count               = local.use_existing_lambda ? 1 : 0
  secret_id           = local.secret_arn_used
  rotation_lambda_arn = var.existing_rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# If AWS managed rotation isn't usable for this region or the user disabled it, fall back to the module-managed Lambda
# (this block expects the module-managed lambda resources to exist in other files, guarded by local.use_module_managed_lambda)
resource "aws_secretsmanager_secret_rotation" "module_managed" {
  count               = local.use_module_managed_lambda ? 1 : 0
  secret_id           = local.secret_arn_used
  rotation_lambda_arn = aws_lambda_function.rotation_lambda[0].arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "errors" {
  count             = var.enable_error_log_export ? 1 : 0
  name              = "/aws/rds/cluster/${aws_rds_cluster.this.cluster_identifier}/postgresql-error"
  retention_in_days = var.log_retention_in_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "slow_queries" {
  count             = var.enable_slow_log_export ? 1 : 0
  name              = "/aws/rds/cluster/${aws_rds_cluster.this.cluster_identifier}/postgresql-slowquery"
  retention_in_days = var.log_retention_in_days
  tags              = var.tags
}

# CloudWatch log exports list
locals {
  enabled_cloudwatch_logs_exports = concat(
    var.enable_error_log_export ? ["postgresql"] : [],
    var.enable_slow_log_export ? ["postgresql"] : []
  )
}

# CloudWatch metric filters for logs
resource "aws_cloudwatch_log_metric_filter" "error_filter" {
  count          = var.enable_error_log_export ? 1 : 0
  name           = "${var.name}-postgres-error-filter"
  log_group_name = aws_cloudwatch_log_group.errors[0].name

  pattern = "[?ERROR ?FATAL ?PANIC]"
  metric_transformation {
    name      = "PostgresErrorCount"
    namespace = var.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "slow_query_filter" {
  count          = var.enable_slow_log_export ? 1 : 0
  name           = "${var.name}-postgres-slowquery-filter"
  log_group_name = aws_cloudwatch_log_group.slow_queries[0].name

  pattern = "duration:"
  metric_transformation {
    name      = "PostgresSlowQueryCount"
    namespace = var.metric_namespace
    value     = "1"
  }
}

# Optional example alarm for errors
resource "aws_cloudwatch_metric_alarm" "error_alarm" {
  count = var.enable_cloudwatch_alarms && var.enable_error_log_export ? 1 : 0

  alarm_name          = "${var.name}-postgres-error-alarm"
  alarm_description   = "Alarm when PostgreSQL errors are detected"
  namespace           = var.metric_namespace
  metric_name         = "PostgresErrorCount"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = var.error_alarm_evaluation_periods
  threshold           = var.error_alarm_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
}
