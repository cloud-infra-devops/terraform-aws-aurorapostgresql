data "aws_rds_engine_version" "aurora_pg_versions" {
  engine             = "aurora-postgresql"
  preferred_versions = var.preferred_engine_versions # e.g., ["17.2", "17.1", "17.0", "15.4", "15.3"]
  # Use this to filter for the latest minor version within a major version
  # parameter_group_family = "postgres14" # Example: for PostgreSQL 14
  # parameter_group_family = "postgres15" # Example: for PostgreSQL 15
  latest = true # Set to true to get the latest available
}
data "archive_file" "lambda_function_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  effective_master_password = var.db_master_password != null ? var.db_master_password : (
    var.generate_master_password ? random_password.db_master[0].result : null
  )
  aurora_db_sg_ids        = var.use_existing_aurora_db_sg && length(var.existing_aurora_db_security_group_ids) > 0 ? var.existing_aurora_db_security_group_ids : [aws_security_group.db.id]
  vpce_sg_ids             = var.use_existing_vpce_sg && length(var.existing_vpce_security_group_ids) > 0 ? var.existing_vpce_security_group_ids : [aws_security_group.vpce.id]
  lambda_rotator_sg_ids   = var.use_existing_lambda_rotator_sg && length(var.existing_lambda_rotator_security_group_ids) > 0 ? var.existing_lambda_rotator_security_group_ids : [aws_security_group.rotator_lambda_security_group.id]
  kms_key_arn             = var.use_existing_kms_key ? var.existing_kms_key_arn : aws_kms_key.this[0].arn
  cluster_identifier      = var.cluster_identifier != null ? var.cluster_identifier : "${var.name}-aurora-pg"
  selected_engine_version = var.engine_version != null ? var.engine_version : data.aws_rds_engine_version.aurora_pg_versions.version
  # Derive the parameter group family from the selected engine version (major component)
  selected_major                     = split(".", local.selected_engine_version)[0]
  cluster_parameter_family_effective = "aurora-postgresql${local.selected_major}"
  # Secrets Manager name
  secret_name = var.secret_name != null ? var.secret_name : "${local.cluster_identifier}/master"
  log_types = compact([
    var.enable_error_logs ? "postgresql" : null, # Aurora Postgres error logs written to CloudWatch Logs "postgresql"
    var.enable_slow_query_logs ? "postgresql" : null
  ])
  lambda_has_vpc = length(var.lambda_subnet_ids) > 0
}

