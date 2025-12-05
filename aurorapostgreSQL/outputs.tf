output "cluster_id" {
  description = "RDS cluster identifier"
  value       = aws_rds_cluster.this.cluster_identifier
}

output "cluster_endpoint" {
  description = "Writer/cluster endpoint"
  value       = aws_rds_cluster.this.endpoint
}

output "cluster_reader_endpoint" {
  description = "Reader endpoint"
  value       = aws_rds_cluster.this.reader_endpoint
}

output "secret_arn" {
  description = "ARN of the Secrets Manager secret with DB master credentials"
  value       = aws_secretsmanager_secret.db_secret.arn
}

output "secret_name" {
  description = "Name of the Secrets Manager secret with DB master credentials"
  value       = aws_secretsmanager_secret.db_secret.name
}

output "kms_key_id" {
  description = "KMS key ARN/ID used for encryption (if created or supplied)"
  value       = local.kms_key_id
}

output "cloudwatch_log_group_names" {
  description = "Map of created CloudWatch Log Group names (error/slow query) when enabled"
  value = {
    error      = var.enable_error_log_export ? aws_cloudwatch_log_group.errors[0].name : ""
    slow_query = var.enable_slow_log_export ? aws_cloudwatch_log_group.slow_queries[0].name : ""
  }
}

output "rotation_lambda_arn" {
  description = "Rotation Lambda ARN used for automatic rotation (either created by module or provided/auto-constructed)"
  value       = local.rotation_lambda_final_arn
}

output "rotation_lambda_function_name" {
  description = "If the module created the rotation Lambda, the function name."
  value = var.create_rotation_lambda ? aws_lambda_function.rotation_lambda[0].function_name : ""
}

output "rotation_lambda_sg_id" {
  description = "If the module created the rotation Lambda, its security group id."
  value = var.create_rotation_lambda ? aws_security_group.rotation_lambda_sg[0].id : ""
}

output "secretsmanager_vpc_endpoint_id" {
  description = "ID of the created Secrets Manager interface VPC endpoint (if created)"
  value       = var.create_secretsmanager_vpc_endpoint ? aws_vpc_endpoint.secretsmanager[0].id : ""
}

output "secretsmanager_vpc_endpoint_sg_id" {
  description = "Security group ID created for the Secrets Manager VPC endpoint (if created)"
  value       = var.create_secretsmanager_vpc_endpoint ? aws_security_group.secretsmanager_endpoint_sg[0].id : ""
}