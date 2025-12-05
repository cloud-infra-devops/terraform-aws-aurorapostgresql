output "cluster_arn" {
  value       = aws_rds_cluster.this.arn
  description = "Aurora PostgreSQL cluster ARN."
}

output "cluster_endpoint" {
  value       = aws_rds_cluster.this.endpoint
  description = "Writer endpoint."
}

output "reader_endpoint" {
  value       = aws_rds_cluster.this.reader_endpoint
  description = "Reader endpoint."
}

output "secret_arn" {
  value       = aws_secretsmanager_secret.db_master.arn
  description = "Secrets Manager secret ARN for master credentials."
}

output "kms_key_arn" {
  value       = local.kms_key_arn
  description = "KMS key ARN used for encryption."
}

output "vpc_endpoint_id" {
  value       = aws_vpc_endpoint.secretsmanager.id
  description = "Interface VPC endpoint ID for Secrets Manager."
}

output "db_security_group_id" {
  value       = aws_security_group.db.id
  description = "Security group ID attached to the DB cluster."
}