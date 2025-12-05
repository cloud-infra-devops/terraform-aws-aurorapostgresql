# variable "byte_length" {
#   type = number
# }
variable "name" {
  description = "Base name for resources."
  type        = string
}

variable "cluster_identifier" {
  description = "Optional custom cluster identifier; defaults to name-aurora-pg."
  type        = string
  default     = null
}

variable "vpc_id" {
  description = "VPC ID for the cluster and endpoints."
  type        = string
}

variable "vpc_cidr" {
  type = string
}

variable "subnet_ids" {
  description = "Private subnet IDs for the DB subnet group."
  type        = list(string)
}

variable "vpc_endpoint_subnet_ids" {
  description = "Subnet IDs for the Secrets Manager interface VPC endpoint."
  type        = list(string)
}

variable "lambda_subnet_ids" {
  description = "Subnet IDs for the rotation lambda VPC config."
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to connect to the DB port."
  type        = list(string)
  default     = []
}

variable "allowed_security_group_ids" {
  description = "Existing Security group IDs allowed to connect to the DB port."
  type        = list(string)
  default     = []
}

variable "port" {
  description = "PostgreSQL port."
  type        = number
  default     = 5432
}

# variable "engine_version" {
#   description = "Aurora PostgreSQL engine version."
#   type        = string
#   default     = "15.3"
# }
variable "engine_version" {
  description = "Aurora PostgreSQL engine version. If null, the module will auto-select a valid version for the region."
  type        = string
  default     = null
}

variable "preferred_engine_versions" {
  description = "Ordered list of preferred Aurora PostgreSQL versions; the first available in the region will be used when engine_version is null."
  type        = list(string)
  default = [
    "15.4",
    "15.2",
    "14.10",
    "14.9"
  ]
}
variable "instance_class" {
  description = "Instance class for cluster instances."
  type        = string
  default     = "db.r6g.large"
}

variable "instance_count" {
  description = "Number of instances in the cluster."
  type        = number
  default     = 2
}

variable "database_name" {
  description = "Initial database name."
  type        = string
  default     = "appdb"
}

variable "db_master_username" {
  description = "Master username."
  type        = string
  sensitive   = true
}

variable "use_existing_kms_key" {
  description = "Use an existing KMS key instead of creating one."
  type        = bool
  default     = false
}

variable "existing_kms_key_arn" {
  description = "ARN of existing KMS key."
  type        = string
  default     = null
}

variable "kms_deletion_window_in_days" {
  description = "Deletion window for the CMK."
  type        = number
  default     = 7
}

variable "secret_name" {
  description = "Name of the Secrets Manager secret for master credentials."
  type        = string
  default     = null
}

variable "enable_auto_secrets_rotation" {
  description = "Enable automatic rotation using AWS managed single-user Lambda."
  type        = bool
  default     = true
}

variable "rotation_days" {
  description = "Automatic secrets rotation interval in days."
  type        = number
  default     = 180
}

variable "rotation_lambda_zip" {
  description = "Path to the ZIP file for rotation lambda code (AWS sample)."
  type        = string
  default     = null
}

variable "backup_retention_days" {
  description = "Backup retention in days."
  type        = number
  default     = 7
}

variable "preferred_backup_window" {
  description = "Backup window (UTC)."
  type        = string
  default     = "03:00-04:00"
}

variable "preferred_maintenance_window" {
  description = "Maintenance window (UTC)."
  type        = string
  default     = "sun:06:00-sun:11:00"
}

variable "apply_immediately" {
  description = "Apply changes immediately."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Enable deletion protection."
  type        = bool
  default     = true
}

variable "allow_major_version_upgrade" {
  description = "Allow major version upgrades."
  type        = bool
  default     = false
}

variable "publicly_accessible" {
  description = "Whether instances are publicly accessible."
  type        = bool
  default     = false
}

variable "auto_minor_version_upgrade" {
  description = "Enable auto minor version upgrade."
  type        = bool
  default     = true
}

variable "monitoring_interval" {
  description = "Enhanced monitoring interval (seconds)."
  type        = number
  default     = 0
}

variable "performance_insights_enabled" {
  description = "Enable Performance Insights."
  type        = bool
  default     = true
}

variable "iam_database_authentication_enabled" {
  description = "Enable IAM database authentication."
  type        = bool
  default     = false
}

variable "enable_error_logs" {
  description = "Enable export of error logs to CloudWatch Logs."
  type        = bool
  default     = true
}

variable "enable_slow_query_logs" {
  description = "Enable export of slow query logs to CloudWatch Logs."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
  default     = 1
}

variable "cluster_parameter_family" {
  description = "Parameter group family for Aurora PostgreSQL."
  type        = string
  default     = "aurora-postgresql15"
}

variable "additional_cluster_parameters" {
  description = "Additional cluster parameters."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "enable_metrics" {
  description = "Enable default CloudWatch metrics/alarms."
  type        = bool
  default     = true
}

variable "cpu_high_threshold" {
  description = "CPU high alarm threshold."
  type        = number
  default     = 80
}

variable "enable_slow_query_metrics" {
  description = "Enable custom slow query metric filter and alarm."
  type        = bool
  default     = false
}

variable "slow_query_filter_pattern" {
  description = "Logs Insights filter pattern to count slow queries."
  type        = string
  default     = "[timestamp, level=\"LOG\", message = /duration: [0-9\\.]+ ms/]"
}

variable "slow_query_threshold" {
  description = "Threshold for slow queries count over period."
  type        = number
  default     = 100
}

variable "alarm_action_arns" {
  description = "SNS topic ARNs to notify on alarm."
  type        = list(string)
  default     = []
}

variable "ok_action_arns" {
  description = "SNS topic ARNs to notify when alarm recovers."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}

variable "log_statement" {
  description = "PostgreSQL log_statement: none | ddl | mod | all"
  type        = string
  default     = "none"
}

variable "log_min_duration_statement_ms" {
  description = "Log queries slower than this many ms; -1 disables."
  type        = number
  default     = -1
}

variable "log_min_error_statement" {
  description = "Minimum error severity to log: error, warning, notice, debug1..debug5, etc."
  type        = string
  default     = "error"
}

variable "log_error_verbosity" {
  description = "Error verbosity: default | verbose | terse"
  type        = string
  default     = "default"
}
