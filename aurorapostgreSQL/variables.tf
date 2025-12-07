# variable "byte_length" {
#   type = number
# }

# variable "rotation_lambda_zip" {
#   description = "Path to the ZIP file for rotation lambda code (AWS sample)."
#   type        = string
#   default     = null
# }

# variable "cluster_parameter_family" {
#   description = "Parameter group family for Aurora PostgreSQL."
#   type        = string
#   default     = "aurora-postgresql17"
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

variable "allowed_other_ingress_cidrs" {
  description = "other ingress CIDR blocks allowed to connect to the Aurora DB"
  type        = list(string)
  # default     = []
}

variable "allowed_existing_security_group_ids" {
  description = "Existing Security group IDs allowed to connect to the DB port."
  type        = list(string)
  # default     = []
}
variable "lambda_security_group_ids" {
  description = "Security group IDs for the rotation Lambda when placed in VPC. Must be non-empty when lambda_subnet_ids is non-empty."
  type        = list(string)
  default     = []
}
variable "port" {
  description = "PostgreSQL port."
  type        = number
  default     = 5432
}

variable "engine_version" {
  description = "Aurora PostgreSQL engine version; if null, a valid version is auto-selected for the region."
  type        = string
  default     = null
}

variable "preferred_engine_versions" {
  description = "Ordered list of preferred Aurora PostgreSQL versions; first available in region is used when engine_version is null."
  type        = list(string)
  default     = ["17.7", "17.6", "17.5", "17.4", "17.3", "17.2", "17.1", "17.0", "15.4", "15.3"]
}

# Remove hard-coded cluster_parameter_family default to avoid mismatches
variable "cluster_parameter_family" {
  description = "Deprecated: parameter group family. The module derives the correct family from the selected engine version."
  type        = string
  default     = null
}
# Allowed Aurora PostgreSQL instance classes (provisioned instances for Aurora PostgreSQL)
# Note: Serverless v2 uses capacity settings, not instance_class. Use these when provisioning instances.
variable "allowed_instance_classes" {
  description = "List of allowed Aurora PostgreSQL instance classes."
  type        = list(string)
  default = [
    # Graviton (recommended for cost/perf)
    "db.r6g.large",
    "db.r6g.xlarge",
    "db.r6g.2xlarge",
    "db.r6g.4xlarge",
    "db.r6g.8xlarge",
    "db.r6g.12xlarge",
    "db.r6g.16xlarge",

    "db.r7g.large",
    "db.r7g.xlarge",
    "db.r7g.2xlarge",
    "db.r7g.4xlarge",
    "db.r7g.8xlarge",
    "db.r7g.12xlarge",
    "db.r7g.16xlarge",

    # Intel-based (legacy)
    "db.r5.large",
    "db.r5.xlarge",
    "db.r5.2xlarge",
    "db.r5.4xlarge",
    "db.r5.8xlarge",
    "db.r5.12xlarge",
    "db.r5.16xlarge",
    "db.r5.24xlarge",

    "db.r6i.large",
    "db.r6i.xlarge",
    "db.r6i.2xlarge",
    "db.r6i.4xlarge",
    "db.r6i.8xlarge",
    "db.r6i.12xlarge",
    "db.r6i.16xlarge",
    "db.r6i.24xlarge",
    "db.r6i.32xlarge"
  ]
}
variable "instance_class" {
  description = "Instance class for cluster instances."
  type        = string
  default     = "db.r6g.large"
  validation {
    condition     = contains(var.allowed_instance_classes, var.instance_class)
    error_message = "Invalid instance_class. Must be one of allowed_instance_classes. Consider a Graviton class such as db.r6g.large or db.r7g.large."
  }
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

variable "db_master_password" {
  description = "Master password. Must be 8-41 printable ASCII characters, excluding '/', '@', '\"', and space."
  type        = string
  sensitive   = true
  default     = null
  validation {
    condition = var.db_master_password == null || (
      length(var.db_master_password) >= 8 &&
      can(regex("^[\\x20-\\x7E]+$", var.db_master_password)) && # printable ASCII 0x20-0x7E
      !can(regex("[/@\" ]", var.db_master_password))            # exclude '/', '@', '\"', and space
    )
    error_message = "db_master_password must be printable ASCII (0x20-0x7E), at least 8 characters, and must not contain '/', '@', '\"', or any spaces."
  }
}

# Option to auto-generate a compliant password if none provided
variable "generate_master_password" {
  description = "If true and db_master_password is null, generate a compliant random password."
  type        = bool
  default     = true
}
variable "generated_password_length" {
  description = "Length of generated master password."
  type        = number
  default     = 24
}
variable "use_existing_kms_key" {
  description = "Use an existing KMS key instead of creating one."
  type        = bool
  # default     = false
}

variable "existing_kms_key_arn" {
  description = "ARN of existing KMS key."
  type        = string
  # default     = null
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
  # default     = true
}

variable "rotation_days" {
  description = "Automatic secrets rotation interval in days."
  type        = number
  default     = 180
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
  default     = false
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

variable "additional_cluster_parameters" {
  description = "Additional cluster parameters."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "skip_final_snapshot" {
  description = "Skip taking a final snapshot on cluster deletion. Set to false in production."
  type        = bool
  default     = true
}

variable "final_snapshot_identifier" {
  description = "Identifier for the final snapshot when skip_final_snapshot is false."
  type        = string
  default     = null
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
