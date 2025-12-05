variable "name" {
  description = "Base name for resources (prefix)."
  type        = string
}
variable "secretsmanager_prefix_list_id" {
  description = "Optional regional EC2 managed prefix list id for AWS Secrets Manager (e.g. pl-0123456789abcdef0). If provided, endpoint and Lambda egress will be restricted to this prefix list. If empty, module will allow 0.0.0.0/0 egress as a fallback."
  type        = string
  default     = ""
}
variable "vpc_cidr" {
  type    = string
  default = "172.16.0.0/16"
}
variable "vpc_id" {
  description = "VPC id where DB, rotation lambda and Secrets Manager VPC endpoint will be created."
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for the DB subnet group and for the Secrets Manager interface endpoint (must be at least 2)."
  type        = list(string)
  default     = []
}

variable "engine" {
  description = "RDS engine to use. (aurora-postgresql)"
  type        = string
  default     = "aurora-postgresql"
}

variable "engine_version" {
  description = "Engine version for the Aurora PostgreSQL cluster."
  type        = string
  default     = "16.10"
}

variable "instance_class" {
  description = "Instance class for cluster instances."
  type        = string
  default     = "db.r5.large"
}

variable "instance_count" {
  description = "Number of instances (including writer)."
  type        = number
  default     = 2
}

variable "vpc_security_group_ids" {
  description = "List of existing VPC security group IDs for the cluster instances."
  type        = list(string)
  default     = []
}

variable "master_username" {
  description = "Initial master username for the database."
  type        = string
  default     = "masteruser"
}

variable "database_name" {
  description = "Initial database name to create."
  type        = string
  default     = "postgres"
}

variable "port" {
  description = "Database port."
  type        = number
  default     = 5432
}

variable "create_kms_key" {
  description = "Whether to create a new KMS CMK for encrypting the DB & secrets. If false, provide existing_kms_key_id."
  type        = bool
  default     = true
}

variable "existing_kms_key_id" {
  description = "If not creating a new KMS key, supply an existing KMS key ID or ARN to use for encryption."
  type        = string
  default     = ""
}

variable "use_secrets_manager" {
  type        = bool
  description = "Enable integration with AWS Secrets Manager for managing DB credentials"
  default     = true
}

variable "existing_secret_arn" {
  type        = string
  description = "ARN of an existing Secrets Manager secret to use; leave empty to create or manage within the module"
  default     = ""
}

variable "secret_rotation_enabled" {
  type        = bool
  description = "Enable secret rotation for the selected implementation (managed, existing, or module-managed)."
  default     = true
}

variable "create_secretsmanager_vpc_endpoint" {
  description = "Create an interface VPC endpoint for Secrets Manager to keep Secrets API traffic inside the VPC."
  type        = bool
  default     = true
}

variable "allowed_vpc_endpoint_source_security_group_ids" {
  description = "Security group IDs that are allowed to connect to the Secrets Manager VPC endpoint on TCP/443 (e.g., rotation Lambda SG, app SG). Keep this minimal to follow least privilege."
  type        = list(string)
  default     = []
}

variable "allowed_vpc_endpoint_source_cidr_blocks" {
  description = "CIDR blocks that can reach the Secrets Manager VPC endpoint on TCP/443 (optional). Keep empty unless explicitly needed."
  type        = list(string)
  default     = []
}

# Input variable to control creation of rotation Lambda
variable "create_rotation_lambda" {
  description = "If true, the module will deploy a rotation Lambda into your account using a provided S3 object (bucket/key)."
  type        = bool
  default     = false
}

variable "rotation_lambda_account" {
  description = "AWS account where the AWS-managed rotation lambdas are hosted for constructing the default ARN. Override if needed."
  type        = string
  # default     = "464417241295"
}

variable "rotation_lambda_subnet_ids" {
  description = "Subnets for the rotation Lambda VPC config. Required if create_rotation_lambda is true and you want Lambda in VPC (recommended)."
  type        = list(string)
  default     = []
}

variable "rotation_lambda_environment" {
  description = "Map of environment variables to set on the rotation Lambda (optional)."
  type        = map(string)
  default     = {}
}

variable "rotation_lambda_s3_bucket" {
  description = "S3 bucket containing the rotation Lambda zip. Required if create_rotation_lambda is true."
  type        = string
  default     = ""
}

variable "rotation_lambda_s3_key" {
  description = "S3 key for the rotation Lambda zip. Required if create_rotation_lambda is true."
  type        = string
  default     = ""
}

variable "rotation_lambda_s3_object_version" {
  description = "Optional S3 object version for the rotation Lambda zip."
  type        = string
  default     = ""
}

variable "rotation_lambda_runtime" {
  description = "Runtime for the rotation Lambda (e.g., python3.9)."
  type        = string
  default     = "python3.9"
}

variable "rotation_lambda_handler" {
  description = "Handler for the rotation Lambda (e.g., lambda_function.lambda_handler)."
  type        = string
  default     = "lambda_function.lambda_handler"
}

# ARN of an existing Secrets Manager rotation Lambda (leave empty to use managed/module lambda)
variable "existing_rotation_lambda_arn" {
  type        = string
  description = "ARN of an existing Secrets Manager rotation Lambda to use for secret rotation; if empty, use AWS-managed or module-managed Lambda."
  default     = ""
}

# Input variable to control use of AWS-managed Secrets Manager rotation function
variable "use_aws_managed_rotation" {
  type        = bool
  description = "Whether to use the AWS-managed Secrets Manager rotation Lambda when available."
  default     = true
}

variable "rotation_days" {
  description = "How many days before Secrets Manager rotates credentials automatically."
  type        = number
  default     = 180
}

variable "enable_error_log_export" {
  description = "Enable CloudWatch error log export & metric filter."
  type        = bool
  default     = false
}

variable "enable_slow_log_export" {
  description = "Enable CloudWatch slow query log export & metric filter."
  type        = bool
  default     = false
}

variable "log_retention_in_days" {
  description = "Retention in days for the created CloudWatch Log Groups. 0 = never expire."
  type        = number
  default     = 1
}

variable "metric_namespace" {
  description = "CloudWatch Metrics namespace for log-derived metrics."
  type        = string
  default     = "RDS/Postgres"
}

variable "enable_cloudwatch_alarms" {
  description = "Create an example CloudWatch alarm for the error metric (optional)."
  type        = bool
  default     = false
}

variable "error_alarm_threshold" {
  description = "Threshold for error alarm (number of errors) within evaluation period."
  type        = number
  default     = 1
}

variable "error_alarm_evaluation_periods" {
  description = "Evaluation periods for the error alarm."
  type        = number
  default     = 1
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}

