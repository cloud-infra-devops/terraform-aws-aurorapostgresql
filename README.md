# AWS Aurora PostgreSQL Terraform Module

This Terraform module creates a highly secure, multi-AZ AWS Aurora PostgreSQL cluster with comprehensive monitoring, automated secret rotation, and VPC endpoint encryption.

## Features

- **Multi-AZ Aurora PostgreSQL Cluster**: Highly available database cluster across multiple availability zones
- **AWS Secrets Manager Integration**: Secure storage of database credentials with KMS encryption
- **Automated Secret Rotation**: Optional 90-day rotation using AWS managed Lambda function
- **VPC Endpoint Security**: All traffic between services stays within VPC using interface endpoints
- **Comprehensive Monitoring**: CloudWatch alarms for all critical Aurora PostgreSQL metrics
- **Least Privilege Security**: Security groups and IAM policies following principle of least privilege
- **KMS Encryption**: Customer-managed KMS keys for encryption at rest and in transit

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           VPC                                   │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │   Private       │    │   Private       │                    │
│  │   Subnet AZ-1   │    │   Subnet AZ-2   │                    │
│  │                 │    │                 │                    │
│  │ ┌─────────────┐ │    │ ┌─────────────┐ │                    │
│  │ │   Aurora    │ │    │ │   Aurora    │ │                    │
│  │ │ Writer Node │ │    │ │ Reader Node │ │                    │
│  │ └─────────────┘ │    │ └─────────────┘ │                    │
│  │                 │    │                 │                    │
│  │ ┌─────────────┐ │    │                 │                    │
│  │ │   Lambda    │ │    │                 │                    │
│  │ │  Rotator    │ │    │                 │                    │
│  │ └─────────────┘ │    │                 │                    │
│  └─────────────────┘    └─────────────────┘                    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                VPC Endpoints                            │   │
│  │  • Secrets Manager  • Lambda  • CloudWatch Logs       │   │
│  │  • KMS             • RDS      • EC2                    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Usage

```hcl
module "aurora_postgres_cluster" {
  source = "./aurorapostgreSQL"
  
  name                        = "my-app"
  vpc_id                      = "vpc-12345678"
  vpc_cidr                    = "10.0.0.0/16"
  aurora_db_subnet_ids        = ["subnet-12345678", "subnet-87654321"]
  vpc_endpoint_subnet_ids     = ["subnet-12345678", "subnet-87654321"]
  lambda_subnet_ids           = ["subnet-12345678", "subnet-87654321"]
  
  db_master_username          = "dbadmin"
  enable_auto_secrets_rotation = true
  rotation_days               = 90
  
  allowed_other_ingress_cidrs = ["10.0.0.0/8"]
  
  use_existing_kms_key        = false
  use_existing_aurora_db_sg   = false
  use_existing_vpce_sg        = false
  use_existing_lambda_rotator_sg = false
  
  existing_aurora_db_security_group_ids      = []
  existing_lambda_rotator_security_group_ids = []
  existing_vpce_security_group_ids           = []
  
  tags = {
    Environment = "production"
    Project     = "my-app"
  }
}
```

### Advanced Configuration

```hcl
module "aurora_postgres_cluster" {
  source = "./aurorapostgreSQL"
  
  # Basic Configuration
  name                        = "production-app"
  cluster_identifier          = "prod-app-aurora-pg"
  vpc_id                      = "vpc-12345678"
  vpc_cidr                    = "10.0.0.0/16"
  
  # Network Configuration
  aurora_db_subnet_ids        = ["subnet-12345678", "subnet-87654321"]
  vpc_endpoint_subnet_ids     = ["subnet-12345678", "subnet-87654321"]
  lambda_subnet_ids           = ["subnet-12345678", "subnet-87654321"]
  
  # Database Configuration
  db_master_username          = "dbadmin"
  database_name               = "appdb"
  port                        = 5432
  engine_version              = "17.7"
  instance_class              = "db.r6g.large"
  instance_count              = 2
  
  # Security Configuration
  allowed_other_ingress_cidrs = ["10.0.0.0/8", "172.16.0.0/12"]
  use_existing_kms_key        = false
  
  # Secrets Management
  enable_auto_secrets_rotation = true
  rotation_days               = 90
  
  # Backup Configuration
  backup_retention_days       = 30
  preferred_backup_window     = "03:00-04:00"
  preferred_maintenance_window = "sun:06:00-sun:11:00"
  skip_final_snapshot         = false
  deletion_protection         = true
  
  # Monitoring Configuration
  enable_metrics              = true
  enable_comprehensive_alarms = true
  enable_error_logs           = true
  enable_slow_query_logs      = true
  log_retention_days          = 30
  
  # Performance Configuration
  performance_insights_enabled = true
  monitoring_interval         = 60
  
  # Alarm Thresholds
  cpu_high_threshold          = 80
  memory_freeable_threshold   = 1073741824  # 1GB
  database_connections_threshold = 80
  read_latency_threshold      = 0.2
  write_latency_threshold     = 0.2
  
  tags = {
    Environment = "production"
    Project     = "my-app"
    Owner       = "platform-team"
  }
}
```

## Security Features

### 1. Network Security
- **VPC Endpoints**: All AWS service communication stays within VPC
- **Security Groups**: Least privilege access with specific port and protocol rules
- **Private Subnets**: Database instances deployed in private subnets only

### 2. Encryption
- **Encryption at Rest**: KMS customer-managed keys for database storage
- **Encryption in Transit**: SSL/TLS for all database connections
- **Secret Encryption**: Secrets Manager secrets encrypted with KMS

### 3. Access Control
- **IAM Roles**: Least privilege IAM roles for Lambda and services
- **Secret Policies**: Resource-based policies limiting secret access
- **Database Authentication**: Optional IAM database authentication

### 4. Secret Management
- **Automatic Rotation**: AWS managed Lambda function for secret rotation
- **Secure Storage**: Secrets stored in AWS Secrets Manager
- **Version Management**: Automatic secret version management during rotation

## Monitoring and Alerting

The module creates comprehensive CloudWatch alarms for:

- **Performance Metrics**:
  - CPU Utilization
  - Memory (Freeable Memory)
  - Database Connections
  - Read/Write Latency
  - Disk Queue Depth
  - Buffer Cache Hit Ratio

- **Availability Metrics**:
  - Aurora Replica Lag
  - Database Deadlocks
  - Swap Usage

- **Custom Metrics**:
  - Slow Query Count (via log metric filters)
  - Error Count (via log metric filters)

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.14.0 |
| aws | >= 6.28.0 |
| random | >= 3.7.2 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 6.28.0 |
| random | >= 3.7.2 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name | Base name for resources | `string` | n/a | yes |
| vpc_id | VPC ID for the cluster and endpoints | `string` | n/a | yes |
| vpc_cidr | VPC CIDR block | `string` | n/a | yes |
| aurora_db_subnet_ids | Private subnet IDs for the DB subnet group | `list(string)` | n/a | yes |
| vpc_endpoint_subnet_ids | Subnet IDs for VPC endpoints | `list(string)` | n/a | yes |
| db_master_username | Master username | `string` | n/a | yes |
| enable_auto_secrets_rotation | Enable automatic rotation | `bool` | n/a | yes |
| use_existing_kms_key | Use existing KMS key | `bool` | n/a | yes |
| use_existing_aurora_db_sg | Use existing Aurora DB security group | `bool` | n/a | yes |
| use_existing_vpce_sg | Use existing VPC endpoint security group | `bool` | n/a | yes |
| use_existing_lambda_rotator_sg | Use existing Lambda security group | `bool` | n/a | yes |
| existing_aurora_db_security_group_ids | Existing Aurora DB security group IDs | `list(string)` | n/a | yes |
| existing_lambda_rotator_security_group_ids | Existing Lambda security group IDs | `list(string)` | n/a | yes |
| existing_vpce_security_group_ids | Existing VPC endpoint security group IDs | `list(string)` | n/a | yes |
| allowed_other_ingress_cidrs | CIDR blocks allowed to connect to Aurora DB | `list(string)` | n/a | yes |
| cluster_identifier | Custom cluster identifier | `string` | `null` | no |
| database_name | Initial database name | `string` | `"appdb"` | no |
| db_master_password | Master password | `string` | `null` | no |
| generate_master_password | Generate random password if none provided | `bool` | `true` | no |
| existing_kms_key_arn | ARN of existing KMS key | `string` | `null` | no |
| port | PostgreSQL port | `number` | `5432` | no |
| engine_version | Aurora PostgreSQL engine version | `string` | `null` | no |
| instance_class | Instance class for cluster instances | `string` | `"db.r6g.large"` | no |
| instance_count | Number of instances in the cluster | `number` | `2` | no |
| rotation_days | Automatic secrets rotation interval in days | `number` | `180` | no |
| backup_retention_days | Backup retention in days | `number` | `7` | no |
| deletion_protection | Enable deletion protection | `bool` | `false` | no |
| enable_comprehensive_alarms | Enable comprehensive CloudWatch alarms | `bool` | `true` | no |
| tags | Tags to apply to resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| cluster_arn | Aurora PostgreSQL cluster ARN |
| cluster_endpoint | Writer endpoint |
| reader_endpoint | Reader endpoint |
| secret_arn | Secrets Manager secret ARN for master credentials |
| kms_key_arn | KMS key ARN used for encryption |
| vpc_endpoint_id | Interface VPC endpoint ID for Secrets Manager |
| db_security_group_id | Security group ID attached to the DB cluster |

## Secret Rotation

The module supports two modes for secret management:

### 1. Manual Rotation (Default)
Set `enable_auto_secrets_rotation = false` to disable automatic rotation. Database administrators can manually rotate secrets through the AWS Console or CLI.

### 2. Automatic Rotation
Set `enable_auto_secrets_rotation = true` and `rotation_days = 90` to enable automatic rotation every 90 days using AWS managed Lambda function.

## Best Practices

1. **Use Private Subnets**: Always deploy Aurora instances in private subnets
2. **Enable Deletion Protection**: Set `deletion_protection = true` for production
3. **Regular Backups**: Configure appropriate backup retention periods
4. **Monitor Alarms**: Set up SNS topics for alarm notifications
5. **Rotate Secrets**: Enable automatic secret rotation for enhanced security
6. **Use Latest Engine Version**: Keep Aurora PostgreSQL engine version updated
7. **Right-size Instances**: Choose appropriate instance classes based on workload

## Examples

See the `examples/` directory for complete usage examples:
- `examples/basic/` - Basic Aurora PostgreSQL cluster
- `examples/advanced/` - Production-ready configuration with all features
- `examples/existing-resources/` - Using existing KMS keys and security groups

## License

This module is licensed under the MIT License. See LICENSE file for details.