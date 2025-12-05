# Aurora PostgreSQL Cluster Terraform Module

This module creates a production-ready Aurora PostgreSQL cluster with:
- Encryption at rest via KMS (new CMK or existing CMK)
- Secrets Manager secret for master credentials (encrypted with KMS)
- Optional automatic rotation using AWS managed single-user Lambda rotator every N days
- Least-privilege IAM roles and resource policies
- CloudWatch Logs export for error/slow query logs
- Optional CloudWatch metrics and alarms, including custom slow query metrics
- Interface VPC Endpoint for Secrets Manager to keep rotation calls private

## Usage

```hcl
module "aurora_postgres_cluster" {
  source = "./modules/aurora-postgres"

  name                      = "prod-app"
  region                    = "us-east-1"
  vpc_id                    = "vpc-0123456789abcdef0"
  subnet_ids                = ["subnet-a", "subnet-b", "subnet-c"]
  vpc_endpoint_subnet_ids   = ["subnet-a", "subnet-b"]
  lambda_subnet_ids         = ["subnet-a", "subnet-b"]

  allowed_cidr_blocks       = ["10.0.0.0/16"]
  allowed_security_group_ids = []

  db_master_username        = "masteruser"
  db_master_password        = "S3cureP@ssw0rd!"
  database_name             = "appdb"

  use_existing_kms_key      = false
  # existing_kms_key_arn    = "arn:aws:kms:us-east-1:111111111111:key/abcd-efgh..."

  enable_rotation           = true
  rotation_days             = 90
  rotation_lambda_zip       = "${path.module}/rotation_lambda.zip" # Provide AWS sample zip or your packaged rotation function

  enable_error_logs         = true
  enable_slow_query_logs    = true
  enable_slow_query_metrics = true

  alarm_action_arns         = ["arn:aws:sns:us-east-1:111111111111:alerts"]

  tags = {
    Environment = "prod"
    Application = "my-app"
  }
}
```

To disable automatic rotation and rely on manual rotation in AWS Secrets Manager:
```hcl
enable_rotation = false
```

## Rotation Lambda

This module expects a ZIP for the rotation Lambda. Use the AWS sample for single-user rotation for RDS/Aurora PostgreSQL from AWS docs, or package your own with the standard handler interface. Ensure the Lambda has VPC access to your Secrets Manager VPC Endpoint and to the RDS cluster as necessary.

Alternatively, if you want to point to an existing rotation Lambda ARN, you can adapt the module by replacing the `aws_lambda_function.rotation` resource with a `variable "rotation_lambda_arn"` and set it in `aws_secretsmanager_secret_rotation`.

## Inputs

See `variables.tf` for the full list. Key inputs:
- `use_existing_kms_key` and `existing_kms_key_arn` to use an existing CMK.
- `db_master_username`, `db_master_password` for initial bootstrap; then stored in Secrets Manager.
- `enable_rotation`, `rotation_days` control automatic rotation (default 90 days). Set `enable_rotation=false` for manual rotation.
- `enable_error_logs`, `enable_slow_query_logs` for CloudWatch Logs export.
- `enable_slow_query_metrics`, `slow_query_filter_pattern`, `slow_query_threshold` to create custom metrics from logs.

## Least Privilege

- KMS key policy grants only necessary services (RDS and Secrets Manager via service conditions) and account root.
- Secret resource policy limits access to the rotation role and root for read.
- Rotation role policy scopes permissions to the specific secret and cluster ARNs.

## VPC Endpoint

A private Interface VPC Endpoint for Secrets Manager is created to keep rotation traffic within your VPC. The Lambda is configured for VPC access and can communicate with Secrets Manager through this endpoint.

## Notes

- Aurora PostgreSQL supports CloudWatch Logs export for `postgresql` logs; slow query detection is implemented via log filter patterns.
- Ensure subnets provided are private and have appropriate routing to support VPC endpoints and Lambda ENIs.
- Supply a valid `rotation_lambda_zip` file; AWS provides sample implementations.

## Outputs

- `cluster_arn`, `cluster_endpoint`, `reader_endpoint`
- `secret_arn`, `kms_key_arn`
- `vpc_endpoint_id`, `db_security_group_id`