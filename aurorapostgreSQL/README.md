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

## KMS CMK Encryption for Lambda Environment Variables

### Overview

This module implements AWS KMS Customer Master Key (CMK) encryption for Lambda environment variables in the Aurora PostgreSQL rotation Lambda function. This ensures that sensitive environment variables (like the KMS key ARN, RDS cluster ARN, and secret ARN) are encrypted at rest and in transit.

## Implementation Details

### 1. KMS Key Policy Update

The KMS CMK key policy has been updated to include the Lambda service principal, allowing Lambda functions to decrypt environment variables encrypted with this key.

**New KMS policy statement:**

```hcl
{
  Sid       = "AllowLambdaUseOfTheKey",
  Effect    = "Allow",
  Principal = { Service = "lambda.amazonaws.com" },
  Action = [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  Resource = "*"
}
```

### 2. Lambda Function Configuration

The `aws_lambda_function` resource now includes the `kms_key_arn` parameter, which specifies the KMS key to use for encrypting environment variables.

**Configuration:**

```hcl
resource "aws_lambda_function" "rotation" {
  # ... other configuration ...
  kms_key_arn = local.kms_key_arn
  
  environment {
    variables = {
      SECRET_ARN      = aws_secretsmanager_secret.db_master.arn
      RDS_CLUSTER_ARN = aws_rds_cluster.this.arn
      KMS_KEY_ARN     = local.kms_key_arn
      DB_ENGINE       = "postgres"
    }
  }
}
```

### 3. IAM Role Policy for Lambda

The Lambda execution role policy has been updated to include KMS permissions, allowing the Lambda function to decrypt environment variables at runtime.

**Updated IAM policy statement:**

```hcl
{
  Sid    = "AllowLambdaKMSDecryption",
  Effect = "Allow",
  Action = [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  Resource = local.kms_key_arn
}
```

## Environment Variables Encrypted

The following environment variables are now encrypted with the KMS CMK:

| Variable | Purpose |
|----------|---------|
| `SECRET_ARN` | ARN of the Secrets Manager secret containing database credentials |
| `RDS_CLUSTER_ARN` | ARN of the Aurora PostgreSQL cluster |
| `KMS_KEY_ARN` | ARN of the KMS CMK used for encryption |
| `DB_ENGINE` | Database engine type (postgres) |

## Lambda Function Access

When the Lambda function initializes, AWS Lambda automatically:

1. **Retrieves** encrypted environment variables from the Lambda environment
2. **Decrypts** them using the KMS key specified in `kms_key_arn`
3. **Injects** the decrypted variables into the function's environment

The decryption happens transparently before the Python handler code executes.

## Lambda Python Code Usage

The Lambda function code accesses these environment variables normally:

```python
import os

def lambda_handler(event, context):
    # These variables are automatically decrypted by Lambda runtime
    secret_arn = os.environ['SECRET_ARN']
    rds_cluster_arn = os.environ['RDS_CLUSTER_ARN']
    kms_key_arn = os.environ['KMS_KEY_ARN']
    db_engine = os.environ['DB_ENGINE']
    
    # Use decrypted values...
    service_client = boto3.client('secretsmanager')
    # ... rest of handler code ...
```

## Security Benefits

1. **Encryption at Rest**: Environment variables are encrypted using AWS KMS
2. **Key Management**: Uses the same CMK as the RDS cluster and Secrets Manager
3. **Least Privilege**: Lambda service principal only has Decrypt and DescribeKey permissions
4. **Audit Trail**: All KMS operations are logged to CloudTrail
5. **Automatic Decryption**: No manual decryption code needed in Lambda function

## IAM Permissions Summary

### Lambda Execution Role Permissions

The Lambda execution role has the following KMS permissions:

- **kms:Decrypt** - Decrypt environment variables
- **kms:DescribeKey** - Retrieve key metadata

These permissions are scoped to `local.kms_key_arn` (the specific KMS key).

## Key Rotation

The KMS CMK has automatic key rotation enabled (`enable_key_rotation = true`), which:

- Automatically rotates the key material annually
- Does not affect existing encrypted data
- Lambda functions can continue to decrypt environment variables with both old and new key material

## Cost Implications

KMS CMK encryption for Lambda environment variables includes:

1. **KMS Key Usage**: Standard KMS key usage charges ($1/month per key)
2. **API Calls**: Each Lambda invocation triggers a KMS decrypt operation
   - KMS API call costs apply (typically included in AWS Lambda pricing tiers)
   - Usually negligible for typical workloads

## Best Practices Applied

1. ✅ Use of CMK instead of AWS-managed keys
2. ✅ Automatic key rotation enabled
3. ✅ Minimal IAM permissions (principle of least privilege)
4. ✅ Service-to-service encryption (Lambda-to-KMS)
5. ✅ Integration with existing security infrastructure (same key as RDS, Secrets Manager)
6. ✅ Audit logging through CloudTrail

## Troubleshooting

### Lambda Execution Fails with "KMS" Error

**Symptoms**: Lambda function fails with error like `User: arn:aws:lambda:... is not authorized to perform: kms:Decrypt`

**Solutions**:

1. Verify the Lambda execution role has the `AllowLambdaKMSDecryption` policy
2. Verify the KMS key policy includes the Lambda service principal
3. Check CloudTrail logs for detailed KMS error messages

### Environment Variables Appear as "\<encrypted\>"

**Symptoms**: Environment variables in Lambda console show as `<encrypted>` instead of plaintext

**This is expected behavior** - AWS Lambda console masks encrypted environment variables for security. The actual function code receives the decrypted values.

## Related Resources

- **KMS Key**: `aws_kms_key.this` or existing KMS key specified by `var.existing_kms_key_arn`
- **Lambda Function**: `aws_lambda_function.rotation`
- **Lambda Execution Role**: `aws_iam_role.lambda_exec`
- **Lambda VPC Policy**: `aws_iam_role_policy.lambda_vpc`

## Configuration Variables

To modify KMS encryption behavior, adjust these variables in `variables.tf`:

- `use_existing_kms_key`: Set to `true` to use an existing CMK (default: `false`)
- `existing_kms_key_arn`: ARN of existing KMS key (used when `use_existing_kms_key = true`)
- `kms_deletion_window_in_days`: Days until KMS key is deleted after scheduling deletion (default: 30)
