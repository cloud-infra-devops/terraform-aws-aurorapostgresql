```markdown
# terraform-aws-aurora-postgres-cluster

This Terraform module provisions an Amazon Aurora PostgreSQL cluster with:

- Optional creation of a KMS Customer Master Key (CMK) or use of an existing CMK
- Storage of DB master credentials in AWS Secrets Manager encrypted with the KMS key
- Automatic secret creation and rotation using either:
  - an AWS-managed rotation Lambda (default auto-constructed ARN), or
  - an optional rotation Lambda deployed into this module (providing predictable VPC access)
- Optional creation of an interface VPC Endpoint for AWS Secrets Manager so secret traffic between the rotation Lambda and Secrets Manager remains inside your VPC
- Creation of a dedicated Security Group for the Secrets Manager VPC Endpoint that opens only TCP/443 from explicitly allowed sources
- If you opt in to deploy the rotation Lambda in this module, the rotation Lambda will be created with:
  - its own security group (attached to same VPC/subnets you provide),
  - an IAM role with least-privilege-ish permissions required to run rotation (review & tighten to match your security posture),
  - a lambda permission that allows Secrets Manager to invoke it,
  - automatic addition of the rotation Lambda SG to the allowed list for the Secrets Manager VPC Endpoint.
- Narrowed endpoint SG egress using the AWS-managed Secrets Manager prefix list so endpoint ENIs only egress to the Secrets Manager service IP ranges in your region (least-privilege egress).
- Optional CloudWatch Logs export for PostgreSQL logs (errors & slow queries) and creation of CloudWatch metric filters and an example alarm.

Important usage notes
- Rotation Lambda code: this module can deploy a rotation Lambda for you, but you must provide the Lambda code as an S3 object (bucket/key and optional object version). The module will create the Lambda function and required IAM role and VPC configuration. If you prefer to use an existing rotation Lambda (for example AWS-managed rotator or your own pre-deployed function), do not enable create_rotation_lambda and instead pass the rotation lambda ARN via `rotation_lambda_arn` and include its SG in `allowed_vpc_endpoint_source_security_group_ids`.
- Networking: The rotation Lambda (whether created here or external) must have VPC subnets and SGs that allow it to connect to the DB instances (port 5432 by default). If you create the rotation Lambda here the module will create a SG that allows outbound to the DB security group on the DB port.
- KMS: If you create a CMK via this module we add KMS permissions for Secrets Manager, RDS and the configured rotation-lambda account. Review and tighten the KMS key policy as required by your security policy.
- Review IAM policies: The module attempts to follow least privilege but rotating DB credentials requires a few broad permissions (secretsmanager actions against the secret and logs). Review the IAM role policy for the Lambda and tighten resources/actions to comply with your corporate security policy.

Example (create rotation Lambda in-module)
```hcl
module "db" {
  source = "./terraform-aws-aurora-postgres-cluster"

  name                   = "prod-db"
  vpc_id                 = "vpc-0example"
  subnet_ids             = ["subnet-aaa", "subnet-bbb"]
  vpc_security_group_ids = ["sg-db-app"]
  master_username        = "dbadmin"
  database_name          = "appdb"

  create_kms_key         = true

  # Secrets Manager VPC endpoint
  create_secretsmanager_vpc_endpoint = true
  # allowed inbound sources for the endpoint (module will append rotation lambda SG automatically if created)
  allowed_vpc_endpoint_source_security_group_ids = ["sg-app-01"]

  # Create rotation Lambda inside this module and provide S3 code
  create_rotation_lambda   = true
  rotation_lambda_s3_bucket = "my-lambda-code-bucket"
  rotation_lambda_s3_key    = "secrets-rotation/SecretsManagerPostgreSQLRotationSingleUser.zip"
  rotation_lambda_runtime   = "python3.9"
  rotation_lambda_handler   = "lambda_function.lambda_handler"
  rotation_lambda_subnet_ids = ["subnet-aaa","subnet-bbb"]
  rotation_lambda_environment = {
    LOG_LEVEL = "INFO"
  }
}
```

What I added in this update
- create_rotation_lambda option: when true the module deploys a rotation Lambda using the S3 object you provide.
- Lambda IAM role & policy: a least-privilege-ish role scoped to the secret (and KMS key when present) and CloudWatch Logs.
- Lambda SG: created in the VPC/subnets you supply; configured to allow outbound to:
  - the DB security group on DB port,
  - the Secrets Manager service via the regional Secrets Manager prefix list (bound to 443).
- The Secrets Manager interface VPC endpoint SG's egress is narrowed to use the Secrets Manager prefix list (so endpoint ENIs only egress to Secrets Manager IP ranges).
- The rotation Lambda SG is automatically added to the allowed sources for the Secrets Manager endpoint.
- The module creates an aws_lambda_permission to allow Secrets Manager to invoke the Lambda.
- Outputs for the deployed Lambda ARN, SG id and IAM role.

Next steps / recommendations
1. Supply rotation Lambda code as an S3 object (bucket/key). The AWS-provided rotator zip can be used if you obtain it; otherwise reuse your own implementation that adheres to the Secrets Manager rotation function interface (createSecret, setSecret, testSecret, finishSecret).
2. Review IAM policies added for the Lambda and tighten if you can scope more strictly.
3. Confirm network connectivity (subnets and routing) between Lambda and DB and the endpoint.
4. If you want, I can add an optional automatic upload of the AWS-managed rotator code into S3 from a known public location (if you provide the public URL), or include example helper scripts to build/package the rotation lambda.
```