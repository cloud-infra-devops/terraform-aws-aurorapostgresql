module "AuroraPostgreSQL" {
  source                  = "./aurorapostgreSQL"
  name                    = "my-aurora-cluster"
  rotation_lambda_account = "679388152427"
  vpc_id                  = "vpc-07b3e9e8021bfb088"
  subnet_ids              = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
}
