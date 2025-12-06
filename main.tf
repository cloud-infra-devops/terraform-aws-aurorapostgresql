terraform {
  required_version = ">= 1.14.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.25.0"
    }
  }
  cloud {
    organization = "cloud-infra-dev"
    workspaces {
      name    = "testing-terraform-aws-modules" # Workspace with VCS driven workflow
      project = "AWS-Cloud-IaC"
    }
  }
}

provider "aws" {
  region              = "us-west-2"
  allowed_account_ids = ["211125325120"]
}

module "aurora_postgres_cluster" {
  source = "./aurorapostgreSQL"

  name                                = "duke-app"
  vpc_id                              = "vpc-07b3e9e8021bfb088"
  vpc_cidr                            = "172.16.0.0/16"
  allowed_other_ingress_cidrs         = ["10.0.0.0/8", "192.168.0.0/16"]
  allowed_existing_security_group_ids = []
  subnet_ids                          = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  vpc_endpoint_subnet_ids             = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  db_master_username                  = "postgreSQLdbAdmin"
  enable_auto_secrets_rotation        = true
  use_existing_kms_key                = false
  existing_kms_key_arn                = []
  tags = {
    Environment = "sbx"
    Owner       = "cloud-infra-devops"
  }
}
