terraform {
  required_version = ">= 1.14.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.25.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
  }
}

provider "aws" {
  region              = "us-west-2"
  allowed_account_ids = ["211125325120"]
}

module "aurora_postgres_cluster" {
  source = "./aurorapostgreSQL"

  name                    = "duke-app"
  vpc_id                  = "vpc-07b3e9e8021bfb088"
  vpc_cidr                = "172.16.0.0/16"
  subnet_ids              = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  vpc_endpoint_subnet_ids = ["subnet-0260bb197628ace27", "subnet-0d316885c8257bf12"]
  db_master_username      = "Admin"
  byte_length             = 3
  tags = {
    Environment = "prod"
    Owner       = "cloud-infra-devops"
  }
}
