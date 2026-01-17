terraform {
  required_version = ">= 1.14.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.28.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.7.2"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}