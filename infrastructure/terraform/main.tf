# CyberShield-IronCore Terraform Infrastructure
# Enterprise-grade AWS infrastructure for $1B-$2B acquisition target
# Built for Fortune 500 companies with 99.99% uptime SLA

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    # Terraform state backend - configure via terraform init
    # bucket = "cybershield-terraform-state-${random_id.suffix.hex}"
    # key    = "infrastructure/terraform.tfstate"
    # region = var.aws_region
    # dynamodb_table = "cybershield-terraform-locks"
    # encrypt = true
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project      = "CyberShield-IronCore"
      Environment  = var.environment
      Owner        = "AI-Driven Development"
      Purpose      = "Enterprise Cybersecurity Platform"
      Acquisition  = "Palo-Alto-Networks-Target"
      IronMan      = "Ready-To-Glitch-The-Matrix"
      ManagedBy    = "Terraform"
      CreatedBy    = "Claude-AI"
    }
  }
}

# Data sources for existing AWS resources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Random suffix for unique resource naming
resource "random_id" "suffix" {
  byte_length = 4
}

# Local values for resource naming and configuration
locals {
  name_prefix = "cybershield-${var.environment}"
  common_tags = {
    Project     = "CyberShield-IronCore"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "CyberShield-Team"
  }
  
  # Network configuration
  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  
  # EKS configuration
  cluster_version = "1.28"
  node_groups = {
    cybershield_nodes = {
      instance_types = ["t3.large", "t3.xlarge"]
      capacity_type  = "ON_DEMAND"
      min_size      = 2
      max_size      = 10
      desired_size  = 3
    }
    
    threat_processing = {
      instance_types = ["c5.2xlarge", "c5.4xlarge"]
      capacity_type  = "SPOT"
      min_size      = 1
      max_size      = 20
      desired_size  = 2
      
      # Taints for specialized workloads
      taints = {
        dedicated = {
          key    = "workload-type"
          value  = "threat-processing"
          effect = "NO_SCHEDULE"
        }
      }
    }
  }
  
  # Database configuration
  db_config = {
    engine         = "postgres"
    engine_version = "15.4"
    instance_class = var.environment == "production" ? "db.r6g.2xlarge" : "db.t3.large"
    allocated_storage = var.environment == "production" ? 1000 : 100
    max_allocated_storage = var.environment == "production" ? 10000 : 1000
    
    # High availability for production
    multi_az               = var.environment == "production"
    backup_retention_period = var.environment == "production" ? 30 : 7
    backup_window          = "03:00-04:00"
    maintenance_window     = "Sun:04:00-Sun:05:00"
    
    # Performance insights
    performance_insights_enabled = true
    performance_insights_retention_period = var.environment == "production" ? 731 : 7
  }
  
  # Redis configuration
  redis_config = {
    node_type = var.environment == "production" ? "cache.r6g.large" : "cache.t3.micro"
    num_cache_nodes = var.environment == "production" ? 3 : 1
    parameter_group_name = "default.redis7"
    port = 6379
    
    # High availability for production
    automatic_failover_enabled = var.environment == "production"
    multi_az_enabled = var.environment == "production"
  }
}