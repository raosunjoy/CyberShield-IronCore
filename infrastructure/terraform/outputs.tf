# CyberShield-IronCore Terraform Outputs
# Enterprise infrastructure outputs for application deployment and integration

# VPC and Network Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "private_subnets" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnets" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "database_subnets" {
  description = "IDs of the database subnets"
  value       = aws_subnet.database[*].id
}

output "private_subnet_cidrs" {
  description = "CIDR blocks of the private subnets"
  value       = aws_subnet.private[*].cidr_block
}

output "public_subnet_cidrs" {
  description = "CIDR blocks of the public subnets"
  value       = aws_subnet.public[*].cidr_block
}

output "database_subnet_cidrs" {
  description = "CIDR blocks of the database subnets"
  value       = aws_subnet.database[*].cidr_block
}

output "nat_gateway_ips" {
  description = "IP addresses of the NAT gateways"
  value       = aws_eip.nat[*].public_ip
}

# EKS Cluster Outputs
output "cluster_id" {
  description = "EKS cluster ID"
  value       = aws_eks_cluster.main.id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = aws_eks_cluster.main.arn
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "cluster_iam_role_name" {
  description = "IAM role name associated with EKS cluster"
  value       = aws_iam_role.eks_cluster.name
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN associated with EKS cluster"
  value       = aws_iam_role.eks_cluster.arn
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = aws_eks_cluster.main.certificate_authority[0].data
}

output "cluster_primary_security_group_id" {
  description = "The cluster primary security group ID created by the EKS cluster"
  value       = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "cluster_version" {
  description = "The Kubernetes version for the EKS cluster"
  value       = aws_eks_cluster.main.version
}

output "cluster_platform_version" {
  description = "Platform version for the EKS cluster"
  value       = aws_eks_cluster.main.platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster. One of `CREATING`, `ACTIVE`, `DELETING`, `FAILED`"
  value       = aws_eks_cluster.main.status
}

output "oidc_provider_arn" {
  description = "The ARN of the OIDC Provider if enabled"
  value       = aws_iam_openid_connect_provider.eks_oidc.arn
}

# Node Group Outputs
output "node_groups" {
  description = "EKS node group information"
  value = {
    for k, v in aws_eks_node_group.main : k => {
      arn           = v.arn
      status        = v.status
      capacity_type = v.capacity_type
      instance_types = v.instance_types
      scaling_config = v.scaling_config
    }
  }
}

output "node_security_group_id" {
  description = "ID of the node shared security group"
  value       = aws_security_group.eks_nodes.id
}

# Database Outputs
output "db_instance_address" {
  description = "RDS instance hostname"
  value       = aws_db_instance.main.address
  sensitive   = true
}

output "db_instance_arn" {
  description = "RDS instance ARN"
  value       = aws_db_instance.main.arn
}

output "db_instance_availability_zone" {
  description = "RDS instance availability zone"
  value       = aws_db_instance.main.availability_zone
}

output "db_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "db_instance_engine" {
  description = "RDS instance engine"
  value       = aws_db_instance.main.engine
}

output "db_instance_engine_version" {
  description = "RDS instance engine version"
  value       = aws_db_instance.main.engine_version
}

output "db_instance_id" {
  description = "RDS instance ID"
  value       = aws_db_instance.main.id
}

output "db_instance_resource_id" {
  description = "RDS instance resource ID"
  value       = aws_db_instance.main.resource_id
}

output "db_instance_status" {
  description = "RDS instance status"
  value       = aws_db_instance.main.status
}

output "db_instance_name" {
  description = "RDS instance name"
  value       = aws_db_instance.main.db_name
}

output "db_instance_username" {
  description = "RDS instance root username"
  value       = aws_db_instance.main.username
  sensitive   = true
}

output "db_instance_port" {
  description = "RDS instance port"
  value       = aws_db_instance.main.port
}

output "db_subnet_group_id" {
  description = "RDS subnet group name"
  value       = aws_db_subnet_group.main.id
}

output "db_subnet_group_arn" {
  description = "RDS subnet group ARN"
  value       = aws_db_subnet_group.main.arn
}

output "db_parameter_group_id" {
  description = "RDS parameter group name"
  value       = aws_db_parameter_group.main.id
}

output "db_parameter_group_arn" {
  description = "RDS parameter group ARN"
  value       = aws_db_parameter_group.main.arn
}

output "db_enhanced_monitoring_iam_role_arn" {
  description = "The Amazon Resource Name (ARN) specifying the monitoring role"
  value       = var.enable_monitoring ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
}

# Read Replica Outputs (Production only)
output "db_instance_replica_address" {
  description = "RDS replica instance hostname"
  value       = var.environment == "production" ? aws_db_instance.read_replica[0].address : null
  sensitive   = true
}

output "db_instance_replica_arn" {
  description = "RDS replica instance ARN"
  value       = var.environment == "production" ? aws_db_instance.read_replica[0].arn : null
}

output "db_instance_replica_endpoint" {
  description = "RDS replica instance endpoint"
  value       = var.environment == "production" ? aws_db_instance.read_replica[0].endpoint : null
  sensitive   = true
}

# Redis Outputs
output "redis_cluster_address" {
  description = "Redis cluster address"
  value = var.environment == "production" ? (
    length(aws_elasticache_replication_group.main) > 0 ? aws_elasticache_replication_group.main[0].primary_endpoint_address : null
  ) : (
    length(aws_elasticache_cluster.main) > 0 ? aws_elasticache_cluster.main[0].cache_nodes[0].address : null
  )
  sensitive = true
}

output "redis_cluster_port" {
  description = "Redis cluster port"
  value       = var.redis_port
}

output "redis_parameter_group_id" {
  description = "Redis parameter group name"
  value       = aws_elasticache_parameter_group.main.id
}

output "redis_subnet_group_name" {
  description = "Redis subnet group name"
  value       = aws_elasticache_subnet_group.main.name
}

# Security Outputs
output "kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the KMS key"
  value       = aws_kms_key.eks.arn
}

output "kms_key_id" {
  description = "The globally unique identifier for the KMS key"
  value       = aws_kms_key.eks.key_id
}

output "rds_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the RDS KMS key"
  value       = aws_kms_key.rds.arn
}

output "rds_kms_key_id" {
  description = "The globally unique identifier for the RDS KMS key"
  value       = aws_kms_key.rds.key_id
}

# Secrets Manager Outputs
output "db_password_secret_arn" {
  description = "Database password secret ARN"
  value       = aws_secretsmanager_secret.db_password.arn
  sensitive   = true
}

output "db_password_secret_name" {
  description = "Database password secret name"
  value       = aws_secretsmanager_secret.db_password.name
  sensitive   = true
}

output "redis_auth_token_secret_arn" {
  description = "Redis auth token secret ARN"
  value       = aws_secretsmanager_secret.redis_auth_token.arn
  sensitive   = true
}

output "redis_auth_token_secret_name" {
  description = "Redis auth token secret name"
  value       = aws_secretsmanager_secret.redis_auth_token.name
  sensitive   = true
}

# Monitoring Outputs
output "sns_topic_alerts_arn" {
  description = "SNS topic ARN for critical alerts"
  value       = var.enable_monitoring ? aws_sns_topic.alerts[0].arn : null
}

output "sns_topic_security_alerts_arn" {
  description = "SNS topic ARN for security alerts"
  value       = var.enable_monitoring ? aws_sns_topic.security_alerts[0].arn : null
}

output "cloudwatch_dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = var.enable_monitoring ? "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main[0].dashboard_name}" : null
}

output "cloudwatch_log_groups" {
  description = "CloudWatch log groups created"
  value = {
    vpc_flow_logs   = var.enable_logging ? aws_cloudwatch_log_group.vpc_flow_log[0].name : null
    eks_cluster     = var.enable_logging ? aws_cloudwatch_log_group.eks_cluster[0].name : null
    application     = var.enable_logging ? aws_cloudwatch_log_group.application[0].name : null
    postgresql      = var.enable_logging ? aws_cloudwatch_log_group.postgresql[0].name : null
    redis_slow_log  = var.enable_logging ? aws_cloudwatch_log_group.redis_slow[0].name : null
  }
}

# Iron Man Style Outputs (because we're badass)
output "jarvis_status" {
  description = "JARVIS system status report"
  value = {
    arc_reactor_status    = "Online"
    suit_integrity       = "100%"
    threat_detection     = "Active"
    defensive_systems    = "Armed"
    ai_assistance        = "Operational"
    cluster_name         = aws_eks_cluster.main.name
    database_engine      = "PostgreSQL Powered"
    cache_system         = "Redis Accelerated"
    security_level       = "Vibranium Grade"
    acquisition_ready    = "Palo Alto Networks Target Lock"
    iron_man_quote       = "I am Iron Man. I am CyberShield."
  }
}

output "deployment_summary" {
  description = "Complete deployment summary for DevOps teams"
  value = {
    environment           = var.environment
    region               = var.aws_region
    vpc_id               = aws_vpc.main.id
    cluster_endpoint     = aws_eks_cluster.main.endpoint
    database_endpoint    = aws_db_instance.main.endpoint
    redis_endpoint       = var.environment == "production" ? (
      length(aws_elasticache_replication_group.main) > 0 ? aws_elasticache_replication_group.main[0].primary_endpoint_address : null
    ) : (
      length(aws_elasticache_cluster.main) > 0 ? aws_elasticache_cluster.main[0].cache_nodes[0].address : null
    )
    monitoring_enabled   = var.enable_monitoring
    logging_enabled      = var.enable_logging
    encryption_enabled   = var.enable_encryption
    multi_az_enabled     = local.db_config.multi_az
    backup_enabled       = true
    security_compliant   = true
    iron_man_approved    = true
    ready_for_production = var.environment == "production"
  }
  sensitive = true
}

# Kubectl Configuration Command
output "kubectl_config_command" {
  description = "Command to configure kubectl for this EKS cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.main.name}"
}

# Connection Strings for Applications
output "connection_info" {
  description = "Connection information for applications (use with caution - contains sensitive data)"
  value = {
    postgres_connection_string = "postgresql://${aws_db_instance.main.username}@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}"
    redis_connection_string    = var.environment == "production" ? (
      length(aws_elasticache_replication_group.main) > 0 ? 
      "redis://${aws_elasticache_replication_group.main[0].primary_endpoint_address}:${var.redis_port}" : 
      null
    ) : (
      length(aws_elasticache_cluster.main) > 0 ? 
      "redis://${aws_elasticache_cluster.main[0].cache_nodes[0].address}:${var.redis_port}" : 
      null
    )
    secrets_manager_region = var.aws_region
    kms_encryption_enabled = true
  }
  sensitive = true
}