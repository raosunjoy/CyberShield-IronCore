# CyberShield-IronCore Redis Configuration
# Enterprise-grade ElastiCache for session management and caching
# Built for high performance and automatic failover

# Subnet group for Redis
resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name_prefix}-redis-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-subnet-group"
    Type = "ElastiCache-Subnet-Group"
  })
}

# Security group for Redis
resource "aws_security_group" "redis" {
  name_prefix = "${local.name_prefix}-redis-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for Redis ElastiCache cluster"

  # Allow Redis access from EKS nodes
  ingress {
    description     = "Redis from EKS nodes"
    from_port       = var.redis_port
    to_port         = var.redis_port
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }

  # Allow Redis access from private subnets
  ingress {
    description = "Redis from private subnets"
    from_port   = var.redis_port
    to_port     = var.redis_port
    protocol    = "tcp"
    cidr_blocks = aws_subnet.private[*].cidr_block
  }

  # No outbound rules needed for Redis
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-sg"
    Type = "Security-Group"
    Purpose = "Redis-Cache"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Parameter group for Redis optimization
resource "aws_elasticache_parameter_group" "main" {
  family = "redis7.x"
  name   = "${local.name_prefix}-redis7"
  description = "Custom parameter group for CyberShield Redis"

  # Memory management
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  # Performance tuning
  parameter {
    name  = "timeout"
    value = "300"
  }

  parameter {
    name  = "tcp-keepalive"
    value = "60"
  }

  # Security
  parameter {
    name  = "requirepass"
    value = "yes"
  }

  # Logging (if needed)
  parameter {
    name  = "slowlog-log-slower-than"
    value = "10000" # Log commands slower than 10ms
  }

  parameter {
    name  = "slowlog-max-len"
    value = "128"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-params"
    Type = "ElastiCache-Parameter-Group"
  })
}

# Generate Redis auth token
resource "random_password" "redis_auth_token" {
  length  = 64
  special = false # Redis auth tokens should not contain special characters
}

# Store Redis auth token in AWS Secrets Manager
resource "aws_secretsmanager_secret" "redis_auth_token" {
  name        = "${local.name_prefix}/redis/auth-token"
  description = "Auth token for CyberShield Redis cluster"
  kms_key_id  = aws_kms_key.rds.arn # Reuse RDS KMS key

  replica {
    region = var.backup_region
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-auth-secret"
    Type = "Secrets-Manager-Secret"
    Purpose = "Redis-Authentication"
  })
}

resource "aws_secretsmanager_secret_version" "redis_auth_token" {
  secret_id = aws_secretsmanager_secret.redis_auth_token.id
  secret_string = jsonencode({
    auth_token = random_password.redis_auth_token.result
    primary_endpoint = var.environment == "production" ? aws_elasticache_replication_group.main[0].primary_endpoint_address : aws_elasticache_cluster.main[0].cache_nodes[0].address
    port = var.redis_port
    engine = "redis"
  })

  depends_on = [
    aws_elasticache_cluster.main,
    aws_elasticache_replication_group.main
  ]
}

# Single-node Redis cluster for development/staging
resource "aws_elasticache_cluster" "main" {
  count = var.environment != "production" ? 1 : 0

  cluster_id           = "${local.name_prefix}-redis"
  engine               = "redis"
  node_type            = local.redis_config.node_type
  num_cache_nodes      = 1
  parameter_group_name = aws_elasticache_parameter_group.main.name
  port                 = var.redis_port
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = [aws_security_group.redis.id]

  # Auth token for security
  auth_token = random_password.redis_auth_token.result

  # Encryption
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  # Maintenance
  maintenance_window = "sun:05:00-sun:06:00"
  
  # Snapshots
  snapshot_retention_limit = 3
  snapshot_window         = "03:00-04:00"

  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow[0].name
    destination_type = "cloudwatch-logs"
    log_format      = "text"
    log_type        = "slow-log"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis"
    Type = "ElastiCache-Cluster"
    Mode = "Single-Node"
    Purpose = "Session-Cache"
  })
}

# Multi-node Redis replication group for production
resource "aws_elasticache_replication_group" "main" {
  count = var.environment == "production" ? 1 : 0

  replication_group_id       = "${local.name_prefix}-redis"
  description                = "CyberShield Redis replication group"
  
  node_type                  = local.redis_config.node_type
  port                       = var.redis_port
  parameter_group_name       = aws_elasticache_parameter_group.main.name
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]

  # Replication configuration
  num_cache_clusters         = 3 # 1 primary + 2 replicas
  automatic_failover_enabled = true
  multi_az_enabled          = true

  # Auth token for security
  auth_token = random_password.redis_auth_token.result

  # Encryption
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  # Maintenance
  maintenance_window = "sun:05:00-sun:06:00"
  
  # Snapshots
  snapshot_retention_limit = 7
  snapshot_window         = "03:00-04:00"

  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow[0].name
    destination_type = "cloudwatch-logs"
    log_format      = "text"
    log_type        = "slow-log"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-replication"
    Type = "ElastiCache-Replication-Group"
    Mode = "Multi-Node-HA"
    Purpose = "Session-Cache-HA"
    JarvisStatus = "Cache-Systems-Online"
  })
}

# CloudWatch log groups for Redis
resource "aws_cloudwatch_log_group" "redis_slow" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/elasticache/${local.name_prefix}/redis/slow-log"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = aws_kms_key.rds.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-slow-logs"
    Type = "CloudWatch-Log-Group"
  })
}

# CloudWatch alarms for Redis monitoring
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-redis-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Redis CPU utilization"
  alarm_actions       = var.enable_monitoring ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    CacheClusterId = var.environment == "production" ? aws_elasticache_replication_group.main[0].id : aws_elasticache_cluster.main[0].cluster_id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-cpu-alarm"
    Type = "CloudWatch-Alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-redis-memory-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "90"
  alarm_description   = "This metric monitors Redis memory utilization"
  alarm_actions       = var.enable_monitoring ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    CacheClusterId = var.environment == "production" ? aws_elasticache_replication_group.main[0].id : aws_elasticache_cluster.main[0].cluster_id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-memory-alarm"
    Type = "CloudWatch-Alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "redis_connections" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-redis-connection-count"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CurrConnections"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "500"
  alarm_description   = "This metric monitors Redis connection count"
  alarm_actions       = var.enable_monitoring ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    CacheClusterId = var.environment == "production" ? aws_elasticache_replication_group.main[0].id : aws_elasticache_cluster.main[0].cluster_id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-connections-alarm"
    Type = "CloudWatch-Alarm"
  })
}