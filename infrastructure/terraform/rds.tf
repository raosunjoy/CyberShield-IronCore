# CyberShield-IronCore RDS Configuration
# Enterprise-grade PostgreSQL with Multi-AZ, encryption, and automated backups
# Built for high availability and compliance (SOC 2, HIPAA, GDPR)

# Random password for database master user
resource "random_password" "db_password" {
  length  = 32
  special = true
  
  # Avoid characters that might cause issues in connection strings
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# KMS key for RDS encryption
resource "aws_kms_key" "rds" {
  description             = "RDS encryption key for ${local.name_prefix}"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-kms-key"
    Type = "KMS-Key"
    Purpose = "RDS-Encryption"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# Store database password in AWS Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name        = "${local.name_prefix}/database/master-password"
  description = "Master password for CyberShield PostgreSQL database"
  kms_key_id  = aws_kms_key.rds.arn

  replica {
    region = var.backup_region
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-password-secret"
    Type = "Secrets-Manager-Secret"
    Purpose = "Database-Credentials"
  })
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = aws_db_instance.main.db_name
  })

  depends_on = [aws_db_instance.main]
}

# DB subnet group for RDS
resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = aws_subnet.database[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-subnet-group"
    Type = "DB-Subnet-Group"
  })
}

# Security group for RDS
resource "aws_security_group" "rds" {
  name_prefix = "${local.name_prefix}-rds-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for RDS PostgreSQL database"

  # Allow PostgreSQL access from EKS nodes
  ingress {
    description     = "PostgreSQL from EKS nodes"
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }

  # Allow PostgreSQL access from Lambda functions (if any)
  ingress {
    description = "PostgreSQL from private subnets"
    from_port   = var.db_port
    to_port     = var.db_port
    protocol    = "tcp"
    cidr_blocks = aws_subnet.private[*].cidr_block
  }

  # No outbound rules needed for RDS
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-sg"
    Type = "Security-Group"
    Purpose = "RDS-Database"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Parameter group for PostgreSQL optimization
resource "aws_db_parameter_group" "main" {
  family = "postgres15"
  name   = "${local.name_prefix}-postgres15"
  description = "Custom parameter group for CyberShield PostgreSQL"

  # Performance tuning parameters
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,pg_hint_plan"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries taking more than 1 second
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_lock_waits"
    value = "1"
  }

  parameter {
    name  = "log_temp_files"
    value = "0"
  }

  parameter {
    name  = "track_activity_query_size"
    value = "2048"
  }

  parameter {
    name  = "pg_stat_statements.track"
    value = "all"
  }

  # Connection and memory settings
  parameter {
    name  = "max_connections"
    value = var.environment == "production" ? "500" : "100"
  }

  parameter {
    name  = "shared_buffers"
    value = "{DBInstanceClassMemory/4}"
  }

  parameter {
    name  = "effective_cache_size"
    value = "{DBInstanceClassMemory*3/4}"
  }

  parameter {
    name  = "work_mem"
    value = "4096"
  }

  parameter {
    name  = "maintenance_work_mem"
    value = "256000"
  }

  # Checkpoint and WAL settings
  parameter {
    name  = "checkpoint_completion_target"
    value = "0.9"
  }

  parameter {
    name  = "wal_buffers"
    value = "16384"
  }

  parameter {
    name  = "default_statistics_target"
    value = "100"
  }

  # Security settings
  parameter {
    name  = "ssl"
    value = "1"
  }

  parameter {
    name  = "log_statement_stats"
    value = "0"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres-params"
    Type = "DB-Parameter-Group"
  })
}

# Option group for PostgreSQL extensions
resource "aws_db_option_group" "main" {
  name                 = "${local.name_prefix}-postgres15"
  option_group_description = "Option group for CyberShield PostgreSQL"
  engine_name          = "postgres"
  major_engine_version = "15"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres-options"
    Type = "DB-Option-Group"
  })
}

# RDS PostgreSQL instance
resource "aws_db_instance" "main" {
  # Basic configuration
  identifier     = "${local.name_prefix}-postgres"
  engine         = local.db_config.engine
  engine_version = local.db_config.engine_version
  instance_class = local.db_config.instance_class

  # Database configuration
  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result
  port     = var.db_port

  # Storage configuration
  allocated_storage     = local.db_config.allocated_storage
  max_allocated_storage = local.db_config.max_allocated_storage
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.rds.arn

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # High availability
  multi_az = local.db_config.multi_az

  # Backup configuration
  backup_retention_period = local.db_config.backup_retention_period
  backup_window          = local.db_config.backup_window
  maintenance_window     = local.db_config.maintenance_window
  copy_tags_to_snapshot  = true
  delete_automated_backups = false

  # Performance Insights
  performance_insights_enabled          = local.db_config.performance_insights_enabled
  performance_insights_kms_key_id      = aws_kms_key.rds.arn
  performance_insights_retention_period = local.db_config.performance_insights_retention_period

  # Monitoring
  monitoring_interval = var.enable_monitoring ? 60 : 0
  monitoring_role_arn = var.enable_monitoring ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
  enabled_cloudwatch_logs_exports = var.enable_logging ? ["postgresql", "upgrade"] : []

  # Parameter and option groups
  parameter_group_name = aws_db_parameter_group.main.name
  option_group_name   = aws_db_option_group.main.name

  # Security
  deletion_protection = var.db_deletion_protection
  skip_final_snapshot = var.environment != "production"
  final_snapshot_identifier = var.environment == "production" ? "${local.name_prefix}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Auto minor version upgrade
  auto_minor_version_upgrade = var.environment != "production"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres"
    Type = "RDS-Instance"
    Engine = "PostgreSQL"
    Purpose = "Primary-Database"
    JarvisQuote = "Database-Systems-Online"
  })

  depends_on = [
    aws_db_parameter_group.main,
    aws_db_option_group.main,
    aws_db_subnet_group.main,
  ]

  lifecycle {
    prevent_destroy = true
    ignore_changes = [
      password, # Password is managed via Secrets Manager
    ]
  }
}

# IAM role for RDS Enhanced Monitoring
resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = var.enable_monitoring ? 1 : 0

  name = "${local.name_prefix}-rds-enhanced-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-monitoring-role"
    Type = "IAM-Role"
  })
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count = var.enable_monitoring ? 1 : 0

  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# CloudWatch log group for PostgreSQL logs
resource "aws_cloudwatch_log_group" "postgresql" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/rds/instance/${aws_db_instance.main.id}/postgresql"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = aws_kms_key.rds.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgresql-logs"
    Type = "CloudWatch-Log-Group"
  })
}

# Read replica for read scaling (production only)
resource "aws_db_instance" "read_replica" {
  count = var.environment == "production" ? 1 : 0

  identifier             = "${local.name_prefix}-postgres-replica"
  replicate_source_db    = aws_db_instance.main.id
  instance_class         = local.db_config.instance_class
  publicly_accessible    = false
  auto_minor_version_upgrade = false

  # Performance Insights
  performance_insights_enabled          = local.db_config.performance_insights_enabled
  performance_insights_kms_key_id      = aws_kms_key.rds.arn
  performance_insights_retention_period = local.db_config.performance_insights_retention_period

  # Monitoring
  monitoring_interval = var.enable_monitoring ? 60 : 0
  monitoring_role_arn = var.enable_monitoring ? aws_iam_role.rds_enhanced_monitoring[0].arn : null

  skip_final_snapshot = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres-replica"
    Type = "RDS-Read-Replica"
    Purpose = "Read-Scaling"
  })
}