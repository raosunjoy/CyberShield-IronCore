# CyberShield-IronCore Monitoring & Alerting Configuration
# Enterprise-grade observability with CloudWatch, SNS, and Iron Man JARVIS-style alerts
# Built for 24/7 SOC monitoring and real-time threat detection

# SNS topic for critical alerts
resource "aws_sns_topic" "alerts" {
  count = var.enable_monitoring ? 1 : 0

  name = "${local.name_prefix}-critical-alerts"
  display_name = "CyberShield Critical Alerts"

  # Encryption
  kms_master_key_id = aws_kms_key.rds.arn

  # Delivery policy for reliable alerting
  delivery_policy = jsonencode({
    "http" = {
      "defaultHealthyRetryPolicy" = {
        "minDelayTarget"     = 20
        "maxDelayTarget"     = 20
        "numRetries"         = 3
        "numMaxDelayRetries" = 0
        "numMinDelayRetries" = 0
        "numNoDelayRetries"  = 0
        "backoffFunction"    = "linear"
      }
      "disableSubscriptionOverrides" = false
    }
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alerts-topic"
    Type = "SNS-Topic"
    Purpose = "Critical-Alerts"
    JarvisMode = "Alert-Systems-Online"
  })
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  count = var.enable_monitoring ? 1 : 0

  name = "${local.name_prefix}-security-alerts"
  display_name = "CyberShield Security Alerts"

  # Encryption
  kms_master_key_id = aws_kms_key.rds.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-security-alerts-topic"
    Type = "SNS-Topic"
    Purpose = "Security-Alerts"
    IronManQuote = "Threat-Detection-Active"
  })
}

# CloudWatch Dashboard for comprehensive monitoring
resource "aws_cloudwatch_dashboard" "main" {
  count = var.enable_monitoring ? 1 : 0

  dashboard_name = "${local.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EKS", "cluster_failed_request_count", "ClusterName", aws_eks_cluster.main.name],
            ["AWS/EKS", "cluster_request_total", "ClusterName", aws_eks_cluster.main.name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "EKS Cluster Requests"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.main.id],
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.main.id],
            ["AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", aws_db_instance.main.id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "RDS Performance Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", var.environment == "production" ? aws_elasticache_replication_group.main[0].id : aws_elasticache_cluster.main[0].cluster_id],
            ["AWS/ElastiCache", "DatabaseMemoryUsagePercentage", "CacheClusterId", var.environment == "production" ? aws_elasticache_replication_group.main[0].id : aws_elasticache_cluster.main[0].cluster_id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Redis Performance Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          query   = "SOURCE '/aws/eks/${aws_eks_cluster.main.name}/cluster'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 100"
          region  = var.aws_region
          title   = "EKS Cluster Errors"
          view    = "table"
        }
      }
    ]
  })

  depends_on = [
    aws_eks_cluster.main,
    aws_db_instance.main,
    aws_elasticache_cluster.main,
    aws_elasticache_replication_group.main
  ]
}

# CloudWatch alarms for EKS cluster
resource "aws_cloudwatch_metric_alarm" "eks_cluster_failed_requests" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-eks-failed-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "cluster_failed_request_count"
  namespace           = "AWS/EKS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors EKS cluster failed requests"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = aws_eks_cluster.main.name
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-failed-requests-alarm"
    Type = "CloudWatch-Alarm"
    Severity = "High"
  })
}

# CloudWatch alarms for RDS
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-rds-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-cpu-alarm"
    Type = "CloudWatch-Alarm"
    Severity = "Medium"
  })
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-rds-connection-count"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = var.environment == "production" ? "400" : "80"
  alarm_description   = "This metric monitors RDS connection count"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-connections-alarm"
    Type = "CloudWatch-Alarm"
    Severity = "High"
  })
}

resource "aws_cloudwatch_metric_alarm" "rds_freeable_memory" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-rds-freeable-memory"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "268435456" # 256 MB in bytes
  alarm_description   = "This metric monitors RDS freeable memory"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-memory-alarm"
    Type = "CloudWatch-Alarm"
    Severity = "High"
  })
}

# Security-focused CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "vpc_flow_log_errors" {
  count = var.enable_logging && var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-vpc-flow-log-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ErrorCount"
  namespace           = "AWS/Logs"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors VPC Flow Log errors"
  alarm_actions       = [aws_sns_topic.security_alerts[0].arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.vpc_flow_log[0].name
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc-flow-errors-alarm"
    Type = "CloudWatch-Alarm"
    Category = "Security"
    Severity = "Critical"
  })
}

# Custom metric filters for security events
resource "aws_cloudwatch_log_metric_filter" "failed_login_attempts" {
  count = var.enable_logging ? 1 : 0

  name           = "${local.name_prefix}-failed-login-attempts"
  log_group_name = "/cybershield/${var.environment}/application"
  pattern        = "[timestamp, request_id, level=\"ERROR\", message=\"Authentication failed\", ...]"

  metric_transformation {
    name      = "FailedLoginAttempts"
    namespace = "CyberShield/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "failed_login_attempts" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-failed-login-attempts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FailedLoginAttempts"
  namespace           = "CyberShield/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "High number of failed login attempts detected"
  alarm_actions       = [aws_sns_topic.security_alerts[0].arn]
  treat_missing_data  = "notBreaching"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-failed-logins-alarm"
    Type = "CloudWatch-Alarm"
    Category = "Security"
    Severity = "Critical"
    ThreatType = "Brute-Force-Attack"
  })
}

# Custom metric for threat detection
resource "aws_cloudwatch_log_metric_filter" "threat_detected" {
  count = var.enable_logging ? 1 : 0

  name           = "${local.name_prefix}-threat-detected"
  log_group_name = "/cybershield/${var.environment}/application"
  pattern        = "[timestamp, request_id, level=\"ERROR\", message=\"Threat detected\", ...]"

  metric_transformation {
    name      = "ThreatsDetected"
    namespace = "CyberShield/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "threat_detected" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${local.name_prefix}-threat-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ThreatsDetected"
  namespace           = "CyberShield/Security"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Cyber threat detected by CyberShield AI"
  alarm_actions       = [aws_sns_topic.security_alerts[0].arn]
  treat_missing_data  = "notBreaching"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-threat-detection-alarm"
    Type = "CloudWatch-Alarm"
    Category = "Security"
    Severity = "Critical"
    JarvisAlert = "Threat-Neutralization-Required"
  })
}

# Application performance metrics
resource "aws_cloudwatch_log_group" "application" {
  count = var.enable_logging ? 1 : 0

  name              = "/cybershield/${var.environment}/application"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = aws_kms_key.rds.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-application-logs"
    Type = "CloudWatch-Log-Group"
    Purpose = "Application-Logging"
  })
}

# Lambda function for custom metrics (if needed)
resource "aws_cloudwatch_log_group" "lambda" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/lambda/${local.name_prefix}-metrics-processor"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = aws_kms_key.rds.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-logs"
    Type = "CloudWatch-Log-Group"
    Purpose = "Lambda-Logging"
  })
}

# CloudWatch Insights queries for security analysis
# These can be used in the dashboard or for ad-hoc analysis
locals {
  security_queries = {
    failed_authentication = "fields @timestamp, source_ip, user_id, failure_reason | filter event_type = \"auth_failure\" | stats count() by source_ip | sort count desc"
    
    threat_timeline = "fields @timestamp, threat_type, risk_score, source_ip | filter event_type = \"threat_detection\" | sort @timestamp desc"
    
    high_risk_events = "fields @timestamp, event_type, risk_score, details | filter risk_score > 7.0 | sort @timestamp desc"
    
    geographic_threats = "fields @timestamp, source_ip, threat_type, risk_score | filter event_type = \"threat_detection\" | stats count() by source_ip, threat_type"
    
    automated_responses = "fields @timestamp, threat_id, action, success | filter event_type = \"auto_mitigation\" | stats count() by action, success"
  }
}

# Export metrics to external monitoring systems (if needed)
resource "aws_cloudwatch_metric_stream" "main" {
  count = var.enable_monitoring && var.environment == "production" ? 1 : 0

  name          = "${local.name_prefix}-metric-stream"
  firehose_arn  = aws_kinesis_firehose_delivery_stream.metrics[0].arn
  role_arn      = aws_iam_role.metric_stream[0].arn
  output_format = "json"

  include_filter {
    namespace = "AWS/EKS"
  }

  include_filter {
    namespace = "AWS/RDS"
  }

  include_filter {
    namespace = "AWS/ElastiCache"
  }

  include_filter {
    namespace = "CyberShield/Security"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-metric-stream"
    Type = "CloudWatch-Metric-Stream"
    Purpose = "External-Monitoring"
  })
}

# Kinesis Firehose for metric streaming (production only)
resource "aws_kinesis_firehose_delivery_stream" "metrics" {
  count = var.enable_monitoring && var.environment == "production" ? 1 : 0

  name        = "${local.name_prefix}-metrics-stream"
  destination = "s3"

  s3_configuration {
    role_arn   = aws_iam_role.firehose[0].arn
    bucket_arn = aws_s3_bucket.metrics[0].arn
    prefix     = "metrics/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
    
    buffer_size     = 10
    buffer_interval = 60
    
    compression_format = "GZIP"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-metrics-firehose"
    Type = "Kinesis-Firehose"
    Purpose = "Metrics-Export"
  })
}

# S3 bucket for metrics storage (production only)
resource "aws_s3_bucket" "metrics" {
  count = var.enable_monitoring && var.environment == "production" ? 1 : 0

  bucket = "${local.name_prefix}-metrics-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-metrics-bucket"
    Type = "S3-Bucket"
    Purpose = "Metrics-Storage"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "metrics" {
  count = var.enable_monitoring && var.environment == "production" ? 1 : 0

  bucket = aws_s3_bucket.metrics[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.rds.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# IAM roles for monitoring services
resource "aws_iam_role" "metric_stream" {
  count = var.enable_monitoring && var.environment == "production" ? 1 : 0

  name = "${local.name_prefix}-metric-stream-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "streams.metrics.cloudwatch.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-metric-stream-role"
    Type = "IAM-Role"
  })
}

resource "aws_iam_role" "firehose" {
  count = var.enable_monitoring && var.environment == "production" ? 1 : 0

  name = "${local.name_prefix}-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-firehose-role"
    Type = "IAM-Role"
  })
}