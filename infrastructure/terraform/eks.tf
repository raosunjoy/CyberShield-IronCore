# CyberShield-IronCore EKS Cluster Configuration
# Enterprise-grade Kubernetes with high availability and auto-scaling
# Built for 1M+ events/second processing and 99.99% uptime

# KMS key for EKS cluster encryption
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key for ${local.name_prefix}"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-kms-key"
    Type = "KMS-Key"
    Purpose = "EKS-Encryption"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.name_prefix}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# CloudWatch Log Group for EKS cluster logs
resource "aws_cloudwatch_log_group" "eks_cluster" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/eks/${local.name_prefix}-eks/cluster"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = aws_kms_key.eks.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-cluster-logs"
    Type = "CloudWatch-Log-Group"
  })
}

# IAM role for EKS cluster
resource "aws_iam_role" "eks_cluster" {
  name = "${local.name_prefix}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-cluster-role"
    Type = "IAM-Role"
  })
}

# Attach required policies to EKS cluster role
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster.name
}

# Security group for EKS cluster control plane
resource "aws_security_group" "eks_cluster" {
  name_prefix = "${local.name_prefix}-eks-cluster-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for EKS cluster control plane"

  # Allow inbound HTTPS traffic from anywhere (will be restricted by endpoint access)
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.cluster_endpoint_public_access_cidrs
  }

  # Allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-cluster-sg"
    Type = "Security-Group"
    Purpose = "EKS-Control-Plane"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# EKS Cluster
resource "aws_eks_cluster" "main" {
  name     = "${local.name_prefix}-eks"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = local.cluster_version

  vpc_config {
    subnet_ids              = concat(aws_subnet.private[*].id, aws_subnet.public[*].id)
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  # Enable cluster logging
  dynamic "enabled_cluster_log_types" {
    for_each = var.enable_logging ? [1] : []
    content {
      log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    }
  }

  # Encryption configuration
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-cluster"
    Type = "EKS-Cluster"
    "kubernetes.io/cluster/${local.name_prefix}-eks" = "owned"
    IronManStatus = "Suit-Up-Complete"
  })

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
    aws_cloudwatch_log_group.eks_cluster,
  ]
}

# IAM role for EKS node groups
resource "aws_iam_role" "eks_node_group" {
  name = "${local.name_prefix}-eks-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-node-group-role"
    Type = "IAM-Role"
  })
}

# Attach required policies to EKS node group role
resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group.name
}

# Additional policy for CyberShield-specific permissions
resource "aws_iam_role_policy" "cybershield_node_policy" {
  name = "${local.name_prefix}-node-additional-policy"
  role = aws_iam_role.eks_node_group.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-*",
          "arn:aws:s3:::${local.name_prefix}-*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${local.name_prefix}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      }
    ]
  })
}

# Security group for EKS node groups
resource "aws_security_group" "eks_nodes" {
  name_prefix = "${local.name_prefix}-eks-nodes-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for EKS node groups"

  # Allow nodes to communicate with each other
  ingress {
    description = "Node to node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # Allow pods to communicate with cluster API server
  ingress {
    description     = "Allow pods to communicate with cluster API server"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # Allow kubelet and kubeproxy to receive communication from cluster control plane
  ingress {
    description     = "Allow worker Kubelets and pods to receive communication from cluster control plane"
    from_port       = 1025
    to_port         = 65535  
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # Allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-nodes-sg"
    Type = "Security-Group"
    Purpose = "EKS-Worker-Nodes"
    "kubernetes.io/cluster/${local.name_prefix}-eks" = "owned"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Launch template for EKS node groups
resource "aws_launch_template" "eks_nodes" {
  name_prefix = "${local.name_prefix}-eks-nodes-"
  description = "Launch template for EKS worker nodes"

  vpc_security_group_ids = [aws_security_group.eks_nodes.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type          = "gp3"
      iops                 = 3000
      throughput           = 125
      encrypted            = true
      kms_key_id          = aws_kms_key.eks.arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-eks-node"
      Type = "EKS-Worker-Node"
      "kubernetes.io/cluster/${local.name_prefix}-eks" = "owned"
    })
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-launch-template"
    Type = "Launch-Template"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# EKS Node Groups
resource "aws_eks_node_group" "main" {
  for_each = local.node_groups

  cluster_name    = aws_eks_cluster.main.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.eks_node_group.arn
  subnet_ids      = aws_subnet.private[*].id

  capacity_type   = each.value.capacity_type
  instance_types  = each.value.instance_types
  
  # Use launch template for advanced configuration
  launch_template {
    id      = aws_launch_template.eks_nodes.id
    version = aws_launch_template.eks_nodes.latest_version
  }

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  update_config {
    max_unavailable = 1
  }

  # Apply labels
  labels = merge(
    {
      "node-group" = each.key
      "capacity-type" = each.value.capacity_type
    },
    lookup(each.value, "labels", {})
  )

  # Apply taints if specified
  dynamic "taint" {
    for_each = lookup(each.value, "taints", {})
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-${each.key}"
    Type = "EKS-Node-Group"
    CapacityType = each.value.capacity_type
    "kubernetes.io/cluster/${local.name_prefix}-eks" = "owned"
  })

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry_read_only,
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# OIDC identity provider for EKS cluster
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks_oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eks-oidc"
    Type = "OIDC-Provider"
  })
}