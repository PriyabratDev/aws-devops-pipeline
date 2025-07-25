# AWS CodePipeline Infrastructure with Terraform
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
provider "github" {
  token = var.github_token
}

#data resources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Get default VPC for the secure approach
data "aws_vpc" "default" {
  default = true
}

resource "aws_ecr_repository" "app_repository" {
  name                 = "${var.project_name}-repo"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr_key.arn
  }

  tags = {
    Name        = "${var.project_name}-ecr"
    Environment = "dev"
  }
}


# S3 Bucket for CodePipeline Artifacts
resource "aws_s3_bucket" "codepipeline_artifacts" {
  bucket = "${var.project_name}-codepipeline-artifacts-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Name        = "${var.project_name}-artifacts"
    Environment = "dev"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket_versioning" "codepipeline_artifacts" {
  bucket = aws_s3_bucket.codepipeline_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "s3_key" {
  description = "KMS key for S3 bucket encryption"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "codepipeline_artifacts" {
  bucket = aws_s3_bucket.codepipeline_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "codepipeline_artifacts" {
  bucket = aws_s3_bucket.codepipeline_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable logging for codepipeline artifacts bucket
resource "aws_s3_bucket_logging" "codepipeline_artifacts" {
  bucket = aws_s3_bucket.codepipeline_artifacts.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "codepipeline-artifacts-logs/"
}

# IAM Role for CodePipeline
resource "aws_iam_role" "codepipeline_role" {
  name = "${var.project_name}-codepipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codepipeline.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "codepipeline_policy" {
  name = "${var.project_name}-codepipeline-policy"
  role = aws_iam_role.codepipeline_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.codepipeline_artifacts.arn,
          "${aws_s3_bucket.codepipeline_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "codebuild:BatchGetBuilds",
          "codebuild:StartBuild"
        ]
        Resource = aws_codebuild_project.build_project.arn
      },
      {
        Effect = "Allow"
        Action = [
          "codedeploy:CreateDeployment",
          "codedeploy:GetApplication",
          "codedeploy:GetApplicationRevision",
          "codedeploy:GetDeployment",
          "codedeploy:GetDeploymentConfig",
          "codedeploy:RegisterApplicationRevision"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.s3_key.arn
      }
    ]
  })
}

# IAM Role for CodeBuild
resource "aws_iam_role" "codebuild_role" {
  name = "${var.project_name}-codebuild-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "codebuild_policy" {
  name = "${var.project_name}-codebuild-policy"
  role = aws_iam_role.codebuild_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = aws_ecr_repository.app_repository.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.codepipeline_artifacts.arn,
          "${aws_s3_bucket.codepipeline_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.s3_key.arn,
          aws_kms_key.ecr_key.arn
        ]
      }
    ]
  })
}
# CodeBuild Project
resource "aws_codebuild_project" "build_project" {
  name          = "${var.project_name}-build"
  description   = "Build project for ${var.project_name}"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode            = true
  environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.aws_region
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = aws_ecr_repository.app_repository.name
    }
  }

  source {
    type = "CODEPIPELINE"
    buildspec = "buildspec.yml"
  }

  tags = {
    Environment = "dev"
    Project     = var.project_name
  }
}


# KMS Key Aliases for better management
resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/${var.project_name}-s3-key"
  target_key_id = aws_kms_key.s3_key.key_id
}

resource "aws_kms_alias" "ecr_key_alias" {
  name          = "alias/${var.project_name}-ecr-key"
  target_key_id = aws_kms_key.ecr_key.key_id
}

# Update EC2 IAM policy to include CodeDeploy agent permissions
resource "aws_iam_role_policy" "ec2_codedeploy_policy" {
  name = "${var.project_name}-ec2-codedeploy-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.codepipeline_artifacts.arn,
          "${aws_s3_bucket.codepipeline_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.s3_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "tag:GetResources",
          "autoscaling:CompleteLifecycleAction",
          "autoscaling:DeleteLifecycleHook",
          "autoscaling:DescribeLifecycleHooks",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:PutLifecycleHook",
          "autoscaling:RecordLifecycleActionHeartbeat"
        ]
        Resource = "*"
      }
    ]
  })
}

# EC2 Instance for Deployment
resource "aws_instance" "app_server" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  key_name      = aws_key_pair.app_key.key_name

  vpc_security_group_ids = [aws_security_group.app_sg_secure.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  tags = {
    Name        = "${var.project_name}-app-server"
    Environment = "dev"
    Project     = var.project_name
  }
  metadata_options {
    http_tokens = "required"
    http_put_response_hop_limit = 1
    http_endpoint = "enabled"
  }
  root_block_device {
    encrypted = true
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Key Pair for EC2
resource "aws_key_pair" "app_key" {
  key_name   = "${var.project_name}-key"
  public_key = var.public_key # Make sure to generate this key
}

resource "null_resource" "validate_variables" {
  lifecycle {
    precondition {
      condition     = length(var.github_owner) > 0
      error_message = "github_owner variable cannot be empty"
    }
    precondition {
      condition     = length(var.github_repo) > 0
      error_message = "github_repo variable cannot be empty"
    }
    precondition {
      condition     = length(var.github_token) > 0
      error_message = "github_token variable cannot be empty"
    }
    precondition {
      condition     = length(var.project_name) > 0
      error_message = "project_name variable cannot be empty"
    }
  }
}

# Get AWS service prefix lists
data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}



# Most secure approach: Use VPC endpoints and minimal egress
resource "aws_security_group" "app_sg_secure" {
  name        = "${var.project_name}-sg-secure"
  description = "Most secure security group with minimal egress"

  # Ingress rules (same as before)
  ingress {
    description = "Allow SSH access from specified IP range"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip_range]
  }

  ingress {
    description = "Allow HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip_range]
  }

  ingress {
    description = "Allow HTTPS access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip_range]
  }

  # Minimal egress - only to VPC endpoints and essential services
  egress {
    description = "Allow HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block] # Only within VPC
  }

  egress {
    description = "Allow DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["169.254.169.253/32"]
  }

  tags = {
    Name = "${var.project_name}-sg-secure"
  }
}



# VPC Endpoints for secure approach (optional but recommended)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  
  tags = {
    Name = "${var.project_name}-s3-endpoint"
  }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = data.aws_vpc.default.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.aws_subnets.default.ids
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  tags = {
    Name = "${var.project_name}-ecr-dkr-endpoint"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = data.aws_vpc.default.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.aws_subnets.default.ids
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  tags = {
    Name = "${var.project_name}-ecr-api-endpoint"
  }
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoint_sg" {
  name        = "${var.project_name}-vpc-endpoint-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  egress {
    description = "Allow HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  tags = {
    Name = "${var.project_name}-vpc-endpoint-sg"
  }
}

# Get default subnets
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}



# IAM Role for EC2
resource "aws_iam_role" "ec2_role" {
  name = "${var.project_name}-ec2-role"

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
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "${var.project_name}-ec2-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.codepipeline_artifacts.arn,
          "${aws_s3_bucket.codepipeline_artifacts.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# CodeDeploy Application
resource "aws_codedeploy_app" "app" {
  compute_platform = "Server"
  name             = "${var.project_name}-app"
}

# CodeDeploy Deployment Group
resource "aws_codedeploy_deployment_group" "deployment_group" {
  app_name              = aws_codedeploy_app.app.name
  deployment_group_name = "${var.project_name}-deployment-group"
  service_role_arn      = aws_iam_role.codedeploy_role.arn

  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "${var.project_name}-app-server"
  }

  deployment_config_name = "CodeDeployDefault.OneAtATime"

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

# IAM Role for CodeDeploy
resource "aws_iam_role" "codedeploy_role" {
  name = "${var.project_name}-codedeploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codedeploy.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "codedeploy_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = aws_iam_role.codedeploy_role.name
}

# CodePipeline
resource "aws_codepipeline" "pipeline" {
  name     = "${var.project_name}-pipeline"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.codepipeline_artifacts.bucket
    type     = "S3"

    encryption_key {
      id   = aws_kms_key.s3_key.arn
      type = "KMS"
    }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        Owner      = var.github_owner
        Repo       = var.github_repo
        Branch     = "main"
        OAuthToken = var.github_token
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      version          = "1"

      configuration = {
        ProjectName = aws_codebuild_project.build_project.name
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeploy"
      input_artifacts = ["build_output"]
      version         = "1"

      configuration = {
        ApplicationName     = aws_codedeploy_app.app.name
        DeploymentGroupName = aws_codedeploy_deployment_group.deployment_group.deployment_group_name
      }
    }

  }
  tags = {
    Name        = "${var.project_name}-pipeline"
    Environment = "dev"
  }
}

# Outputs
output "pipeline_url" {
  description = "URL of the CodePipeline"
  value       = "https://console.aws.amazon.com/codesuite/codepipeline/pipelines/${aws_codepipeline.pipeline.name}/view"
}

output "app_sg_secure_id" {
  description = "ID of the secure application security group"
  value       = aws_security_group.app_sg_secure.id
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for artifacts"
  value       = aws_s3_bucket.codepipeline_artifacts.bucket
}

output "ec2_instance_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.app_server.public_ip
}

output "default_vpc_cidr" {
  description = "CIDR block of the default VPC"
  value       = data.aws_vpc.default.cidr_block
}

resource "aws_s3_bucket" "log_bucket" {
  bucket        = "${var.project_name}-logs-${random_string.bucket_suffix.result}"
  force_destroy = true
}

# Enable versioning for log bucket
resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Block public access for log bucket
resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption for log bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_kms_key" "ecr_key" {
  description         = "KMS key for ECR image encryption"
  enable_key_rotation = true
}


# Enable logging for log bucket (optional - logs about the log bucket itself)
resource "aws_s3_bucket_logging" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log-bucket-access-logs/"
}