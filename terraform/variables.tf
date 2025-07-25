variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-2"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "dp"
}

variable "github_owner" {
  description = "GitHub owner/organization"
  type        = string
  default = "PriyabratDev"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default = "aws-devops-pipeline"
}

variable "github_token" {
  description = "GitHub personal access token"
  type        = string
  sensitive   = true
  # validation {
  #   condition     = length(var.github_token) > 0
  #   error_message = "GitHub token cannot be empty."
  # }
}

variable "allowed_ip_range" {
  description = "CIDR range for inbound access (e.g., '10.0.0.0/16', '192.168.1.0/24')"
  type        = string
  
  validation {
    condition     = can(cidrhost(var.allowed_ip_range, 0))
    error_message = "The allowed_ip_range must be a valid CIDR block"
  }
}

variable "public_key" {
  type        = string
  description = "SSH public key to access EC2 instance"
}