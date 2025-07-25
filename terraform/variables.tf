variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-2"
}
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "devops-pipeline"
}
variable "github_owner" {
  description = "GitHub owner/organization"
  type        = string
}
variable "github_repo" {
  description = "GitHub repository name"
  type        = string
}
variable "github_token" {
  description = "GitHub personal access token"
  type        = string
  sensitive   = true
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
variable "allowed_package_repos" {
  description = "List of CIDR blocks for package repositories"
  type        = list(string)
  default     = [
    "151.101.0.0/16",  # GitHub package registry
    "52.216.0.0/15",   # Amazon Linux package repository
    "13.32.0.0/15",    # Amazon Linux package repository
    "16.182.0.0/15"    # Amazon Linux package repository
  ]
  
  validation {
    condition = alltrue([
      for cidr in var.allowed_package_repos : can(cidrhost(cidr, 0))
    ])
    error_message = "All elements must be valid CIDR blocks"
  }
}
