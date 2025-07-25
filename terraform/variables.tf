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
  description = "CIDR range for allowed IP addresses"
  default = "0.0.0.0/0"
  type        = string
}
variable "public_key" {
  type        = string
  description = "SSH public key to access EC2 instance"
}
