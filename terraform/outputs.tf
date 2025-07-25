output "pipeline-url" {
  description = "URL of the CodePipeline"
  value       = "https://console.aws.amazon.com/codesuite/codepipeline/pipelines/${aws_codepipeline.pipeline.name}/view"  
}

output "s3-bucket-name" {
  description = "Name of the S3 bucket used for artifacts"
  value       = aws_s3_bucket.codepipeline_artifacts.bucket
  
}

output "ec2-instance-ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.app_server.public_ip
  
}
output "codebuild-project-name" {
  description = "Name of the CodeBuild project"
  value       = aws_codebuild_project.build_project.name
  
}

output "github_token_output" {
  value = var.github_token
}