package test

import (
	"os"
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestTerraformCodePipeline(t *testing.T) {
	t.Parallel()

	// Terraform options configuration
	terraformOptions := &terraform.Options{
		TerraformDir: "../terraform",
		Vars: map[string]interface{}{
			"aws_region":       "ap-south-2",
			"project_name":     "devops-pipeline",
			"github_owner":     "PriyabratDev",
			"github_repo":      "aws-devops-pipeline",
			"github_token":     os.Getenv("GITHUB_TOKEN"),
			"allowed_ip_range": os.Getenv("ALLOWED_IP_RANGE"),
		},
	}

	// Clean up resources after test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy terraform infrastructure
	terraform.InitAndApply(t, terraformOptions)

	// Test S3 bucket creation
	bucketName := terraform.Output(t, terraformOptions, "s3_bucket_name")
	assert.NotEmpty(t, bucketName)

	// Verify that the S3 bucket exists in AWS
	awsRegion := "ap-south-2"
	aws.AssertS3BucketExists(t, awsRegion, bucketName)

	// Test EC2 instance
	instanceIP := terraform.Output(t, terraformOptions, "ec2_instance_ip")
	assert.NotEmpty(t, instanceIP)

	// Test CodeBuild project
	projectName := terraform.Output(t, terraformOptions, "codebuild_project_name")
	assert.NotEmpty(t, projectName)
}

func TestS3BucketVersioning(t *testing.T) {
	t.Parallel()

	// Terraform options configuration
	terraformOptions := &terraform.Options{
		TerraformDir: "../terraform",
		Vars: map[string]interface{}{
			"aws_region":       "ap-south-2",
			"project_name":     "devops-pipeline",
			"github_owner":     "PriyabratDev",
			"github_repo":      "aws-devops-pipeline",
			"github_token":     os.Getenv("GITHUB_TOKEN"),
			"allowed_ip_range": os.Getenv("ALLOWED_IP_RANGE"),
		},
	}

	// Clean up resources after test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy terraform infrastructure
	terraform.InitAndApply(t, terraformOptions)

	// Check if versioning enabled
	bucketName := terraform.Output(t, terraformOptions, "s3_bucket_name")
	awsRegion := "ap-south-2"

	actualStatus := aws.GetS3BucketVersioning(t, awsRegion, bucketName)
	expectedStatus := "Enabled"
	assert.Equal(t, expectedStatus, actualStatus)
}
