package test

import (
	"os"
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	aws_ec2_sdk "github.com/aws/aws-sdk-go/service/ec2"
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
			"public_key":       os.Getenv("PUBLIC_KEY"),
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

	// Test CodeBuild project - Note: This output doesn't exist in the main.tf
	// You may need to add this output or remove this test
	// projectName := terraform.Output(t, terraformOptions, "codebuild_project_name")
	// assert.NotEmpty(t, projectName)
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
			"public_key":       os.Getenv("PUBLIC_KEY"),
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

func TestSecurityGroupConfiguration(t *testing.T) {
	t.Parallel()
	awsRegion := "ap-south-2"
	// Terraform options configuration
	terraformOptions := &terraform.Options{
		TerraformDir: "../terraform",
		Vars: map[string]interface{}{
			"aws_region":       awsRegion,
			"project_name":     "devops-pipeline",
			"github_owner":     "PriyabratDev",
			"github_repo":      "aws-devops-pipeline",
			"github_token":     os.Getenv("GITHUB_TOKEN"),
			"allowed_ip_range": os.Getenv("ALLOWED_IP_RANGE"),
			"public_key":       os.Getenv("PUBLIC_KEY"),
		},
	}

	// Clean up resources after test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy terraform infrastructure
	terraform.InitAndApply(t, terraformOptions)

	// Test that the secure security group exists and has proper configuration
	appSgSecureID := terraform.Output(t, terraformOptions, "app_sg_secure_id")
	assert.NotEmpty(t, appSgSecureID, "Expected app_sg_secure_id output to be non-empty")

	// Get an EC2 client
	ec2Client := aws.NewEc2Client(t, awsRegion)

	// Describe security groups to get the details
	input := &aws_ec2_sdk.DescribeSecurityGroupsInput{
		GroupIds: []*string{&appSgSecureID},
	}

	result, err := ec2Client.DescribeSecurityGroups(input)
	assert.NoError(t, err)
	assert.NotEmpty(t, result.SecurityGroups, "Expected at least one security group with the given ID")

	securityGroup := result.SecurityGroups[0]
	assert.NotNil(t, securityGroup, "Security group should not be nil")

	// --- Assert Ingress Rules ---
	// Expected SSH rule
	hasSSHIngress := false
	for _, ipPerm := range securityGroup.IpPermissions {
		if ipPerm.FromPort != nil && *ipPerm.FromPort == 22 &&
			ipPerm.ToPort != nil && *ipPerm.ToPort == 22 &&
			ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == "tcp" {
			for _, ipRange := range ipPerm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == os.Getenv("ALLOWED_IP_RANGE") {
					hasSSHIngress = true
					break
				}
			}
		}
		if hasSSHIngress {
			break
		}
	}
	assert.True(t, hasSSHIngress, "Expected SSH ingress rule from ALLOWED_IP_RANGE")

	// Expected HTTP rule
	hasHTTPIngress := false
	for _, ipPerm := range securityGroup.IpPermissions {
		if ipPerm.FromPort != nil && *ipPerm.FromPort == 80 &&
			ipPerm.ToPort != nil && *ipPerm.ToPort == 80 &&
			ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == "tcp" {
			for _, ipRange := range ipPerm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == os.Getenv("ALLOWED_IP_RANGE") {
					hasHTTPIngress = true
					break
				}
			}
		}
		if hasHTTPIngress {
			break
		}
	}
	assert.True(t, hasHTTPIngress, "Expected HTTP ingress rule from ALLOWED_IP_RANGE")

	// Expected HTTPS rule
	hasHTTPSIngress := false
	for _, ipPerm := range securityGroup.IpPermissions {
		if ipPerm.FromPort != nil && *ipPerm.FromPort == 443 &&
			ipPerm.ToPort != nil && *ipPerm.ToPort == 443 &&
			ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == "tcp" {
			for _, ipRange := range ipPerm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == os.Getenv("ALLOWED_IP_RANGE") {
					hasHTTPSIngress = true
					break
				}
			}
		}
		if hasHTTPSIngress {
			break
		}
	}
	assert.True(t, hasHTTPSIngress, "Expected HTTPS ingress rule from ALLOWED_IP_RANGE")

	// --- Assert Egress Rules ---
	// Expected HTTPS to VPC endpoints (assuming data.aws_vpc.default.cidr_block is used)
	hasVPCEndpointEgress := false
	for _, ipPerm := range securityGroup.IpPermissionsEgress {
		if ipPerm.FromPort != nil && *ipPerm.FromPort == 443 &&
			ipPerm.ToPort != nil && *ipPerm.ToPort == 443 &&
			ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == "tcp" {
			// You would need to know the default VPC CIDR block here, or make it an output
			// For simplicity, let's assume it's one of the allowed egress rules.
			// A more robust test might fetch data.aws_vpc.default.cidr_block directly in the test setup.
			for _, ipRange := range ipPerm.IpRanges {
				// This assumes default VPC CIDR, which is often 172.31.0.0/16 in new accounts.
				// For a precise test, you'd fetch the actual default VPC CIDR and compare.
				if ipRange.CidrIp != nil && (*ipRange.CidrIp == "172.31.0.0/16" || *ipRange.CidrIp == "10.0.0.0/16") { // Example CIDR blocks
					hasVPCEndpointEgress = true
					break
				}
			}
		}
		if hasVPCEndpointEgress {
			break
		}
	}
	assert.True(t, hasVPCEndpointEgress, "Expected HTTPS egress rule to VPC endpoints")

	// Expected DNS egress
	hasDNSEgress := false
	for _, ipPerm := range securityGroup.IpPermissionsEgress {
		if ipPerm.FromPort != nil && *ipPerm.FromPort == 53 &&
			ipPerm.ToPort != nil && *ipPerm.ToPort == 53 &&
			ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == "udp" {
			for _, ipRange := range ipPerm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "169.254.169.253/32" {
					hasDNSEgress = true
					break
				}
			}
		}
		if hasDNSEgress {
			break
		}
	}
	assert.True(t, hasDNSEgress, "Expected DNS egress rule")
}
