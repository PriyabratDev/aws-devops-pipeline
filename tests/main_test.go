package test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"

	// This import is crucial for aws_ec2_sdk.DescribeSecurityGroupsInput and types.SecurityGroup
	aws_ec2_sdk "github.com/aws/aws-sdk-go/service/ec2"
)

// Helper function to get the last N characters of a string
func getLastNChars(s string, n int) string {
	if len(s) < n {
		return s
	}
	return strings.ToLower(s[len(s)-n:])
}

// NEW HELPER FUNCTION: Get the first N characters of a string
func getFirstNChars(s string, n int) string {
	if len(s) < n {
		return s
	}
	return strings.ToLower(s[:n])
}
func TestTerraformCodePipeline(t *testing.T) {
	t.Parallel()

	// Generate a unique project name using the GitHub Actions Run ID
	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" {
		runID = "local" // Fallback for local testing
	}
	RunID := getLastNChars(runID, 4)
	TestName := getFirstNChars(t.Name(), 10)

	uniqueProjectName := fmt.Sprintf("dp-%s-%s", RunID, TestName)

	// Terraform options configuration
	terraformOptions := &terraform.Options{
		TerraformDir: "../terraform",
		Vars: map[string]interface{}{
			"aws_region":       "ap-south-2",
			"project_name":     uniqueProjectName,
			"github_owner":     "PriyabratDev",
			"github_repo":      "aws-devops-pipeline",
			"github_token":     os.Getenv("TF_VAR_GITHUB_TOKEN"),
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

	// Removed CodeBuild project test as output was not present in main.tf
	// If you add a "codebuild_project_name" output in main.tf, you can re-enable this:
	// projectName := terraform.Output(t, terraformOptions, "codebuild_project_name")
	// assert.NotEmpty(t, projectName)
}

func TestS3BucketVersioning(t *testing.T) {
	t.Parallel()

	// Generate a unique project name using the GitHub Actions Run ID
	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" {
		runID = "local" // Fallback for local testing
	}
	RunID := getLastNChars(runID, 4)
	TestName := getFirstNChars(t.Name(), 10)

	uniqueProjectName := fmt.Sprintf("dp-%s-%s", RunID, TestName)

	// Terraform options configuration
	terraformOptions := &terraform.Options{
		TerraformDir: "../terraform",
		Vars: map[string]interface{}{
			"aws_region":       "ap-south-2",
			"project_name":     uniqueProjectName,
			"github_owner":     "PriyabratDev",
			"github_repo":      "aws-devops-pipeline",
			"github_token":     os.Getenv("TF_VAR_GITHUB_TOKEN"),
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
	// Generate a unique project name using the GitHub Actions Run ID
	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" {
		runID = "local" // Fallback for local testing
	}
	RunID := getLastNChars(runID, 4)
	TestName := getFirstNChars(t.Name(), 10)

	uniqueProjectName := fmt.Sprintf("dp-%s-%s", RunID, TestName)

	// Terraform options configuration
	terraformOptions := &terraform.Options{
		TerraformDir: "../terraform",
		Vars: map[string]interface{}{
			"aws_region":       awsRegion,
			"project_name":     uniqueProjectName,
			"github_owner":     "PriyabratDev",
			"github_repo":      "aws-devops-pipeline",
			"github_token":     os.Getenv("TF_VAR_GITHUB_TOKEN"),
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
		GroupIds: []*string{&appSgSecureID}, // Pass the Security Group ID as a pointer to a string slice
	}

	result, err := ec2Client.DescribeSecurityGroups(input)
	assert.NoError(t, err)
	assert.NotEmpty(t, result.SecurityGroups, "Expected at least one security group with the given ID")

	securityGroup := result.SecurityGroups[0]
	assert.NotNil(t, securityGroup, "Security group should not be nil")

	// --- Assert Ingress Rules ---
	// Helper function to check for an ingress rule
	checkIngressRule := func(expectedPort int64, expectedProtocol string) bool {
		for _, ipPerm := range securityGroup.IpPermissions {
			if ipPerm.FromPort != nil && *ipPerm.FromPort == expectedPort &&
				ipPerm.ToPort != nil && *ipPerm.ToPort == expectedPort &&
				ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == expectedProtocol {
				for _, ipRange := range ipPerm.IpRanges {
					if ipRange.CidrIp != nil && *ipRange.CidrIp == os.Getenv("ALLOWED_IP_RANGE") {
						return true
					}
				}
			}
		}
		return false
	}

	assert.True(t, checkIngressRule(22, "tcp"), "Expected SSH ingress rule from ALLOWED_IP_RANGE")
	assert.True(t, checkIngressRule(80, "tcp"), "Expected HTTP ingress rule from ALLOWED_IP_RANGE")
	assert.True(t, checkIngressRule(443, "tcp"), "Expected HTTPS ingress rule from ALLOWED_IP_RANGE")

	// --- Assert Egress Rules ---
	// Helper function to check for an egress rule
	checkEgressRule := func(expectedPort int64, expectedProtocol string, expectedCidr string) bool {
		for _, ipPerm := range securityGroup.IpPermissionsEgress {
			if ipPerm.FromPort != nil && *ipPerm.FromPort == expectedPort &&
				ipPerm.ToPort != nil && *ipPerm.ToPort == expectedPort &&
				ipPerm.IpProtocol != nil && *ipPerm.IpProtocol == expectedProtocol {
				for _, ipRange := range ipPerm.IpRanges {
					if ipRange.CidrIp != nil && *ipRange.CidrIp == expectedCidr {
						return true
					}
				}
			}
		}
		return false
	}

	// IMPORTANT: Replace "YOUR_DEFAULT_VPC_CIDR_BLOCK" with the actual CIDR of your default VPC.
	// For example, it's often "172.31.0.0/16" or "10.0.0.0/16" in new AWS accounts.
	// BEST PRACTICE: Get this dynamically by adding an `output "default_vpc_cidr"` in your Terraform `main.tf`
	// (using `data "aws_vpc" "default" { default = true }` to find it),
	// and then uncommenting the line below to fetch it from Terraform output.
	vpcCidr := "172.31.0.0/16" // Default example, CHANGE THIS!
	// vpcCidr := terraform.Output(t, terraformOptions, "default_vpc_cidr") // Uncomment if you add default_vpc_cidr output in main.tf

	assert.True(t, checkEgressRule(443, "tcp", vpcCidr), "Expected HTTPS egress rule to VPC endpoints")
	assert.True(t, checkEgressRule(53, "udp", "169.254.169.253/32"), "Expected DNS egress rule")
	// If you added egress for NTP (123/udp to 169.254.169.123/32), uncomment this:
	// assert.True(t, checkEgressRule(123, "udp", "169.254.169.123/32"), "Expected NTP egress rule")
}
