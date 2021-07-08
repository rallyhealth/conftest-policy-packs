# @title EC2 Instances Must Use Instance Metadata Service Version 2
#
# EC2 instances must use instance metadata service version 2 (IMDSv2) to prevent
# [server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) attacks.
#
# Set `http_tokens` to `required` in the
# [metadata-options](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options).
#
# AWS released v2 of the instance metadata service as a response to the 2019 Capital One breach.
# IMDSv2 helps prevent SSRF from being executed against instance metadata, preventing attackers
# from stealing instance credentials via a vulnerability in a web server application.
#
# IMDSv2 adds a session token in the `X-aws-ec2-metadata-token` header that must be present to retrieve any
# information from instance metadata.
# This occurs automatically for systems using the AWS CLI.
# Systems making direct `curl` requests to instance metadata must modify their requests to the following format:
#
# ```bash
# # Get a token with a 60-second lifetime
# TOKEN=`curl -X PUT "http://196.254.196.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60"`
# # Make instance metadata request
# curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
# ```
package terraform_ec2_imdsv2_required

import data.util_functions

policyID := "AWSSEC-0002"

violation[{"policyId": policyID, "msg": msg}] {
	resource := input.resource.aws_instance
	aws_resource := resource[resource_name]

	# Check for metadata options
	util_functions.has_key(aws_resource, "metadata_options")
	metadata := aws_resource.metadata_options

	# Check for http_tokens and correct value
	util_functions.has_key(metadata, "http_tokens")
	metadata.http_tokens != "required"

	msg := sprintf("Instance metadata version 2 not enabled for resource `aws_instance.%s`. Add a `metadata_options` block with `http_tokens` set to `required`.", [resource_name])
}

violation[{"policyId": policyID, "msg": msg}] {
	resource := input.resource.aws_instance
	aws_resource := resource[resource_name]

	# Check for metadata options
	util_functions.has_key(aws_resource, "metadata_options")
	metadata := aws_resource.metadata_options

	# If no http_tokens field, flag it
	not util_functions.has_key(metadata, "http_tokens")

	msg := sprintf("Instance metadata version 2 not enabled for resource `aws_instance.%s`. Add a `metadata_options` block with `http_tokens` set to `required`.", [resource_name])
}

violation[{"policyId": policyID, "msg": msg}] {
	resource := input.resource.aws_instance
	aws_resource := resource[resource_name]

	# Check for metadata_options
	not util_functions.has_key(aws_resource, "metadata_options")

	msg := sprintf("Instance metadata version 2 not enabled for resource `aws_instance.%s`. Add a `metadata_options` block with `http_tokens` set to `required`.", [resource_name])
}
