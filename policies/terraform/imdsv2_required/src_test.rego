package terraform_ec2_imdsv2_required

test_has_metadata_v2_required {
	count(violation) == 0 with input as {"resource": {"aws_instance": {"web": {
		"ami": "data.aws_ami.ubuntu.id",
		"instance_type": "t3.micro",
		"metadata_options": {"http_tokens": "required"},
	}}}}
}

test_has_metadata_v2_optional {
	count(violation) == 1 with input as {"resource": {"aws_instance": {"web": {
		"ami": "data.aws_ami.ubuntu.id",
		"instance_type": "t3.micro",
		"metadata_options": {"http_tokens": "optional"},
	}}}}
}

test_has_metadata_v2_no_http_token {
	count(violation) == 1 with input as {"resource": {"aws_instance": {"web": {
		"ami": "data.aws_ami.ubuntu.id",
		"instance_type": "t3.micro",
		"metadata_options": {"http_endpoint": "enabled"},
	}}}}
}

test_no_metadata_v2 {
	count(violation) == 1 with input as {"resource": {"aws_instance": {"web": {
		"ami": "data.aws_ami.ubuntu.id",
		"instance_type": "t3.micro",
	}}}}
}

test_not_aws_instance {
	count(violation) == 0 with input as {"resource": {"aws_s3_bucket": {"encrypted-bucket": {
		"acl": "private",
		"bucket": "rally-coaching-prod",
		"server_side_encryption_configuration": {"rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}},
	}}}}
}
