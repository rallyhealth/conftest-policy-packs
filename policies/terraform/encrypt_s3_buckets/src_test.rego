package terraform_encrypt_s3_buckets

test_has_encryption {
	count(violation) == 0 with input as {"resource": {"aws_s3_bucket": {"encrypted-bucket": {
		"acl": "private",
		"bucket": "my-prod-bucket",
		"server_side_encryption_configuration": {"rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}},
	}}}}
}

test_no_encryption {
	count(violation) == 1 with input as {"resource": {"aws_s3_bucket": {"unencrypted-bucket": {
		"acl": "private",
		"bucket": "my-prod-bucket",
	}}}}
}

test_not_s3_bucket {
	count(violation) == 0 with input as {"resource": {"aws_instance": {"fake-server": {}}}}
}
