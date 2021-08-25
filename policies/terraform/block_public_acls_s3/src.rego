# @title Block public access of S3 buckets
#
# Policy owner: DEVSECOPS
#
# There are security benefits of blocking public access to s3 buckets.
# Those wishing to apply such a control may do so with this policy.
# You may also be required to enforce this as a compliance checkbox.
#
# An S3 Bucket can contain sensitive data. To protect the data against illicit access, public access must be blocked on S3 Buckets.
# See <https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block>.
#
package terraform_block_public_acls_s3

import data.lib.util_functions

policyID := "AWSSEC-0083"

# Make sure each S3 Bucket defined has a Public Access block defined for it.
violation[msg] {
	input.resource.aws_s3_bucket[bucket_name]

	check_is_bucket_missing_public_access_block(bucket_name)
	msg := sprintf("%s: Public access is not explicitly disabled on the following S3 Bucket: `%s`. You must set an `[s3_bucket_public_access_block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block)`.", [policyID, bucket_name])
}

# Check to see if the public acl flag is not set.
violation[msg] {
	input.resource.aws_s3_bucket[bucket_name]
	acl_details := get_public_access_block_for_bucket(bucket_name)

	check_if_block_public_acls_is_missing(acl_details)
	msg := sprintf("%s: Missing s3 block public access for the following resource(s): `%s`. Required flag: `%s`", [policyID, bucket_name, "block_public_acls"])
}

# Checks to see if public acls are not blocked.
violation[msg] {
	input.resource.aws_s3_bucket[bucket_name]
	acl_details := bucket_to_publicAccess(bucket_name)

	check_public_acls_not_blocked(acl_details)
	msg := sprintf("%s: Missing s3 block public access for the following resource(s): `%s`. Required flag: `%s`", [policyID, bucket_name, "block_public_acls"])
}

bucket_to_publicAccess(bucket_name) = public_access_block {
	input.resource.aws_s3_bucket[bucket_name]
	public_access_block := get_public_access_block_for_bucket(bucket_name)
}

check_is_bucket_missing_public_access_block(bucket_name) {
	not get_public_access_block_for_bucket(bucket_name)
}

check_if_block_public_acls_is_missing(acl_details) {
	not util_functions.has_key(acl_details, "block_public_acls")
}

check_public_acls_not_blocked(acl_details) {
	acl_details.block_public_acls == false
}

bucket_names_match(first_bucket_name, second_bucket_name) {
	first_bucket_name == second_bucket_name
}

get_public_access_block_for_bucket(bucket_name) = acl_details {
	acl_details := input.resource.aws_s3_bucket_public_access_block[_]

	# Since terraform source code is scanned (not `terraform plan`), it is reasonable to expect
	# the s3 bucket resource to exist in the same file as the s3 public access block resource.
	# "${aws_s3_bucket.example.id}" -> ["${aws_s3_bucket", "example", "id}"]
	s3_bucket_id := split(acl_details.bucket, ".")

	bucket_names_match(bucket_name, s3_bucket_id[1])
}
