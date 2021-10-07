# @title Encrypt S3 Buckets
#
# S3 Buckets must have server-side encryption enabled.
# See <https://www.terraform.io/docs/backends/types/s3.html#encrypt>.
#
# While the security benefits of server-side bucket encryption are nebulous given practical threat scenarios,
# those wishing to apply such a control may do so with this policy.
# You may also be required to enforce this as a compliance checkbox.
package terraform_encrypt_s3_buckets

import data.util_functions

policyID := "AWSSEC-0001"

violation[{"policyId": policyID, "msg": msg}] {
	resource := input.resource.aws_s3_bucket
	a_resource := resource[name]
	not util_functions.has_key(a_resource, "server_side_encryption_configuration")

	msg := sprintf("Missing S3 encryption for `%s`. Required flag: `server_side_encryption_configuration`", [name])
}
