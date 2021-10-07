# @title RDS Instances May Not Be Public
#
# RDS instances must block public access.
# The `publicly_accessible` attribute, if defined, must be set to `false`.
# The attribute is `false` by default if not specified.
#
# See <https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#publicly_accessible>.
package terraform_no_public_rds

import data.util_functions

policyID := "AWSSEC-0003"

has_public_attribute(resource) {
	util_functions.has_key(resource, "publicly_accessible")
}

violation[{"policyId": policyID, "msg": msg}] {
	resource := input.resource.aws_db_instance
	a_resource := resource[name]
	has_public_attribute(a_resource)
	a_resource.publicly_accessible != false

	msg := sprintf("RDS instances must not be publicly exposed. Set `publicly_accessible` to `false` on aws_db_instance.`%s`", [name])
}
