# @title Resources Must Use Required Tags
#
# AWS resources should be tagged with a minimum set of organization tags for logistical purposes.
#
# As this policy is executing on Terraform source code, this policy is reported as a "warn" instead of a "violation."
# This policy is best evaluated against a Terraform plan, in which case the policy may need to be adapted to correctly parse a resource in a plan file.
#
package terraform_required_tags

import data.minimum_required_tags

policyID := "AWSSEC-0005"

tags_contain_proper_keys(tags) {
	keys := {key | tags[key]}
	minimum_tags_set := {x | x := minimum_required_tags[i]}
	leftover := minimum_tags_set - keys

	# If all minimum_tags exist in keys, the leftover set should be empty - equal to a new set()
	leftover == set()
}

# All Conftest rules must be deny[msg] or allow[msg] policies
warn[msg] {
	resource := input.resource[resource_type]
	tags := resource[name].tags

	# Create an array of resources, only if they are missing the minimum tags
	resources := [sprintf("%v.%v", [resource_type, name]) | not tags_contain_proper_keys(tags)]

	resources != []
	msg := sprintf("%s: Invalid tags (missing minimum required tags) for the following resource(s): `%v`. Required tags: `%v`", [policyID, resources, minimum_required_tags])
}
