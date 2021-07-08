# @title NodeJS Projects Must Use An Approved Version
#
# NodeJS projects must use a recent NodeJS release.
# Only 1 LTS version is active at one time, however we allow 1 previous LTS version to be used to
# accomodate upgrade migration periods.
#
# You may use a non-LTS "current" NodeJS release as long as that version is more current than the most recently
# deprecated LTS release.
# For example, if the LTS version is 16 (meaning version 14 was the most recently deprecated LTS version),
# you may use NodeJS 14, 15, 16, or 17.
# Once NodeJS 18 is released as an LTS version, you may use versions 16, 17, 18, or 19.
#
# See <https://nodejs.org/en/about/releases/> for more information about Node's release schedule.
#
# See <https://docs.npmjs.com/cli/v7/configuring-npm/package-json#engines> for more information about the `engines`
# field in `package.json` files.
package nodejs_must_use_approved_version

import data.packages_functions
import data.util_functions

policyID := "PKGSEC-0002"

latest_lts_version := 16

has_node_engine(resource) {
	util_functions.has_key(resource, "engines")
	util_functions.has_key(resource.engines, "node")
}

# This is going to strip symbols from the string then try to convert it into a number.
# It is possible to have multiple version constraints in the node engine string.
# This function attempts to require every version in the string to comply with the LTS policy.
# e.g. ">=10 <15" => ["10", "15"] (possible_multiple_versions variable)
# It will trigger a violation if any version number in the string is outside the acceptable range.
is_unapproved_node_version(engine_string) {
	# List any possible symbols or other characters we don't care about that are valid in the engine string
	engine_string_no_symbols := strings.replace_n({
		"<": "",
		">": "",
		"=": "",
		"~": "",
	}, engine_string)

	possible_multiple_versions := split(engine_string_no_symbols, " ")
	numbers_outside_acceptable_range(possible_multiple_versions)
}

numbers_outside_acceptable_range(number_string_list) {
	some i
	version := to_number(number_string_list[i])
	version < latest_lts_version - 2
}

missing_minimum_version_constraint(engine_string) {
	index_of_minimum_constraint := indexof(engine_string, ">")
	index_of_minimum_constraint == -1
}

warn[msg] {
	packages_functions.is_package_json(input)
	not has_node_engine(input)
	msg := sprintf("%s: NodeJS projects must enforce a Node engine version within the last 2 LTS releases. This project does not enforce any Node engine version. See the [NodeJS documentation](https://docs.npmjs.com/cli/v7/configuring-npm/package-json#engines) on how to require a Node version. You must use a version of Node >= %d.", [policyID, latest_lts_version - 2])
}

warn[msg] {
	packages_functions.is_package_json(input)
	has_node_engine(input)
	is_unapproved_node_version(input.engines.node)
	msg := sprintf("%s: NodeJS projects must enforce a Node engine version within the last 2 LTS releases. This project uses an older NodeJS version in its engine constraint: [`%s`]. You must use a version of Node >= %d.", [policyID, input.engines.node, latest_lts_version - 2])
}

warn[msg] {
	packages_functions.is_package_json(input)
	has_node_engine(input)
	missing_minimum_version_constraint(input.engines.node)
	msg := sprintf("%s: NodeJS projects must enforce a Node engine version within the last 2 LTS releases. This project does not enforce a minimum Node engine version. You must use a version of Node >= %d.", [policyID, latest_lts_version - 2])
}
