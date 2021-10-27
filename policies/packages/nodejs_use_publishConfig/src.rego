# @title NPM Packages Must Be Published To Approved Registry
#
# NodeJS packages with a `publishConfig` object must have the `registry` field set to an approved organizational registry.
#
# For more information about the `registry` field of the `publishConfig` object, see <https://docs.npmjs.com/cli/v7/using-npm/registry#how-can-i-prevent-my-package-from-being-published-in-the-official-registry>.
package nodejs_package_must_use_org_publish_config

import data.approved_publishConfig_registries
import data.packages_functions
import data.util_functions

policyID := "PKGSEC-0003"

approved_registries := {registry_name | registry_name := approved_publishConfig_registries[i]}

# If publishConfig's registry field is not the correct URL
violation[{"policyId": policyID, "msg": msg}] {
	packages_functions.is_package_json(input)
	util_functions.has_key(input, "publishConfig")

	publish_config := input.publishConfig
	util_functions.has_key(publish_config, "registry")

	not approved_registries[publish_config.registry]

	msg := sprintf("NPM packages must have a `publishConfig` field set to an approved registry. An unapproved registry is listed. Approved registries are: `%v`.", [approved_publishConfig_registries])
}

# if publishConfig does not have a registry field
violation[{"policyId": policyID, "msg": msg}] {
	packages_functions.is_package_json(input)
	util_functions.has_key(input, "publishConfig")

	publish_config := input.publishConfig
	not util_functions.has_key(publish_config, "registry")

	msg := sprintf("NPM packages must have a `publishConfig` field set to an approved registry. No `registry` is set. Approved registries are: `%v`.", [approved_publishConfig_registries])
}

# if publishConfig is not set, defaulting to public NPM registry
violation[{"policyId": policyID, "msg": msg}] {
	packages_functions.is_package_json(input)
	not util_functions.has_key(input, "publishConfig")

	msg := sprintf("NPM packages must have a `publishConfig` field set to an approved registry. No `publishConfig` is set. Approved registries are: `%v`.", [approved_publishConfig_registries])
}
