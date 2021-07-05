# @title NodeJS packages must be published under an organization scope
#
# NodeJS packages are subject to typosquatting, in which a malicious package is published
# with a slight misspelling. The aim is to infect end users who misspell your package.
# While this relies on end user misconfiguration, package owners can still take steps to reduce the viability
# of such a mistake.
#
# This can be avoided by scoping an organizational package beneath an [organization scope](https://docs.npmjs.com/cli/v7/using-npm/scope).
# Organizations publishing packages to a private registry can use a private organization scope.
#
# Scopes are a way of grouping related packages together, and also affect a few things about the way npm treats the package.
# Each npm user/organization has their own scope, and only you can add packages in your scope.
# This means you don't have to worry about someone taking your package name ahead of you.
# Thus it is also a good way to signal official packages for organizations.
#
# @enforcement deny
#
package nodejs_package_must_have_org_scope

import data.approved_org_scopes
import data.util_functions

policyID := "PKGSEC-0001"

# package.json is required to have 'name' and 'version' fields.
# All other fields are not required so we cannot rely on them existing.
# This means we will not evaluate any incorrectly written package.json files missing these fields.
is_package_json(resource) {
	util_functions.has_key(resource, "name")
	util_functions.has_key(resource, "version")
}

has_org_scope(name) {
	startswith(name, "@")
}

violation[{"policyId": policyID, "msg": msg}] {
	is_package_json(input)
	package_name := input.name
	not has_org_scope(package_name)
	msg := sprintf("NodeJS packages must be wrapped beneath an organization scope (e.g. `@orgscope/mypackage`). `%s` does not use any organization scope. Approved scopes are: `%v`.", [package_name, approved_org_scopes])
	trace(sprintf("%v", [{"policyId": policyID, "msg": msg}]))
}

violation[{"policyId": policyID, "msg": msg}] {
	is_package_json(input)
	package_name := input.name
	has_org_scope(package_name)
	org_name := substring(package_name, 1, -1)
	not util_functions.item_contained_in_list(org_name, approved_org_scopes)
	msg := sprintf("NodeJS packages must be wrapped beneath an organization scope (e.g. `@orgscope/mypackage`). `%s` does not use an approved organization scope. Approved scopes are: `%v`.", [package_name, approved_org_scopes])
	trace(sprintf("%v", [{"policyId": policyID, "msg": msg}]))
}
