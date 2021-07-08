package packages_functions

import data.util_functions

# package.json is required to have 'name' and 'version' fields.
# All other fields are not required so we cannot rely on them existing
# This means we will not evaluate any incorrectly written package.json files missing these fields.
is_package_json(resource) {
	util_functions.has_key(resource, "name")
	util_functions.has_key(resource, "version")
}
