package packages_functions

import data.conftest

is_package_json(resource) {
	conftest.file.name == "package.json"
}
