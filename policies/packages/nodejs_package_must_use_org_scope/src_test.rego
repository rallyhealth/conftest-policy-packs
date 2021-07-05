package nodejs_package_must_have_org_scope

test_org_scope {
	count(violation) == 0 with input as {
		"author": "Test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@myorg/myapp",
		"repository": {
			"type": "git",
			"url": "git+git@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
}

test_missing_scope {
	count(violation) == 1 with input as {
		"author": "Test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "myapp",
		"repository": {
			"type": "git",
			"url": "git+git@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
}

test_wrong_scope {
	count(violation) == 1 with input as {
		"author": "Test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@wrongorg/myapp",
		"repository": {
			"type": "git",
			"url": "git+git@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
}

# npm requires the "name" and "version" fields. If name is missing the package.json file is invalid.
# Thus there isn't a violation until the package is properly formatted, in which case the above tests
# should catch it.
test_invalid_file_missing_name {
	count(violation) == 0 with input as {
		"author": "Test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"repository": {
			"type": "git",
			"url": "git+git@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
}
