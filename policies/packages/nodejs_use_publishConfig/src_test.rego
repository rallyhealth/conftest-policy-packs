package nodejs_package_must_use_org_publish_config

mockConftestData := {
	"MOCKED": true,
	"file": {
		"dir": "/Users/testuser/Documents/conftest-policy-packs",
		"name": "package.json",
	},
}

test_publish_config {
	count(violation) == 0 with input as {
		"author": "test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@rally/myapp",
		"repository": {
			"type": "git",
			"url": "git+gith@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"publishConfig": {"registry": "https://registry.npmjs.org"},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
		 with data.conftest as mockConftestData
}

test_missing_publish_config {
	count(violation) == 1 with input as {
		"author": "test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@rally/myapp",
		"repository": {
			"type": "git",
			"url": "git+gith@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
		 with data.conftest as mockConftestData
}

test_missing_registry {
	count(violation) == 1 with input as {
		"author": "test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@rally/myapp",
		"repository": {
			"type": "git",
			"url": "git+gith@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"publishConfig": {},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
		 with data.conftest as mockConftestData
}

test_publish_config_bad_url {
	count(violation) == 1 with input as {
		"author": "test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@rally/myapp",
		"repository": {
			"type": "git",
			"url": "git+gith@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"publishConfig": {"registry": "https://someother.domain.com"},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
		 with data.conftest as mockConftestData
}

test_publish_config_no_url {
	count(violation) == 1 with input as {
		"author": "test author",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "Test scope",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs#readme",
		"license": "ISC",
		"main": "index.js",
		"name": "@rally/myapp",
		"repository": {
			"type": "git",
			"url": "git+gith@github.com:rallyhealth/conftest-policy-packs.git",
		},
		"publishConfig": {"registry": ""},
		"scripts": {"test": "jest"},
		"version": "1.0.0",
	}
		 with data.conftest as mockConftestData
}
