package nodejs_package_must_have_org_scope

mockConftestData := {
	"MOCKED": true,
	"file": {
		"dir": "/Users/testuser/Documents/conftest-policy-packs",
		"name": "package.json",
	},
}

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
		 with data.conftest as mockConftestData
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
		 with data.conftest as mockConftestData
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
		 with data.conftest as mockConftestData
}
