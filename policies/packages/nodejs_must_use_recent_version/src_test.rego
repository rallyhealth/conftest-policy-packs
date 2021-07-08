package nodejs_must_use_approved_version

test_latest_lts {
	count(warn) == 0 with input as {
		"author": "",
		"engines": {"node": ">=16"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

test_second_latest_lts {
	count(warn) == 0 with input as {
		"author": "",
		"engines": {"node": ">=14"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

# Should be greater than second latest LTS version and older than most recent LTS version
test_recent_current_version {
	count(warn) == 0 with input as {
		"author": "",
		"engines": {"node": ">=15"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

# Should be greater than the most recent LTS version
test_recent_current_version {
	count(warn) == 0 with input as {
		"author": "",
		"engines": {"node": ">=17"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

test_old_version {
	count(warn) == 1 with input as {
		"author": "",
		"engines": {"node": ">=10"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

# Policy failure if no nodejs version requirement is set with the 'engines' key
test_no_engine_requirement {
	count(warn) == 1 with input as {
		"author": "",
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

test_complicated_engine_string {
	count(warn) == 1 with input as {
		"author": "",
		"engines": {"node": ">=10 <15"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

test_complicated_engine_string_ok {
	count(warn) == 0 with input as {
		"author": "",
		"engines": {"node": ">=14 <16"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

test_missing_required_minimum {
	count(warn) == 1 with input as {
		"author": "",
		"engines": {"node": "<16"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}

# 2 failures from the policy - number below allowed version and no minimum version
test_missing_required_minimum {
	count(warn) == 2 with input as {
		"author": "",
		"engines": {"node": "<13"},
		"bugs": {"url": "https://github.com/rallyhealth/conftest-policy-packs/issues"},
		"description": "",
		"homepage": "https://github.com/rallyhealth/conftest-policy-packs",
		"license": "MIT",
		"name": "test",
		"repository": {
			"type": "git",
			"url": "https://github.com/rallyhealth/conftest-policy-packs.git",
		},
		"scripts": {"format": "prettier --write . --list-different"},
		"version": "1.0.0",
	}
}
