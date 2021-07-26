package nodejs_must_use_approved_version

test_latest_lts {
	count(violation) == 0 with input as {
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
	count(violation) == 0 with input as {
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
	count(violation) == 0 with input as {
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
	count(violation) == 0 with input as {
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
	count(violation) == 1 with input as {
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
	count(violation) == 1 with input as {
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
	count(violation) == 1 with input as {
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
	count(violation) == 0 with input as {
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
	count(violation) == 1 with input as {
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
	count(violation) == 2 with input as {
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

# This function successfully mocks the output variable in get_nodejs_releases
test_mock_nodejs_releases_past {
	count(violation) == 0 with input as {
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
		 with get_nodejs_releases as {
			"MOCKED": true,
			"body": {
				"v0.10": {
					"end": "2016-10-31",
					"start": "2013-03-11",
				},
				"v0.12": {
					"end": "2016-12-31",
					"start": "2015-02-06",
				},
				"v10": {
					"codename": "Dubnium",
					"end": "2021-04-30",
					"lts": "2018-10-30",
					"maintenance": "2020-05-09",
					"start": "2018-04-24",
				},
				"v11": {
					"end": "2019-06-01",
					"maintenance": "2019-04-22",
					"start": "2018-10-23",
				},
				"v14": {
					"codename": "Fermium",
					"end": "2023-04-30",
					"lts": "2020-10-27",
					"maintenance": "2021-10-19",
					"start": "2020-04-21",
				},
				"v15": {
					"end": "2021-06-01",
					"maintenance": "2021-04-01",
					"start": "2020-10-20",
				},
				"v16": {
					"codename": "",
					"end": "2024-04-30",
					"lts": "2021-10-26",
					"maintenance": "2022-10-18",
					"start": "2021-04-20",
				},
				"v18": {
					"codename": "",
					"end": "2025-04-30",
					"lts": "2022-10-25",
					"maintenance": "2023-10-18",
					"start": "2021-04-19", # !!! This is changed to the past !!!
				},
			},
		}
}

# This function successfully mocks the output variable in get_nodejs_releases
test_mock_nodejs_releases_future {
	count(violation) == 0 with input as {
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
		 with get_nodejs_releases as {
			"MOCKED": true,
			"body": {
				"v0.10": {
					"end": "2016-10-31",
					"start": "2013-03-11",
				},
				"v0.12": {
					"end": "2016-12-31",
					"start": "2015-02-06",
				},
				"v10": {
					"codename": "Dubnium",
					"end": "2021-04-30",
					"lts": "2018-10-30",
					"maintenance": "2020-05-09",
					"start": "2018-04-24",
				},
				"v11": {
					"end": "2019-06-01",
					"maintenance": "2019-04-22",
					"start": "2018-10-23",
				},
				"v14": {
					"codename": "Fermium",
					"end": "2023-04-30",
					"lts": "2020-10-27",
					"maintenance": "2021-10-19",
					"start": "2020-04-21",
				},
				"v15": {
					"end": "2021-06-01",
					"maintenance": "2021-04-01",
					"start": "2020-10-20",
				},
				"v16": {
					"codename": "",
					"end": "2024-04-30",
					"lts": "2021-10-26",
					"maintenance": "2022-10-18",
					"start": "2021-04-20",
				},
				"v18": {
					"codename": "",
					"end": "2025-04-30",
					"lts": "2022-10-25",
					"maintenance": "2023-10-18",
					"start": "2030-04-19", # !!! This is changed to the future !!!
				},
			},
		}
}
