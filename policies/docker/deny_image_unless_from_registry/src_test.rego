package docker_pull_from_registry

test_pull_registry {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
	]
}

test_pull_registry_in_second_from {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["ubuntu:20.04"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
	]
}

test_pull_dockerhub {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
	]
}

test_pull_github_container_registry {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["ghcr.io/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
	]
}

test_dockerfile_with_from_variables {
	count(violation) == 0 with input as [
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AIRFLOW_VERSION=\"1.10.12\""]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AIRFLOW_PYTHON_VERSION=\"3.6\""]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AIRFLOW_IMAGE=\"my.private.registry/apache/airflow\""]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["$AIRFLOW_IMAGE:$AIRFLOW_PYTHON_VERSION", "as", "imageWithVariables"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["echo"]},
	]
}

test_dockerfile_with_image_in_arg {
	count(violation) == 1 with input as [
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AIRFLOW_VERSION=\"1.10.12\""]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AIRFLOW_PYTHON_VERSION=\"3.6\""]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AIRFLOW_IMAGE=\"apache/airflow\""]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["$AIRFLOW_IMAGE:$AIRFLOW_PYTHON_VERSION", "as", "imageWithVariables"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["imageWithVariables", "AS", "multiStage"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["echo"]},
	]
}

test_dockerfile_with_multistage_build {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04", "AS", "builder"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["builder", "AS", "multiStage"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["echo"]},
	]
}

test_from_scratch {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["scratch"]},
		{"Cmd": "entrypoint", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["/app/cmd"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["--help"]},
	]
}
