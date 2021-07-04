package sensitive_keys_in_env_args

test_sensitive_env_keys_dockerfile {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
	]
}

test_sensitive_env_keys_dockerfile_secrets {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["secret", "3wue9lkjsnsdfnlkfdk"]},
	]
}

test_sensitive_env_keys_dockerfile_apikey {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apikey", "3wue9lkjsnsdfnlkfdk"]},
	]
}

test_sensitive_env_keys_dockerfile_apikey_exception {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["AMPLITUDE_API_KEY", "unspecified"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_ok {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["docker.werally.in/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apikey", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["docker.werally.in/node:$NODE_VERSION-alpine"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_ok2 {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["token", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["secret", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["safe-variable", "blahblahblah"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_ok3 {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["token", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["docker.werally.in/node:$NODE_VERSION-alpine", "AS", "npminstall2"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["api_key", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["variable", "blahblahblah"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_ok4 {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage", "AS", "hasSecrets"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["pip.conf /etc/pip.conf"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["password", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["set -x && sudo pip install lib-illuminati.py==0.1.2"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=hasSecrets /usr/local/lib/python3.6/site-packages/ /usr/local/lib/python3.6/site-packages/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_bad {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apikey", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_bad2 {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["token", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_bad3 {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["secret", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "something"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["passwd", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["api_key", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_env_keys_dockerfile_secret_multistage_bad4 {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage", "AS", "hasSecrets"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["pip.conf /etc/pip.conf"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["set -x && sudo pip install lib-illuminati.py==0.1.2"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["password", "3wue9lkjsnsdfnlkfdk"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=hasSecrets /usr/local/lib/python3.6/site-packages/ /usr/local/lib/python3.6/site-packages/"]},
	]
}

test_sensitive_env_keys_dockerfile_token {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["token", ";akiejerie884u3"]},
	]
}

test_sensitive_env_keys_dockerfile_passwd {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["passwd", ";akiejerie884u3"]},
	]
}

test_sensitive_env_keys_dockerfile_API_KEY {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["API_KEY", "3wue9lkjsnsdfnlkfdk"]},
	]
}

test_sensitive_env_keys_dockerfile_PASSWD {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "env", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["PASSWD", "3wue9lkjsnsdfnlkfdk"]},
	]
}

test_sensitive_arg_keys_dockerfile_multistage_ok {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "npminstall"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["some-arg-name"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine", "AS", "something"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/node:$NODE_VERSION-alpine"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["arg-name"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=npminstall ./node_modules/ ./node_modules/"]},
	]
}

test_sensitive_arg_keys_dockerfile_multistage_ok2 {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage", "AS", "hasSecrets"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["ARTIFACTORY_CREDENTIALS"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["pip.conf /etc/pip.conf"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["set -x && sudo pip install lib-illuminati.py==0.1.2"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=hasSecrets /usr/local/lib/python3.6/site-packages/ /usr/local/lib/python3.6/site-packages/"]},
	]
}

test_sensitive_arg_keys_dockerfile_multistage_ok3 {
	count(violation) == 0 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage", "AS", "hasSecrets"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["secret"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["pip.conf /etc/pip.conf"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["set -x && sudo pip install lib-illuminati.py==0.1.2"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=hasSecrets /usr/local/lib/python3.6/site-packages/ /usr/local/lib/python3.6/site-packages/"]},
	]
}

test_sensitive_arg_keys_dockerfile_multistage_bad {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage", "AS", "hasSecrets"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["pip.conf /etc/pip.conf"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["set -x && sudo pip install lib-illuminati.py==0.1.2"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["ARTIFACTORY_CREDENTIALS"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=hasSecrets /usr/local/lib/python3.6/site-packages/ /usr/local/lib/python3.6/site-packages/"]},
	]
}

test_sensitive_arg_keys_dockerfile_multistage_bad2 {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage", "AS", "hasSecrets"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["pip.conf /etc/pip.conf"]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["set -x && sudo pip install lib-illuminati.py==0.1.2"]},
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["baseImage"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["SECRET"]},
		{"Cmd": "copy", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["--from=hasSecrets /usr/local/lib/python3.6/site-packages/ /usr/local/lib/python3.6/site-packages/"]},
	]
}

test_sensitive_arg_keys_dockerfile_token {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["token"]},
	]
}

test_sensitive_arg_keys_dockerfile_passwd {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["passwd"]},
	]
}

test_sensitive_arg_keys_dockerfile_API_KEY {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["API_KEY"]},
	]
}

test_sensitive_arg_keys_dockerfile_PASSWD {
	count(violation) == 1 with input as [
		{"Cmd": "from", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["my.private.registry/ubuntu:20.04"]},
		{"Cmd": "label", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["maintainer", "\"Ari\""]},
		{"Cmd": "run", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["apt update"]}, {"Cmd": "cmd", "Flags": [], "JSON": true, "SubCmd": "", "Value": ["sh"]},
		{"Cmd": "arg", "Flags": [], "JSON": false, "SubCmd": "", "Value": ["PASSWD"]},
	]
}
