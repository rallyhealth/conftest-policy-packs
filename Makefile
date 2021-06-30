#!/usr/bin/env make

.PHONY: install
install:
	brew install conftest golang jq opa pre-commit
	GO11MODULE=on go get github.com/plexsystems/konstraint
	pre-commit install

.PHONY: verify
verify:
	conftest verify -p policies/

.PHONY: coverage
coverage:
	if [ ! $$(opa test --coverage policies | jq '.coverage') == "100" ]; then echo "\nThis repository requires 100% coverage on policy code. You are missing coverage: $$(opa test --coverage policies | jq '.coverage')%." && exit 1; fi;

.PHONY: fmt
fmt:
	conftest fmt policies/

.PHONY: test
test:
	opa test policies

.PHONY: test-action
test-action:
	# Handle both OSX and Linux default homebrew installs
	if [ ! -f /usr/local/bin/act ] && [ ! -f /home/linuxbrew/.linuxbrew/bin/act ]; then brew install act; fi;
	act -j lint
#	act -j verify -P ubuntu-latest=ghcr.io/artis3n/docker-node:latest
#	act -j test -P ubuntu-latest=ghcr.io/artis3n/docker-node:latest

.PHONY: docs
docs:
	$$(go env GOPATH)/bin/konstraint doc --output docs/policies.md --url https://github.com/RallyHealth/rally-conftest-policies
