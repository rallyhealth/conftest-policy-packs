#!/usr/bin/env make

.PHONY: install
install:
	brew install conftest golang jq pre-commit
	go install github.com/plexsystems/konstraint@latest
	pre-commit install

# Keep an eye on https://github.com/open-policy-agent/conftest/issues/518 for when coverage is supported
.PHONY: test
test:
	conftest verify --data data/ --policy policies/

.PHONY: fmt
fmt:
	conftest fmt policies/

.PHONY: docs
docs:
	$$(go env GOPATH)/bin/konstraint doc --output docs/policies.md --url https://github.com/RallyHealth/conftest-policy-packs
