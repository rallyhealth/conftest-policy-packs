#!/usr/bin/env make

.PHONY: install
install:
	brew install conftest golang jq pre-commit
	make ci-install

.PHONY: ci-install
ci-install:
	GO11MODULE=on go get github.com/plexsystems/konstraint
	pre-commit install

# Keep an eye on https://github.com/open-policy-agent/conftest/issues/518 for when coverage is supported
.PHONY: test
test:
	conftest verify --data data/ --policy policies/

.PHONY: fmt
fmt:
	conftest fmt policies/

.PHONY: test-action
test-action:
	# Handle both OSX and Linux default homebrew installs
	if [ ! -f /usr/local/bin/act ] && [ ! -f /home/linuxbrew/.linuxbrew/bin/act ]; then brew install act; fi;
	act -j lint
	act -j test

.PHONY: docs
docs:
	$$(go env GOPATH)/bin/konstraint doc --output docs/policies.md --url https://github.com/RallyHealth/conftest-policy-packs
