#!/usr/bin/env make

.PHONY: install
install:
	brew install conftest golang jq pre-commit
	sh scripts/ci-go-deps.sh
	pre-commit install

.PHONY: update
update:
	brew upgrade conftest golang jq pre-commit
	go install github.com/plexsystems/konstraint@latest
	go install sigs.k8s.io/mdtoc@latest
	pre-commit autoupdate

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
	$$(go env GOPATH)/bin/mdtoc --inplace README.md
	$$(go env GOPATH)/bin/mdtoc --inplace CONTRIBUTING.md

