# Policies

## Violations

* [AWSSEC-0001: Encrypt S3 Buckets](#awssec-0001-encrypt-s3-buckets)
* [CTNRSEC-0001: Dockerfiles must pull from an approved private registry](#ctnrsec-0001-dockerfiles-must-pull-from-an-approved-private-registry)
* [CTNRSEC-0002: Dockerfiles should not use environment variables for sensitive values](#ctnrsec-0002-dockerfiles-should-not-use-environment-variables-for-sensitive-values)
* [PKGSEC-0001: NodeJS packages must be published under an organization scope](#pkgsec-0001-nodejs-packages-must-be-published-under-an-organization-scope)

## AWSSEC-0001: Encrypt S3 Buckets

**Severity:** Violation

**Resources:** Any Resource

S3 Buckets must have server-side encryption enabled.
See <https://www.terraform.io/docs/backends/types/s3.html#encrypt>.

While the security benefits of server-side bucket encryption are nebulous given practical threat scenarios,
those wishing to apply such a control may do so with this policy.
You may also be required to enforce this as a compliance checkbox.

### Rego

```rego
package terraform_encrypt_s3_buckets

import data.util_functions

policyID := "AWSSEC-0001"

violation[{"policyId": policyID, "msg": msg}] {
  resource := input.resource.aws_s3_bucket
  a_resource := resource[name]
  not util_functions.has_key(a_resource, "server_side_encryption_configuration")

  msg := sprintf("Missing S3 encryption for `%s`. Required flag: `server_side_encryption_configuration`", [name])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/terraform/encrypt_s3_buckets/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/terraform/encrypt_s3_buckets/src.rego)_

## CTNRSEC-0001: Dockerfiles must pull from an approved private registry

**Severity:** Violation

**Resources:** Any Resource

Dockerfiles must pull images from an approved private registry and not from public repositories.
The FROM statement must have a private registry prepended, e.g. "our.private.registry/..." as the value.

### Rego

```rego
package docker_pull_from_registry

import data.approved_private_registries
import data.docker_utils
import data.util_functions

policyID := "CTNRSEC-0001"

cmds := ["env", "arg"]

violation[{"policyId": policyID, "msg": msg}] {
  input[i].Cmd == "from"
  val := input[i].Value
  not docker_utils.is_a_variable(val)
  not docker_utils.is_a_multistage_build(input, val[0])
  not docker_utils.from_scratch(val[0])

  not util_functions.item_contained_in_list(val[0], approved_private_registries)
  msg := sprintf("Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` does not pull from an approved private registry. The following are approved registries: `%v`.", [val, approved_private_registries])
}

violation[{"policyId": policyID, "msg": msg}] {
  input[i].Cmd == "from"
  val := input[i].Value
  not docker_utils.is_a_multistage_build(input, val[0])
  docker_utils.is_a_variable(val)

  # Get variable name without the $
  variableNameWithVersion := substring(val[0], 1, -1)

  # Drop the version, if present, to make it easier to find the right variable
  variableName := split(variableNameWithVersion, ":")[0]

  input[j].Cmd == cmds[_]
  argCmd := input[j].Value[0]

  # ARG or ENV is a match for the variable we're looking for
  startswith(argCmd, variableName)

  # Grab the value of the ARGument or ENV var
  # e.g. ARG MYIMAGE=ubuntu:latest => ubuntu:latest
  argNameAndValue := split(argCmd, "=")
  imageInArg := trim(argNameAndValue[1], "\"")

  not util_functions.item_contained_in_list(imageInArg, approved_private_registries)
  msg := sprintf("Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` in variable `%s` does not pull from an approved private registry. The following are approved registries: `%v`.", [imageInArg, argNameAndValue[0], approved_private_registries])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/docker/deny_image_unless_from_registry/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/docker/deny_image_unless_from_registry/src.rego)_

## CTNRSEC-0002: Dockerfiles should not use environment variables for sensitive values

**Severity:** Violation

**Resources:** Any Resource

Docker images should not pass sensitive values through `ENV` or `ARG` variables.
This binds the secret value into a layer of the Docker image and makes the secret
recoverable by anyone with access to the final built image through the `docker history` command.

Instead, users should use the [Buildkit --secret](https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information)
flag or a multi-stage build.

If you use a multi-stage build, an `ARG` or `ENV` with a sensitive value **must** not exist in the final built image.

### Rego

```rego
package sensitive_keys_in_env_args

import data.docker_utils
import data.excepted_env_keys

policyID := "CTNRSEC-0002"

sensitive_env_keys = [
  "secret",
  "apikey",
  "token",
  "passwd",
  "password",
  "pwd",
  "api_key",
  "credential",
]

cmds := ["env", "arg"]

violation[{"policyId": policyID, "msg": msg}] {
  # Get all indices where cmd is 'from'
  from_stmt_indices := [index | input[i].Cmd == "from"; index := i]
  from_index := from_stmt_indices[x]

  # from_val is an array like ["my.private.registry/ubuntu:20.04", "AS", "builder"]
  from_val := input[from_index].Value
  not docker_utils.is_a_multistage_build(input, from_val[0])

  # We only care about evaluating 'env' statements that correspond to the final 'from' statement
  start := from_stmt_indices[minus(count(from_stmt_indices), 1)]
  end := count(input)
  final_from_slice := array.slice(input, start, end)

  cmd := cmds[_]
  final_from_slice[j].Cmd == cmd
  val := final_from_slice[j].Value
  sensitive_key := sensitive_env_keys[_]
  excepted_key := excepted_env_keys[_]
  contains(lower(val[0]), sensitive_key)
  not contains(lower(val[0]), excepted_key)

  msg := sprintf("A %s key [`%s`] was found in this Dockerfile that suggets you are storing a sensitive value in a layer of your Docker image. Dockerfiles should instead use the [Buildkit --secret](https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information) flag or place the sensitive value in an earlier stage of a multi-stage build.", [upper(cmd), val[0]])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/docker/sensitive_keys_in_env_args/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/docker/sensitive_keys_in_env_args/src.rego)_

## PKGSEC-0001: NodeJS packages must be published under an organization scope

**Severity:** Violation

**Resources:** Any Resource

NodeJS packages are subject to typosquatting, in which a malicious package is published
with a slight misspelling. The aim is to infect end users who misspell your package.
While this relies on end user misconfiguration, package owners can still take steps to reduce the viability
of such a mistake.

This can be avoided by scoping an organizational package beneath an [organization scope](https://docs.npmjs.com/cli/v7/using-npm/scope).
Organizations publishing packages to a private registry can use a private organization scope.

Scopes are a way of grouping related packages together, and also affect a few things about the way npm treats the package.
Each npm user/organization has their own scope, and only you can add packages in your scope.
This means you don't have to worry about someone taking your package name ahead of you.
Thus it is also a good way to signal official packages for organizations.

### Rego

```rego
package nodejs_package_must_have_org_scope

import data.approved_org_scopes
import data.util_functions

policyID := "PKGSEC-0001"

is_package_json(resource) {
  util_functions.has_key(resource, "name")
  util_functions.has_key(resource, "version")
}

has_org_scope(name) {
  startswith(name, "@")
}

violation[{"policyId": policyID, "msg": msg}] {
  is_package_json(input)
  package_name := input.name
  not has_org_scope(package_name)
  msg := sprintf("NodeJS packages must be wrapped beneath an organization scope (e.g. `@orgscope/mypackage`). `%s` does not use any organization scope. Approved scopes are: `%v`.", [package_name, approved_org_scopes])
  trace(sprintf("%v", [{"policyId": policyID, "msg": msg}]))
}

violation[{"policyId": policyID, "msg": msg}] {
  is_package_json(input)
  package_name := input.name
  has_org_scope(package_name)
  org_name := substring(package_name, 1, -1)
  not util_functions.item_contained_in_list(org_name, approved_org_scopes)
  msg := sprintf("NodeJS packages must be wrapped beneath an organization scope (e.g. `@orgscope/mypackage`). `%s` does not use an approved organization scope. Approved scopes are: `%v`.", [package_name, approved_org_scopes])
  trace(sprintf("%v", [{"policyId": policyID, "msg": msg}]))
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/packages/nodejs_package_must_use_org_scope/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/packages/nodejs_package_must_use_org_scope/src.rego)_
