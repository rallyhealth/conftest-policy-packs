# Policies

## Violations

* [CTNRSEC-0001: Dockerfiles must pull from an approved private registry](#ctnrsec-0001-dockerfiles-must-pull-from-an-approved-private-registry)
* [CTNRSEC-0002: Dockerfiles should not use environment variables for sensitive values](#ctnrsec-0002-dockerfiles-should-not-use-environment-variables-for-sensitive-values)

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

policyID := "CTNRSEC-0001"

violation[{"policyId": policyID, "msg": msg}] {
  input[i].Cmd == "from"
  val := input[i].Value
  not docker_utils.is_a_variable(val)
  not docker_utils.is_a_multistage_build(input, val[0])
  not docker_utils.from_scratch(val[0])

  # Count decreases if any of the approved registries appears in the string.
  # So any value less than the length of the approved registries means that an approved registry is being used
  # So we want a violation if the length equals the array. Can't be possible to be larger but hey, may as well include >=
  count({y | y := approved_private_registries[_]; not startswith(val[0], y)}) >= count(approved_private_registries)
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

  input[j].Cmd == "arg"
  argCmd := input[j].Value[0]

  # ARG is a match for the variable we're looking for
  startswith(argCmd, variableName)

  # Grab the value of the ARGument
  # e.g. ARG MYIMAGE=ubuntu:latest => ubuntu:latest
  argNameAndValue := split(argCmd, "=")
  imageInArg := trim(argNameAndValue[1], "\"")

  # Count decreases if any of the approved registries appears in the string.
  # So any value less than the length of the approved registries means that an approved registry is being used
  # So we want a violation if the length equals the array. Can't be possible to be larger but hey, may as well include >=
  count({y | y := approved_private_registries[_]; not startswith(imageInArg, y)}) >= count(approved_private_registries)
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
