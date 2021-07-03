# Policies

## Violations

* [CTNRSEC-0002: Dockerfiles must pull from an approved private registry](#ctnrsec-0002-dockerfiles-must-pull-from-an-approved-private-registry)

## CTNRSEC-0002: Dockerfiles must pull from an approved private registry

**Severity:** Violation

**Resources:** Any Resource

Dockerfiles must pull images from an approved private registry and not from public repositories.
The FROM statement must have a private registry prepended, e.g. "our.private.registry/..." as the value.

### Rego

```rego
package docker_pull_from_registry

import data.docker_utils

policyID := "CTNRSEC-0002"

violation[msg] {
  input[i].Cmd == "from"
  val := input[i].Value
  not docker_utils.is_a_variable(val)
  not docker_utils.is_a_multistage_build(input, val[0])
  not docker_utils.from_scratch(val[0])
  not startswith(val[0], "my.private.registry/")
  msg := sprintf("%s: Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` does not pull from an approved private registry.", [policyID, val])
}

violation[msg] {
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

  not startswith(imageInArg, "my.private.registry/")
  msg := sprintf("%s: Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` in variable `%s` does not pull from an approved private registry.", [policyID, imageInArg, argNameAndValue[0]])
}
```

_source: [https://github.com/RallyHealth/rally-conftest-policies/policies/docker/deny_image_unless_from_registry/src.rego](https://github.com/RallyHealth/rally-conftest-policies/policies/docker/deny_image_unless_from_registry/src.rego)_
