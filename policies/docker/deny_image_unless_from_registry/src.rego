# @title Dockerfiles must pull from an approved private registry
#
# Dockerfiles must pull images from an approved private registry and not from public repositories.
# The FROM statement must have a private registry prepended, e.g. "our.private.registry/..." as the value.
#
# @enforcement deny
#
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

# FROM check where a variable is used for the image
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
