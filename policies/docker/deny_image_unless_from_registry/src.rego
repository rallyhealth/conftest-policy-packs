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
