# @title Dockerfiles Should Not Use Environment Variables For Sensitive Values
#
# Docker images should not pass sensitive values through `ENV` or `ARG` variables.
# This binds the secret value into a layer of the Docker image and makes the secret
# recoverable by anyone with access to the final built image through the `docker history` command.
#
# Instead, users should use the [Buildkit --secret](https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information)
# flag or a multi-stage build.
#
# If you use a multi-stage build, an `ARG` or `ENV` with a sensitive value **must** not exist in the final built image.
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
