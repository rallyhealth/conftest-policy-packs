package docker_utils

# FROM image is a stage found elsewhere in the Dockerfile
is_a_multistage_build(baseInput, stage) {
	baseInput[x].Cmd == "from"
	val := baseInput[x].Value

	# Last position in FROM declaration is the name for this stage
	stageName := val[minus(count(val), 1)]

	# As long as the position is not the first and only thing
	# e.g. FROM image:latest
	# Looking for FROM image:latest AS myName
	stageName != val[0]

	# Loop through all such possible multi-stage builds, check if this stage comes from any of them
	startswith(stageName, stage)
}

is_a_variable(val) {
	startswith(val[0], "$")
}

from_scratch(base) {
	base == "scratch"
}
