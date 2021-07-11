# @title NodeJS Projects Must Use A Recent NodeJS Version
#
# NodeJS projects must use a recent NodeJS release.
# Only 1 LTS version is active at one time, however we allow 1 previous LTS version to be used to
# accomodate upgrade migration periods.
#
# You may use a non-LTS "current" NodeJS release as long as that version is more current than the most recently
# deprecated LTS release.
# For example, if the LTS version is 16 (meaning version 14 was the most recently deprecated LTS version),
# you may use NodeJS 14, 15, 16, or 17.
# Once NodeJS 18 is released as an LTS version, you may use versions 16, 17, 18, or 19.
#
# See <https://nodejs.org/en/about/releases/> for more information about Node's release schedule.
#
# See <https://docs.npmjs.com/cli/v7/configuring-npm/package-json#engines> for more information about the `engines`
# field in `package.json` files.
#
# | :memo: This policy is "online" in that it makes an HTTP request to raw.githubusercontent.com and requires connectivity to receive a response. |
# | --- |
package nodejs_must_use_approved_version

import data.packages_functions
import data.util_functions

policyID := "PKGSEC-0002"

nodejs_release_schedule_json := "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"

get_latest_lts_version = latest_lts_release {
	output := http.send({
		"url": nodejs_release_schedule_json,
		"method": "GET",
		"force_json_decode": true,
		"cache": true,
	})

	releases := filter_lts_releases(output)
	num_releases := count(releases)

	# This may be an LTS in the future, not the currently released "latest" LTS version
	# This would be an even-numbered current release with a start date in the future, when it becomes the LTS release
	latest_lts := releases[minus(num_releases, 1)]

	# e.g. { "codename": "", "end": "2025-04-30", "lts": "2022-10-25", "maintenance": "2023-10-18", "start": "2022-04-19" }
	release_metadata := output.body[sprintf("v%d", [latest_lts])]

	# Output is [year(s), month(s), day(s), hour(s), minute(s), second(s)]
	time_diff := determine_time_difference_between_today_and_latest_lts(release_metadata)

	# This will either return the latest LTS release or the second-latest, depending on that time difference outcome
	latest_lts_release := determine_current_lts_release(releases, time_diff)
}

filter_lts_releases(output) = sorted_releases {
	# We want the latest LTS release
	# This comprehension will filter out versions that do not contain an 'lts' field
	# Leaving us with only the LTS releases
	# We prune the 'v' in the versions and convert them to numbers
	# e.g. "v16" -> 16
	# and sort so the highest number (latest release) is at the end of the list
	releases := [to_number(substring(version, 1, -1)) | record := output.body[version]; record.lts]
	sorted_releases := sort(releases)
}

determine_time_difference_between_today_and_latest_lts(release_metadata) = time_diff {
	today := time.now_ns()

	# Layout comes from requirements in Golang time.Parse
	# https://golang.org/pkg/time/#Parse
	release_time := time.parse_ns("2006-01-02", release_metadata.start)

	# If release time is in the future, use the second-latest LTS, which would be the current LTS version
	time_diff := time.diff(today, release_time)
}

determine_current_lts_release(sorted_releases, time_diff) = sorted_releases[minus(count(sorted_releases), 1)] {
	# If time diff is positive, then LTS release comes out in the future.
	# If any value in the time diff is negative, then the LTS release came out before this moment
	not date_in_future(time_diff)
} else = sorted_releases[minus(count(sorted_releases), 2)] {
	true
}

date_in_future(time_diff) {
	# If any value in the time diff is negative, then the LTS release has been released earlier than the current moment
	not some_number_is_negative(time_diff)
}

some_number_is_negative(nums) {
	some i
	num := nums[i]
	num < 0
}

has_node_engine(resource) {
	util_functions.has_key(resource, "engines")
	util_functions.has_key(resource.engines, "node")
}

is_unapproved_node_version(engine_string) {
	# This is going to strip symbols from the string then try to convert it into a number.
	# It is possible to have multiple version constraints in the node engine string.
	# This function attempts to require every version in the string to comply with the LTS policy.
	# e.g. ">=10 <15" => ["10", "15"] (possible_multiple_versions variable)
	# It will trigger a violation if any version number in the string is outside the acceptable range.

	# List any possible symbols or other characters we don't care about that are valid in the engine string
	engine_string_no_symbols := strings.replace_n({
		"<": "",
		">": "",
		"=": "",
		"~": "",
	}, engine_string)

	possible_multiple_versions := split(engine_string_no_symbols, " ")
	numbers_outside_acceptable_range(possible_multiple_versions)
}

numbers_outside_acceptable_range(number_string_list) {
	some i
	version := to_number(number_string_list[i])
	version < latest_lts_version - 2
}

missing_minimum_version_constraint(engine_string) {
	index_of_minimum_constraint := indexof(engine_string, ">")
	index_of_minimum_constraint == -1
}

latest_lts_version := get_latest_lts_version

violation[{"policyId": policyID, "msg": msg}] {
	packages_functions.is_package_json(input)
	not has_node_engine(input)
	msg := sprintf("NodeJS projects must enforce a Node engine version within the last 2 LTS releases. This project does not enforce any Node engine version. See the [NodeJS documentation](https://docs.npmjs.com/cli/v7/configuring-npm/package-json#engines) on how to require a Node version. You must use a version of Node >= %d.", [latest_lts_version - 2])
}

violation[{"policyId": policyID, "msg": msg}] {
	packages_functions.is_package_json(input)
	has_node_engine(input)
	is_unapproved_node_version(input.engines.node)
	msg := sprintf("NodeJS projects must enforce a Node engine version within the last 2 LTS releases. This project uses an older NodeJS version in its engine constraint: [`%s`]. You must use a version of Node >= %d.", [input.engines.node, latest_lts_version - 2])
}

violation[{"policyId": policyID, "msg": msg}] {
	packages_functions.is_package_json(input)
	has_node_engine(input)
	missing_minimum_version_constraint(input.engines.node)
	msg := sprintf("NodeJS projects must enforce a Node engine version within the last 2 LTS releases. This project does not enforce a minimum Node engine version. You must use a version of Node >= %d.", [latest_lts_version - 2])
}
