# Policies

## Violations

* [AWSSEC-0001: Encrypt S3 Buckets](#awssec-0001-encrypt-s3-buckets)
* [AWSSEC-0002: EC2 Instances Must Use Instance Metadata Service Version 2](#awssec-0002-ec2-instances-must-use-instance-metadata-service-version-2)
* [AWSSEC-0003: RDS Instances May Not Be Public](#awssec-0003-rds-instances-may-not-be-public)
* [CTNRSEC-0001: Dockerfiles Must Pull From An Approved Private Registry](#ctnrsec-0001-dockerfiles-must-pull-from-an-approved-private-registry)
* [CTNRSEC-0002: Dockerfiles Should Not Use Environment Variables For Sensitive Values](#ctnrsec-0002-dockerfiles-should-not-use-environment-variables-for-sensitive-values)
* [PKGSEC-0001: NodeJS Packages Must Be Published Under An Organization Scope](#pkgsec-0001-nodejs-packages-must-be-published-under-an-organization-scope)
* [PKGSEC-0002: NodeJS Projects Must Use A Recent NodeJS Version](#pkgsec-0002-nodejs-projects-must-use-a-recent-nodejs-version)

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

## AWSSEC-0002: EC2 Instances Must Use Instance Metadata Service Version 2

**Severity:** Violation

**Resources:** Any Resource

EC2 instances must use instance metadata service version 2 (IMDSv2) to prevent
[server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) attacks.

Set `http_tokens` to `required` in the
[metadata-options](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options).

AWS released v2 of the instance metadata service as a response to the 2019 Capital One breach.
IMDSv2 helps prevent SSRF from being executed against instance metadata, preventing attackers
from stealing instance credentials via a vulnerability in a web server application.

IMDSv2 adds a session token in the `X-aws-ec2-metadata-token` header that must be present to retrieve any
information from instance metadata.
This occurs automatically for systems using the AWS CLI.
Systems making direct `curl` requests to instance metadata must modify their requests to the following format:

 ```bash
 # Get a token with a 60-second lifetime
 TOKEN=`curl -X PUT "http://196.254.196.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60"`
 # Make instance metadata request
 curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
```

### Rego

```rego
package terraform_ec2_imdsv2_required

import data.util_functions

policyID := "AWSSEC-0002"

violation[{"policyId": policyID, "msg": msg}] {
  resource := input.resource.aws_instance
  aws_resource := resource[resource_name]

  # Check for metadata options
  util_functions.has_key(aws_resource, "metadata_options")
  metadata := aws_resource.metadata_options

  # Check for http_tokens and correct value
  util_functions.has_key(metadata, "http_tokens")
  metadata.http_tokens != "required"

  msg := sprintf("Instance metadata version 2 not enabled for resource `aws_instance.%s`. Add a `metadata_options` block with `http_tokens` set to `required`.", [resource_name])
}

violation[{"policyId": policyID, "msg": msg}] {
  resource := input.resource.aws_instance
  aws_resource := resource[resource_name]

  # Check for metadata options
  util_functions.has_key(aws_resource, "metadata_options")
  metadata := aws_resource.metadata_options

  # If no http_tokens field, flag it
  not util_functions.has_key(metadata, "http_tokens")

  msg := sprintf("Instance metadata version 2 not enabled for resource `aws_instance.%s`. Add a `metadata_options` block with `http_tokens` set to `required`.", [resource_name])
}

violation[{"policyId": policyID, "msg": msg}] {
  resource := input.resource.aws_instance
  aws_resource := resource[resource_name]

  # Check for metadata_options
  not util_functions.has_key(aws_resource, "metadata_options")

  msg := sprintf("Instance metadata version 2 not enabled for resource `aws_instance.%s`. Add a `metadata_options` block with `http_tokens` set to `required`.", [resource_name])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/terraform/imdsv2_required/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/terraform/imdsv2_required/src.rego)_

## AWSSEC-0003: RDS Instances May Not Be Public

**Severity:** Violation

**Resources:** Any Resource

RDS instances must block public access.
The `publicly_accessible` attribute, if defined, must be set to `false`.
The attribute is `false` by default if not specified.

See <https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#publicly_accessible>.

### Rego

```rego
package terraform_no_public_rds

import data.util_functions

policyID := "AWSSEC-0003"

has_public_attribute(resource) {
  util_functions.has_key(resource, "publicly_accessible")
}

violation[{"policyId": policyID, "msg": msg}] {
  resource := input.resource.aws_db_instance
  a_resource := resource[name]
  has_public_attribute(a_resource)
  a_resource.publicly_accessible != false

  msg := sprintf("RDS instances must not be publicly exposed. Set `publicly_accessible` to `false` on aws_db_instance.`%s`", [name])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/terraform/no_public_rds/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/terraform/no_public_rds/src.rego)_

## CTNRSEC-0001: Dockerfiles Must Pull From An Approved Private Registry

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

  not util_functions.item_startswith_in_list(val[0], approved_private_registries)
  msg := sprintf("Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` does not pull from an approved private registry. The following are approved registries: `%v`.", [val[0], approved_private_registries])
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

  not util_functions.item_startswith_in_list(imageInArg, approved_private_registries)
  msg := sprintf("Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` in variable `%s` does not pull from an approved private registry. The following are approved registries: `%v`.", [imageInArg, argNameAndValue[0], approved_private_registries])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/docker/deny_image_unless_from_registry/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/docker/deny_image_unless_from_registry/src.rego)_

## CTNRSEC-0002: Dockerfiles Should Not Use Environment Variables For Sensitive Values

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

## PKGSEC-0001: NodeJS Packages Must Be Published Under An Organization Scope

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
import data.packages_functions
import data.util_functions

policyID := "PKGSEC-0001"

has_org_scope(name) {
  startswith(name, "@")
}

violation[{"policyId": policyID, "msg": msg}] {
  packages_functions.is_package_json(input)
  package_name := input.name
  not has_org_scope(package_name)
  msg := sprintf("NodeJS packages must be wrapped beneath an organization scope (e.g. `@orgscope/mypackage`). `%s` does not use any organization scope. Approved scopes are: `%v`.", [package_name, approved_org_scopes])
}

violation[{"policyId": policyID, "msg": msg}] {
  packages_functions.is_package_json(input)
  package_name := input.name
  has_org_scope(package_name)
  org_name := substring(package_name, 1, -1)
  not util_functions.item_startswith_in_list(org_name, approved_org_scopes)
  msg := sprintf("NodeJS packages must be wrapped beneath an organization scope (e.g. `@orgscope/mypackage`). `%s` does not use an approved organization scope. Approved scopes are: `%v`.", [package_name, approved_org_scopes])
}
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/packages/nodejs_package_must_use_org_scope/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/packages/nodejs_package_must_use_org_scope/src.rego)_

## PKGSEC-0002: NodeJS Projects Must Use A Recent NodeJS Version

**Severity:** Violation

**Resources:** Any Resource

NodeJS projects must use a recent NodeJS release.
Only 1 LTS version is active at one time, however we allow 1 previous LTS version to be used to
accomodate upgrade migration periods.

You may use a non-LTS "current" NodeJS release as long as that version is more current than the most recently
deprecated LTS release.
For example, if the LTS version is 16 (meaning version 14 was the most recently deprecated LTS version),
you may use NodeJS 14, 15, 16, or 17.
Once NodeJS 18 is released as an LTS version, you may use versions 16, 17, 18, or 19.

See <https://nodejs.org/en/about/releases/> for more information about Node's release schedule.

See <https://docs.npmjs.com/cli/v7/configuring-npm/package-json#engines> for more information about the `engines`
field in `package.json` files.

| :memo: This policy is "online" in that it makes an HTTP request to raw.githubusercontent.com and requires connectivity to receive a response. |
| --- |

### Rego

```rego
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
```

_source: [https://github.com/RallyHealth/conftest-policy-packs/policies/packages/nodejs_must_use_recent_version/src.rego](https://github.com/RallyHealth/conftest-policy-packs/policies/packages/nodejs_must_use_recent_version/src.rego)_
