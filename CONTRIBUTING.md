# Contributing

<!-- toc -->
- [Local Setup](#local-setup)
  - [IDE Plugin](#ide-plugin)
  - [Commits](#commits)
- [Adding Rego Policies](#adding-rego-policies)
  - [Writing Policies](#writing-policies)
    - [Policy Documentation](#policy-documentation)
    - [Policy ID](#policy-id)
- [Testing Policies](#testing-policies)
- [Troubleshooting Policies](#troubleshooting-policies)
<!-- /toc -->

### Languages

*Open Policy Agent*

# Local Setup

[Install Homebrew](https://brew.sh/) on OSX or Linux.

Run `make install`.

We use [konstraint](https://github.com/plexsystems/konstraint) to generate Rego policy documentation and [mdtoc](https://github.com/kubernetes-sigs/mdtoc) to
generate markdown table-of-contents.

## IDE Plugin

We recommend the [official Open Policy Agent](https://plugins.jetbrains.com/plugin/14865-open-policy-agent) plugin
for Jetbrains IDEs.

We recommend [tsandall.opa](https://marketplace.visualstudio.com/items?itemName=tsandall.opa) for Visual Studio Code.

## Commits

This project follows [semantic commit messages](https://karma-runner.github.io/latest/dev/git-commit-msg.html).

Format of a commit message:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Example commit messages:

```
feat: Add npm org scope policy
docs: Generate policy docs from new konstraint version
```

Message subject (first line):

The first line cannot be more than 70 characters.
The second line is always blank and the other lines should be wrapped at 80 characters.
The type and scope should always be in lowercase.

Allowed `<type>` values:

- `feat` - new feature for the user, e.g. new Rego policy. Not a new feature for a build script
- `fix` - bug fix for the user, e.g. fixing an issue in a Rego policy. Not a fix to a build script
- `docs` - Changes to the documentation
- `style` - Formatting, etc
- `refactor` - Refactoring Rego code
- `test` - Add missing tests, refactor existing tests. No policy code changes
- `chore` - Update build scripts or Actions workflow. No policy code changes

The `<scope>` is optional, and if not present the parentheses are omitted.

Message body:

Use the present tense.
Include the motivation for the change and any contrasts with existing behavior.

Message footer:

If relevant, reference related issues in the footer.
Closed issues should be listed on a separate line prefixed with a `Closes:` keyword:

```
Closes #123
```

Or, in the case of multiple issues:

```
Closes #123, #124, #125
```

**Breaking changes**:

All breaking changes have to be mentioned in the footer with the description of the change, justification, and
migration notes.

Artificial example:

```
BREAKING CHANGE:

`CNTRSEC-0001` did not previously take into account a specific scenario. Accounting for that scenario causes
previously passing cases to now show as violating policy. No migration steps are needed.
```

# Adding Rego Policies

All new policies should be created under `/policies`.
You should create a directory with some short name identifying the policy being created (e.g. `deny_image_unless_from_registry`).
Inside that directory, you should write the policy in a `src.rego` file and add tests in a `src_test.rego` file.

All policies **must** be accompanied by matching tests in `src_test.rego`.
For more information on adding tests, see [Testing Policies](#testing-policies).

## Writing Policies

Bookmark this Rego reference page! <https://www.openpolicyagent.org/docs/latest/policy-reference/>

The [Rego Playground](https://play.openpolicyagent.org/) is another useful tool to write Rego policies.

For education on how to write Rego, see this excellent [free Rego course](https://academy.styra.com/courses/opa-rego) from [Styra](https://www.styra.com/).

Policies should represent a discrete requirement applied to a discrete resource or asset type, such as "Dockerfiles Must Pull From An Approved Private Registry"
or "EC2 Instances Must Use Instance Metadata Service Version 2."
Avoid combining different requirements into a single policy.
At the same time, avoid creating policies that are hyper-specific, such as policies that apply only to a single instance
of a resource or asset.
Exceptions may be used to exempt special cases from a policy.

Conftest differs slightly from generic OPA in that each Rego policy **must** begin with `deny`, `violation`, or `warn`.
`deny` and `msg` take a `msg` parameter. `violation` may take an arbitrary object.
We require the use of `violation` or `warn` to generate documentation from policies with [konstraint](https://github.com/plexsystems/konstraint).

`violation` policies must use the parameters `policyId` and `msg`, e.g. `violation[{ "policyId": policyID, "msg": msg }]`.

Any input outside of the `msg` field will be available under a `metadata` key with JSON output from conftest (via `--output json`).

![Conftest test with metadata](/docs/images/conftest-violation-output-json.png)

`warn` policies can only use `msg`, e.g. `warn[msg]`.
In this case, the `msg` must begin with the policy ID, e.g. `msg := sprintf("%s: ...", [policyID])`.

All policies should have a unique `package` name describing their purpose, e.g. `package docker_pull_from_registry`.

All policy packages must have a `policyID` variable.
This variable is interpolated into the policy message given to developers but is also used by Konstraint to attach
the ID to the policy title in the auto-generated documentation.
See the [Policy ID](#policy-id) section below for guidance on selecting or creating a `policyID`.

### Policy Documentation

Each policy must have Konstraint documentation above the `package` declaration.

![Policy documentation](/docs/images/konstraint-docs.png)

The format is as follows:

```markdown
# @title <The Title Of The Capitalized Policy>
#
# <One or more paragraphs describing what this policy is and where developers can get further information>
```

You can enter markdown syntax in the policy documentation and it will render in the [generated markdown file](/docs/policies.md).

### Policy ID

`policyID` enables us to uniquely identify policies, reference policies in code, and tie Conftest policies to organizational
requirements and standards documented elsewhere.

Generally, increment the latest published number for a particular identifier (e.g. `AWSSEC-`) when creating a new policy
against similar resources.

If you need to create a new unique identifier, file an issue against the repository to get approval from a current
maintainer. For example, to target internal org packages like NodeJS or Python packages, request the new identifier `PKGSEC-`
and receive approval from a maintainer to associate that identifier with this group of resources moving forward.

# Testing Policies

All `src.rego` files must be accompanied by `src_test.rego` files.
The `src_test.rego` file must minimally include one "failure" case that triggers the Rego policy and one "good" case
that passes the policy.
Each test case must begin with `test_`, e.g. `test_pull_registry{...}`.

A good way of generating mock input for test cases is to create a file, such as a Dockerfile, with the content you
expect to create a policy against, such as a `FROM notApprovedRegistry/ubuntu:latest` line.
Then run `conftest parse <file>` to convert the file into the JSON representation a policy will receive as `input`.
You can use this JSON as the input for the test cases.

# Troubleshooting Policies

If you need to debug a policy's internal behavior, run `conftest` locally with the `--trace` flag.
It is typically easiest to append the `--trace` flag to the `make test` command in the Makefile during troubleshooting
sessions.
You should then use Rego's `trace(string)` function and pass in a `sprintf()` containing local variables.

For example:

```rego
violation[{"policyId": policyID, "msg": msg}] {
	input[i].Cmd == "from"
	val := input[i].Value
	not docker_utils.is_a_variable(val)
	not docker_utils.is_a_multistage_build(input, val[0])
	not docker_utils.from_scratch(val[0])

	not util_functions.item_startswith_in_list(val[0], approved_private_registries)
	msg := sprintf("Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` does not pull from an approved private registry. The following are approved registries: `%v`.", [val, approved_private_registries])
	trace(msg)
}
```

Invoke conftest with `--trace` and look for lines beginning with `Note`.
To focus on your trace output, pipe the output to grep:

```bash
conftest test --data data --policy policies --trace | grep Note
```

![Debugging policies with trace](/docs/images/debugging-policies-trace.png)

From this trace, we see that the `val` variable is being interpolated with array syntax (` The image `[\"ghcr.io/ubuntu:20.04\"]` ...`).
This looks ugly.
We want the input to be the string value inside `val`.
By using `trace`, we identify the problem and replace `val` with `val[0]` in the `sprintf` function.

```rego
msg := sprintf("Dockerfiles must pull images from an approved private registry (`FROM my.private.registry/...`). The image `%s` does not pull from an approved private registry. The following are approved registries: `%v`.", [val[0], approved_private_registries])
```

Now the policy evaluates as expected.
