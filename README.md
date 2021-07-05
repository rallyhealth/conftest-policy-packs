# Conftest Policy Packs

Centralized OPA policy workflow for Conftest-based Compliance-as-Code evaluations at CI-speed.

This is a central repository housing a snapshot of Rally's Rego policies for Compliance-as-Code.
They are enforced by a homegrown GitHub App running on AWS ECS to evaluate every commit in the organization in under 30 seconds.

# Usage

## Policy Data

These policies are provided for general consumption.
Policy contents are written to be general purpose and org-specific values are relegated to conftest `--data` in the `data/` directory.
You should pull the policies with `conftest pull` and specify your own data files as appropriate for your organization.

# Policy Organization and Management

See <the GitHub pages site once it is created.>

# Why share this?

TBA

# Contributing

This project uses [semantic commit messages](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716).

## Quick Start

[Install Homebrew](https://brew.sh/) on OSX or Linux.

```bash
make install
```

Follow the [contribution instructions](/) [TBA].
