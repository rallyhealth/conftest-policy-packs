# Policy Exceptions

We have opted to handle exceptions in the code surrounding Conftest execution, although as JSON files you may opt to modify your Rego to accomodate them.

Our ECS task runs Conftest with the policies in this repo and records violations by file per repo. It then compares the listed violations to a map constructed from these policy exceptions.
If a match is found, that violation is excluded from the results published as a GitHub status check for developers.
It is recorded as an exempted violation in the Datadog dashboard providing the holistic landscape for the Appsec team.

Given that framework, exceptions are organized by repository in our organization.
Per repo, exceptions are granted on a file level.
We did not have a need to go more granular, and producing more granular exceptions requires more complexity in the custom code surrounding the Conftest evaluation.
Please open source your exception frameworks to share with the community if you follow a different approach.

An exemption is granted for specific `policyID`s as documented in our [policies](/).
As we handle exceptions with our custom logic, we also support a catch-all `ALL` exception that can be applied to a file in a repo or for the entire repo.
An example is provided in `rally-conftest-policies.json`.
A more realistic example of our exceptions can be found in `other-repo.json`.

Exceptions must be approved by Security, in the form of a Jira ticket.
To grant an exception, a dev team files a Jira ticket with a brief justification and opens a PR in this repo to add the specific policy excemption to their repo.
Once that exception is approved the Appsec team merges the PR and the next commit anywhere in the organization will pick up the latest changes.
