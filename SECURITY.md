# Security policy

fleet-mcp holds Fleet Manager credentials, can change Fleet Manager configuration, and can run commands on Fleet Manager hosts and sensors over SSH. Please report security problems privately.

## Reporting a vulnerability

Use GitHub's private reporting: on the repository's **Security** tab, choose **Report a vulnerability**. Please do not open a public issue or pull request for a security problem.

Include:
- the fleet-mcp version (`fleet-mcp version`) and your operating system;
- the Fleet Manager version, if it matters;
- what you did, what happened, and what you expected.

Never include real passwords, tokens, community strings, certificates or keys. Replace them with placeholders.

fleet-mcp is community supported, and Corelight does not support it. Reports are handled on a best-effort basis, and fixes go into the next release. Only the latest release is supported.

## Scope

In scope: fleet-mcp's own code, its release binaries and its release workflow. Examples: a secret appearing in a tool result or log, a change running without a valid confirm token, or a command injection through tool arguments.

Out of scope: vulnerabilities in Corelight Fleet Manager or Corelight sensors. Report those to Corelight.
