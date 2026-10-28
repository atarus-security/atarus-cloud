# Security policy

## Reporting a vulnerability

Please report security issues in atarus-cloud privately by email to info@atarussecurity.com. Do not open a public GitHub issue for a vulnerability.

Include:

- the version or commit you tested
- steps to reproduce, and a proof of concept if you have one
- the impact you expect

We aim to acknowledge reports within 5 business days and to agree a fix and disclosure date with you. We are happy to credit reporters who want credit.

## Supported versions

Only the latest release on the default branch receives security fixes.

## Scope

In scope: the code in this repository, the reports it generates and the remediation script it writes.

Out of scope: the cloud SDKs and CLIs this project calls (boto3, the Azure SDK, the `az` command), and findings that require an attacker who already controls the machine running the tool or the credentials it is given.

## Using this tool

atarus-cloud is read-only against the cloud account it is pointed at: every API call it makes is a describe, get or list call, made with the credentials already on your machine (the AWS credential chain, or the Azure CLI login). It writes files only to the output directory you choose. The remediation script is written only with `--remediation-script`; every command in it is commented out, every value is shell-quoted and the file is created with mode 0644, so nothing runs until a person reads a line and removes its comment marker. Only review accounts you own or are authorized in writing to assess, and only run remediation commands against accounts you are authorized to change.

Treat as a security bug and report it: any API call that creates, modifies or deletes a cloud resource; a report or console summary that shows a score, a "no findings" or a "no failed controls" message for an account where a check did not run (every check that does not run must appear in the coverage table with a reason); a remediation script that is executable, contains a live (uncommented) command, or places a resource name into a command unquoted so that it could be interpreted by the shell; a resource name that can inject terminal markup or break out of the generated HTML, JSON or script; any credential, token or secret value written to a report or log; and any network destination not listed in the README's network table.
