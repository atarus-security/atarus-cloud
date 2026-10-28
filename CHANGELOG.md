# Changelog

All notable changes to atarus-cloud. Dates are commit dates. Only v1.0.0 was tagged and published as a GitHub release; earlier versions were development builds on the same day.

## 1.1.0 (unreleased, refresh-2026-10)

### Security

- **A module that reports success without recording a single check is recorded as not run.**

  What was wrong: coverage is self reported. Each module calls `cov.checked` or `cov.not_run` for the checks it makes, and the runner trusted a `success=True` return on its own. A module that returned success without recording anything (a code path that skipped its checks, a future module that forgets to record, a region where a module quietly looked at nothing) counted as complete, the coverage table showed no line for it, and the score was computed as if the service had been reviewed.

  What changed: `CloudRunner` compares the coverage table before and after each module call. If a module returns success and the table did not grow, the runner records a not-run line for that module and region with the reason "module reported no coverage", prints "not run" instead of "done", and the score is withheld as for any other not-run line. A module that recorded even one row, checked or not run, is left as it is. Tested with a module that returns success and records nothing, in two regions.

- **Coverage table in every output; no score, "no findings" or "no failed controls" verdict when a check did not run.**

  What was wrong: every check in every module caught its own exceptions and, unless `--verbose` was on, threw them away. An IAM user without `iam:ListUsers`, an EC2 call refused by a permission boundary, or an SDK error of any kind produced zero findings for that check, and zero findings scored as 100 out of 100. The HTML report then said "No findings detected" and "Environment meets CIS and NIST control coverage", and the executive summary called the posture strong. A reader could not tell a clean account from an account the tool had not been allowed to look at. On top of that the AWS run looked at exactly one region (us-west-1 unless `--region` was given), so resources in the other sixteen or more enabled regions were never examined and nothing in the output said so.

  What changed, in plain terms: the tool now keeps a list of every check it meant to make, per service and per region, and marks each one checked or not run with the reason (the error, "skipped with --skip", "not in the --region list", "Azure SDK not installed", and so on). The console prints a Coverage table at the end plus a "Checks not run" list; the HTML report has a Coverage tab and the JSON report a `coverage` array. If even one check did not run, the score is withheld: the console and the report say "partial coverage, no score (n of m checks did not run)", the executive summary says the assessment did not complete, the findings tab says that no findings among the checks that ran is not a clean result, and the compliance tab says that controls with no finding are not passes. The score, and the clean wording, come back only when every check ran in every selected region.

  Technically: `models.AuditResult` gained `coverage` (a list of `CheckRecord(module, service, region, check, status, detail)`), `regions`, `regions_not_checked`, `coverage_status`, `checks_total` and `checks_not_run`; `overall_score` is `Optional[int]` and `finalize()` sets it to `None` unless `coverage_complete` is true. Modules record through `result.recorder(module, service, region)`, which returns a `CoverageRecorder` with `checked(check, detail)` and `not_run(check, reason)`; every former `except Exception: if verbose: print(...)` now calls `not_run` with `describe_error(e)` (exception type plus a 200-character message). Per-resource failures (a bucket, a key, a vault) produce one not-run line each, and the check's summary line says how many resources it did cover. `CloudRunner` records a not-run line for modules left out by `--skip` or `--only`, for a module that raises, for a module that returns `ModuleResult(success=False)`, and for every region listed in `regions_not_checked`. Two silent-pass paths were closed on the way: the S3 per-bucket calls caught `ClientError` and ignored every code except the two they were looking for, so an `AccessDenied` on `GetPublicAccessBlock` or `GetBucketEncryption` was dropped; and the Azure identity module set the role-definition map to empty when the listing failed, after which every assignment was skipped and the module reported success. `exec_summary`, the HTML template (`cloud_report.html`), `json_export` and the console summary all branch on `overall_score is None`.

- **All enabled regions by default; an explicit `--region` list shows the regions it leaves out.**

  What was wrong: `--region` took one value and defaulted to us-west-1, so an AWS review covered one region and the report did not say which or that the others were skipped.

  What changed: with no `--region`, the tool calls `ec2:DescribeRegions` and runs every regional module (EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager) in every region enabled for the account; IAM and S3 run once as global modules. `--region` may be repeated or comma separated; the enabled regions it leaves out are listed under "Regions not checked" in the console, the report and the JSON, and the score is withheld. If the region listing itself fails (for example the identity lacks `ec2:DescribeRegions`), the run falls back to the session's own region and records "all other regions: could not list enabled regions" as not checked. Findings from a regional module carry the region in `CloudFinding.region`. CloudTrail is evaluated per region: a region with no trail (own or multi-region shadow) gets a finding, and per-trail settings are checked in the trail's home region only, so a multi-region trail is reported once rather than once per region. `CloudRunner` now takes `sessions` (region to session) and `global_session`; `register()` takes `service` and `scope` (`SCOPE_GLOBAL` or `SCOPE_REGIONAL`).

- **Remediation script is opt-in, every command commented out, every value quoted, file mode 0644.**

  What was wrong: every run wrote `remediation-<account>.sh` with mode 0755 and `set -e`, and resource names from the cloud account (bucket names, user names, trail names, key vault names, resource groups) were pasted into the commands unquoted. A name containing a space, a semicolon, `$(...)` or a newline would change what the script did, and the README told users the script "actually runs" and to "execute it to resolve the majority of findings". The HTML report showed the same unquoted commands.

  What changed: the script is written only with `--remediation-script`. Every command line is prefixed with `# `, the header says REVIEW BEFORE RUNNING and explains that nothing in the file is live until the reader removes the comment marker, the file is created with mode 0644 and never made executable, and the closing line restates the count of commented commands. Every resource value interpolated into a `remediation_cmd` in the AWS and Azure modules passes through `shlex.quote`, so the quoted form appears both in the script and in the report's Remediation tab; explicit placeholders (`<RG>`, `YOUR-LOG-BUCKET`, `<NEW_RUNTIME>`) are left for the reader to fill in. Observation, resource and effort comments are collapsed to one printable line each, so a value cannot start a new script line. Output file names are built from `file_stem(account_id)`, which keeps only `[A-Za-z0-9._-]`. The console and the HTML report say where the script is and that it is commented out, or that none was written.

- **Resource names are escaped before they reach the terminal.** Console lines that include module messages, check names and reasons pass through `rich.markup.escape`, so a resource named `[bold red]...[/]` cannot restyle the output. The HTML template already autoescapes.

### Fixed

- Fresh installs crashed on every command (including `--version` and AWS-only scans) with `ModuleNotFoundError: No module named 'azure'`: `cli.py` imported all Azure modules, and they imported the Azure SDK at module level, while `pyproject.toml` declared no Azure SDK packages. The Azure SDK is now an optional extra (`pip install 'atarus-cloud[azure]'`) and the Azure modules import the SDK inside a `_client()` function, so the base install imports cleanly. `-p azure` without the extra exits with a usage error naming the missing packages and the install command before any authentication is attempted. A base install (`pip install -e .`) now runs AWS reviews with HTML and JSON reports.
- WeasyPrint is the optional extra `[pdf]` and is imported only for PDF export. `--format pdf` without it exits with a usage error pointing at the extra and the Pango libraries; `--format all` writes HTML and JSON and says PDF was skipped. `.[all]` installs both extras.
- Missing credentials print one line ("No AWS credentials found. atarus-cloud reads the standard AWS credential chain...") instead of a traceback; a missing profile and other botocore errors are reported the same way.
- CIS Azure mapping for open NSG ports: SSH (22) was mapped to CIS Azure 6.1, which is the RDP control, and every other open port to 6.2, the SSH control. SSH now maps to 6.2, RDP to 6.1 and other ports to no CIS Azure control.
- RDS listing is paginated; accounts with more than 100 instances were truncated.
- Version string lives in `atarus_cloud.__version__` and feeds the CLI, the JSON `version` field and the report footer (the template had `v1.0.0` hard-coded).
- HTML template is resolved inside the package only; the stale fallback to a repository-level `templates/` directory is gone.

### Added

- `--region` (repeatable), `--remediation-script` and validation of `--skip` and `--only` module names.
- `tests/test_coverage_and_remediation.py` (35 tests): the socket layer is guarded so no test can reach a cloud API; every SDK client is a fake. Covers the withheld score, per-service and per-region aggregation, the runner's not-run lines for skipped, crashed and failed modules, swallowed-exception paths in IAM, S3, EC2, CloudTrail, KMS and the Azure identity and storage modules, CloudTrail home-region de-duplication, shell quoting of hostile resource names, the script's mode, header and commented commands, the partial wording in HTML and JSON, region selection through the CLI, the `[azure]` and `[pdf]` usage errors, the no-credentials message, and that importing the CLI loads neither the Azure SDK nor WeasyPrint.
- CI: the matrix job installs the base package only and smoke-tests `--version`, `--list-modules` and the `-p azure` usage error; a second job installs `.[all]` against `constraints.txt`.

### Docs

- README: install per extra, the coverage table and the withheld score, region selection, the opt-in remediation script, a "What this tool sends over the network" table, a module reference corrected to the checks the code makes and the permissions it needs (the previous text listed checks that did not exist, such as root access keys, inline `*:*` policies, public bucket ACLs, MFA delete, RDS default user names and Lambda VPC configuration), and Known issues.
- SECURITY.md: what counts as a security bug for this tool.

## Earlier work on refresh-2026-10 (folded into 1.1.0)

- `pyproject.toml` and `requirements.txt` declared the SDKs the code imports; the unused `azure-mgmt-resource` and `azure-mgmt-monitor` were dropped.
- HTML report template moved into the package so non-editable installs can find it.
- Offline unit tests (`tests/test_core.py`), GitHub Actions workflow, `constraints.txt`, SECURITY.md and this changelog.
- README: Pango requirement for PDF, correct description of the module `session` argument, atarus-webscan added to the suite list.

## 1.0.0 (2026-04-19)
- First stable release: 16 modules (AWS IAM, S3, EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager; Azure Identity, Storage, Network, Compute, Key Vault, SQL, Cosmos DB).
- Attack path correlation, executive summary, CIS AWS, CIS Azure and NIST 800-53 mapping, remediation script, HTML, PDF and JSON reports.

## Development builds (2026-04-19)
- 0.1.0 IAM and S3 auditing with remediation scripts; 0.2.1 PDF polish; 0.3.0 Lambda and KMS; 0.4.0 attack paths; 0.5.0 executive summary; 0.7.0 CIS AWS and NIST mapping; 0.8.0 Azure provider; 0.9.0 Azure Key Vault, SQL and Cosmos DB.
