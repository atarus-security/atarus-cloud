# atarus-cloud

Read-only cloud configuration review for AWS and Azure by [Atarus Offensive Security](https://atarussecurity.com).

Sixteen modules of describe, get and list calls against the account you point it at, written up the way a pentest report would put them: observation, risk, recommendation and the CLI command that fixes it. Attack path correlation, an executive summary, CIS and NIST mapping, and a coverage table that says exactly which checks ran in which regions and which did not.

## Install

Python 3.10 or newer.

```bash
git clone https://github.com/atarus-security/atarus-cloud.git
cd atarus-cloud
python3 -m venv venv
source venv/bin/activate

pip install -e .              # AWS reviews, HTML and JSON reports
pip install -e ".[azure]"     # add the Azure provider (the Azure SDK)
pip install -e ".[pdf]"       # add PDF export (WeasyPrint)
pip install -e ".[all]"       # both extras
```

PDF export also needs the Pango system libraries. On Debian or Kali: `sudo apt install libpango-1.0-0 libpangoft2-1.0-0`. HTML and JSON reports never need them.

`atarus-cloud --version` and `atarus-cloud --list-modules` work with no credentials and no extras. `-p azure` without the Azure extra, and `--format pdf` without the PDF extra, stop with a one-line message naming the install command.

## Quick start

```bash
# AWS: every module, every enabled region, HTML and JSON reports
aws configure                      # or any other way of setting the AWS credential chain
atarus-cloud -p aws --format all

# Azure: the default subscription of your az login
az login
atarus-cloud -p azure --format all
```

A run writes to `./output` (change it with `-o`):

- `atarus-cloud-<account-id>.html`: tabbed report with overview, executive summary, attack paths, findings, compliance, coverage and remediation
- `atarus-cloud-<account-id>.json`: the same data, machine readable
- `atarus-cloud-<account-id>.pdf`: with `--format pdf` or `all`, when the PDF extra is installed
- `remediation-<account-id>.sh`: only with `--remediation-script`; see below

With no credentials the tool stops with a one-line message, for example `No AWS credentials found. atarus-cloud reads the standard AWS credential chain ...`. There is no traceback.

## What the output says and does not say

### Coverage table

Every check the tool intends to make is recorded, per service and per region, as **checked** or **not run** with the reason. The console prints the table at the end of every run, the HTML report has a Coverage tab, and the JSON report has a `coverage` array with one entry per check.

```
                                  Coverage
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Service               ┃ Region     ┃ Status  ┃ Detail                    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ IAM                   │ global     │ checked │ 6 checks                  │
│ S3                    │ global     │ checked │ 4 checks                  │
│ EC2                   │ us-west-1  │ checked │ 3 checks                  │
│ EC2                   │ eu-west-1  │ partial │ 1 of 3 checks did not run │
│ ...                   │            │         │                           │
│ all regional services │ ap-south-1 │ not run │ not in the --region list  │
└───────────────────────┴────────────┴─────────┴───────────────────────────┘
Checks not run (2):
  - all regional services / ap-south-1: not in the --region list
  - EC2 / eu-west-1 / security groups open to the internet: ClientError: An error occurred
    (UnauthorizedOperation) when calling the DescribeSecurityGroups operation: ...
```

Reasons you will see: an API error (usually a missing permission), `skipped with --skip`, `not listed in --only`, `not in the --region list`, `could not list enabled regions`, `module crashed`, and `Azure SDK package not installed`. A check that fails for one resource (one bucket, one key, one vault) gets its own line, and the check's summary line says how many resources it did cover.

### Score only on full coverage

If every check ran in every selected region, the report carries a score out of 100 and the usual wording. If even one check did not run, there is no score: the console, the report and the JSON say **partial coverage, no score (n of m checks did not run)**, the executive summary says the assessment did not complete, the findings tab says that no findings among the checks that ran is not a clean result, and the compliance tab says that controls with no finding are not passes. A service with zero findings is a clean service only when its checks are all marked checked. Coverage is self reported by each module, so the runner adds one guard: a module that returns success without recording a single check is itself recorded as not run, with the reason "module reported no coverage", and the score is withheld as for any other not-run line.

### Regions

AWS by default: the tool lists the regions enabled for the account (`ec2:DescribeRegions`) and runs the regional modules (EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager) in each of them. IAM and S3 are global and run once. `--region` limits the run; it may be repeated or comma separated (`--region us-east-1,eu-west-1`). Enabled regions you leave out are listed as not checked and the score is withheld. If the region listing itself fails, the run uses the session's own region and records every other region as not checked.

CloudTrail is judged per region: a region with no trail covering it is a finding. Per-trail settings (multi-region, log file validation, logging status) are checked in the trail's home region only, so one multi-region trail is reported once.

Azure modules list resources across the whole subscription in one call each; the region column reads `subscription`.

### Remediation script

Written only when you pass `--remediation-script`. Every command in it is commented out, every resource value is shell-quoted, the file is created with mode 0644 and is never executable, and the header says REVIEW BEFORE RUNNING. Read each command, check the resource and the change against your own environment, replace any placeholder (`<RG>`, `YOUR-LOG-BUCKET`, `<NEW_RUNTIME>`), and remove the leading `# ` from the lines you approve. The same quoted commands appear in the report's Remediation tab. The tool itself never changes a cloud resource.

## Modules

| Provider | Key | Service | Scope | What it checks |
|---|---|---|---|---|
| AWS | iam | IAM | global | Root MFA, console users without MFA, access key age and inactive keys, password policy, directly attached AdministratorAccess, console users unused for 90 days |
| AWS | s3 | S3 | global | Public access block, default encryption, versioning, access logging |
| AWS | ec2 | EC2 | per region | Security groups open to the internet, instances with public IPs, EBS encryption by default |
| AWS | cloudtrail | CloudTrail | per region | A trail covering the region; for trails homed there: multi-region, log file validation, logging status |
| AWS | rds | RDS | per region | Public accessibility, storage encryption, auto minor version upgrade, backup retention |
| AWS | vpc | VPC | per region | Default VPC in use, VPC flow logs |
| AWS | lambda | Lambda | per region | Environment variables that look like secrets, deprecated runtimes, resource policy open to any principal |
| AWS | kms | KMS | per region | Customer-managed keys: automatic rotation, key policy open to any principal |
| AWS | secrets | Secrets Manager | per region | Automatic rotation, age since last rotation or change, resource policy open to any principal, scheduled deletion |
| Azure | identity | Identity | subscription | Owner assignments at subscription scope, direct user Owner assignments, custom roles with wildcard actions |
| Azure | storage | Storage | subscription | Secure transfer, minimum TLS, network default action, account-level blob public access, blob encryption, public containers |
| Azure | network | Network | subscription | NSG inbound rules open to the internet, allocated public IPs |
| Azure | compute | Compute | subscription | OS disk encryption settings, managed disks, boot diagnostics |
| Azure | keyvault | Key Vault | subscription | Soft delete, purge protection, network default action, RBAC permission model |
| Azure | sql | SQL | subscription | Public network access, firewall rules, minimum TLS, Entra ID administrator, auditing |
| Azure | cosmosdb | Cosmos DB | subscription | Public network access without restrictions, 0.0.0.0 firewall rule, local key-based authentication, automatic failover |

Every module can be left out with `--skip` or selected with `--only`; the modules that do not run are recorded as not run.

## AWS module reference

### iam (global)

**Checks**: root account MFA (critical if disabled); console users without an MFA device (high); access keys older than 90 days (medium) and inactive access keys (low); password policy, flagged when missing (high), shorter than 14 characters or without all four character classes (medium); users with `AdministratorAccess` attached directly (medium); console users whose password was last used more than 90 days ago (low).

**API calls**: `iam:ListUsers`, `iam:GetAccountSummary`, `iam:ListMFADevices`, `iam:GetLoginProfile`, `iam:ListAccessKeys`, `iam:GetAccountPasswordPolicy`, `iam:ListAttachedUserPolicies`. If `ListUsers` fails the whole module is recorded as not run.

**Compliance**: CIS AWS 1.5, 1.8, 1.10, 1.12, 1.14, 1.16.

### s3 (global)

**Checks**: public access block missing or not fully enabled (high); no default encryption (medium); versioning off (low); server access logging off (low).

**API calls**: `s3:ListAllMyBuckets`, then per bucket `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`. Any error other than the "no configuration" codes the checks expect is a not-run line for that bucket.

**Compliance**: CIS AWS 2.1.1, 2.1.3, 2.1.4, 2.1.5.

**Notes**: bucket ACLs and bucket policies are not read; a bucket can be public through either and this module does not say so. The bucket calls use the base session's region; see Known issues.

### ec2 (per region)

**Checks**: security group rules from `0.0.0.0/0` to all ports (critical) or to 22, 3389 (critical), 3306, 5432, 1433, 27017, 6379, 11211, 23, 21 or 445 (high); the same ports from `::/0` (high); running instances with a public IPv4 address (medium); EBS encryption by default off in the region (medium).

**API calls**: `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`, `ec2:GetEbsEncryptionByDefault`.

**Compliance**: CIS AWS 5.2, 2.2.1.

**Notes**: a rule is matched on its `FromPort`; a port range that merely spans an admin port is not flagged. Individual EBS volumes are not examined.

### cloudtrail (per region)

**Checks**: no trail covers the region, own or multi-region shadow (critical); for trails homed in the region: not multi-region (high), log file validation off (medium), logging stopped (critical).

**API calls**: `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`.

**Compliance**: CIS AWS 3.1, 3.2.

### rds (per region)

**Checks**: publicly accessible (critical); storage not encrypted (high); auto minor version upgrade off (medium); backup retention under 7 days (low).

**API calls**: `rds:DescribeDBInstances` (paginated).

**Compliance**: CIS AWS 2.3.1.

### vpc (per region)

**Checks**: default VPC with network interfaces attached (medium) or empty (low); VPCs without flow logs (medium).

**API calls**: `ec2:DescribeVpcs`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeFlowLogs`.

**Compliance**: CIS AWS 3.9, 5.3.

### lambda (per region)

**Checks**: environment variable names that look like secrets (high) and values matching secret patterns such as `AKIA...` or `password=` (critical); deprecated runtimes (medium); resource policy allowing any principal (critical).

**API calls**: `lambda:ListFunctions` (paginated; the function configuration including environment variables comes back in the listing), `lambda:GetPolicy`.

**Notes**: secret detection is pattern matching and will flag test values; the report never stores the variable's value, only its name.

### kms (per region)

**Checks**: customer-managed, enabled keys without automatic rotation (medium); default key policy with an `Allow` for any principal and no condition (critical).

**API calls**: `kms:ListKeys` (paginated), `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`.

**Compliance**: CIS AWS 2.8.

### secrets (per region)

**Checks**: automatic rotation off (medium); last rotated or changed more than 180 days ago (medium) or more than 365 (high); resource policy allowing any principal without a condition (critical); scheduled for deletion (low).

**API calls**: `secretsmanager:ListSecrets` (paginated), `secretsmanager:GetResourcePolicy`. Secret values are never read.

## Azure module reference

Every Azure module needs the Reader role on the subscription and lists resources subscription-wide.

### identity

**Checks**: more than three Owner assignments at subscription scope (high); user principals with a direct Owner assignment (medium); custom roles granting `*` actions (high). If the role definitions cannot be listed, all three checks are recorded as not run rather than silently passing.

**Compliance**: CIS Azure 1.22, 1.23.

### storage

**Checks**: secure transfer not required (high); minimum TLS below 1.2 (medium); public network access with default action Allow (high); blob public access allowed at account level (medium); blob encryption disabled (high); containers with anonymous public access (critical).

**Compliance**: CIS Azure 3.1, 3.2, 3.6, 3.7, 3.15.

### network

**Checks**: NSG inbound Allow rules from `*`, `Internet` or `0.0.0.0/0` to all ports (critical) or to the admin and database ports listed under ec2 (critical for 22 and 3389, high otherwise); every allocated public IP address (low, informational).

**Compliance**: CIS Azure 6.1 (RDP), 6.2 (SSH).

### compute

**Checks**: OS disk without Azure Disk Encryption settings (medium); unmanaged disks (medium); boot diagnostics off (low).

**Compliance**: CIS Azure 7.2, 7.3.

### keyvault

**Checks**: soft delete off (high); purge protection off (medium); public network access with default action Allow (high); access-policy permission model instead of RBAC (low).

**Compliance**: CIS Azure 8.1, 8.2, 8.5.

### sql

**Checks**: public network access enabled (high); firewall rule `0.0.0.0` to `255.255.255.255` (critical); `AllowAllWindowsAzureIps` or a `0.0.0.0` to `0.0.0.0` rule (medium); minimal TLS below 1.2 (medium); no Entra ID administrator (medium); auditing not enabled (high).

**Compliance**: CIS Azure 4.1.1 to 4.1.6.

### cosmosdb

**Checks**: public network access with no IP or VNet rules (high); `0.0.0.0` IP rule (medium); local key-based authentication enabled (medium); automatic failover off (low).

**Compliance**: CIS Azure 4.5.1.

## Usage

```bash
atarus-cloud -p aws                                  # every enabled region, HTML report
atarus-cloud -p aws --format all                     # HTML, JSON and (with the extra) PDF
atarus-cloud -p aws --profile production             # a named AWS profile
atarus-cloud -p aws --region us-east-1,eu-west-1     # two regions; the rest listed as not checked
atarus-cloud -p aws --remediation-script             # also write the commented-out script
atarus-cloud -p azure --subscription <SUBSCRIPTION_ID>
atarus-cloud -p aws --skip rds,vpc                   # recorded as not run
atarus-cloud -p azure --only storage,identity        # the rest recorded as not run
atarus-cloud --list-modules
atarus-cloud --version
```

### Authentication

**AWS**: the standard credential chain (`aws configure` profiles, environment variables, an instance or container role). Nothing is read from arguments. One `sts:GetCallerIdentity` call confirms the identity before anything else runs.

**Azure**: the Azure CLI login. Run `az login` first. The tool uses the default enabled subscription unless `--subscription` is given.

### Required permissions

Read-only in both clouds. **AWS**: the AWS-managed `SecurityAudit` policy covers everything; the module reference lists the exact calls. The tool also calls `sts:GetCallerIdentity`, `iam:ListAccountAliases` and `ec2:DescribeRegions`. **Azure**: Reader on the subscription.

### What this tool sends over the network

| Component | Destination | What is sent | When |
|---|---|---|---|
| AWS authentication | the STS endpoint of your default region | one `GetCallerIdentity` request using the credentials boto3 finds locally | every AWS run |
| AWS account alias and regions | IAM (global) and EC2 in your default region | `ListAccountAliases`, `DescribeRegions` | every AWS run |
| iam, s3 | the IAM and S3 global endpoints | the describe, get and list calls named in the module reference | every AWS run unless skipped |
| ec2, cloudtrail, rds, vpc, lambda, kms, secrets | the service endpoint in each selected region | the describe, get and list calls named in the module reference, once per region | every AWS run unless skipped |
| boto3 credential chain | the EC2 instance metadata service (169.254.169.254) or the ECS or EKS credential endpoint | a credential request, only when no static credentials or profile are configured and you are running on AWS compute | boto3's own behaviour |
| Azure authentication | the local `az` command, which talks to `login.microsoftonline.com` | `az account get-access-token` for the management scope, run by `AzureCliCredential`; `az account show --subscription <id>` when the subscription listing has no tenant id | every Azure run |
| Azure modules | `management.azure.com` | subscription, role, storage, network, compute, key vault, SQL and Cosmos DB list and get calls | every Azure run unless skipped |
| Reports | nothing | files are written to `--output` only | |

No third-party service is contacted. There are no update checks, no telemetry and no outbound calls other than the cloud APIs above. The remediation script is a file; the tool never executes it.

### Known issues

- S3 bucket calls (`GetBucketPublicAccessBlock` and the others) are made with the base session's region. boto3 follows most S3 region redirects, but a call for a bucket in another region can still fail; when it does, the bucket appears as a not-run line rather than a finding or a silent pass.
- A region named with `--region` that is not enabled for the account is attempted anyway and will fail with an API error recorded in the coverage table.
- Compliance mapping covers only the controls listed in `analysis/compliance.py`; "controls failed" is a count over those, not a CIS or NIST assessment.
- A full default run makes nine modules' worth of calls in every enabled region; on an account with many regions this takes minutes.

## Reports

### HTML

Tabbed dark-themed report: Overview (score or "Partial", counts, regions, coverage summary), Executive Summary, Attack Paths, Findings (observation, risk, recommendation, quoted command, effort, controls), Compliance, Coverage (per service and region, every check that did not run with its reason, and the full check list) and Remediation.

### JSON

Everything in the HTML report plus `coverage` (one object per check: module, service, region, check, status, detail), `coverage_status`, `checks_total`, `checks_not_run`, `regions`, `regions_not_checked`, `overall_score` (`null` when partial) and `score_note`.

### PDF

The HTML report rendered by WeasyPrint, with page numbers and footer. Needs the `[pdf]` extra and the Pango libraries.

## Compliance frameworks

- CIS AWS Foundations Benchmark 2.0 (18 controls mapped)
- CIS Azure Foundations Benchmark 2.0 (21 controls mapped)
- NIST 800-53 Rev 5 (14 controls mapped, shared across AWS and Azure)

The Compliance tab shows the mapped controls that have a failing finding. A mapped control with no failing finding is not shown as passed, and when coverage is partial the tab says so.

## Adding a module

```python
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.providers.aws.common import q, region_of
from atarus_cloud.runner import ModuleResult

def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    cov = result.recorder("yourmodule", "YourService", region_of(session))
    client = session.client("yourservice")
    try:
        things = client.list_things()["Things"]
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list things: {e}")  # recorded as not run
    for t in things:
        if t["Open"]:
            result.add_finding(CloudFinding(service="YourService", resource_id=t["Id"], resource_name=t["Name"],
                                            severity="high", observation="...", risk="...", recommendation="...",
                                            remediation_cmd=f"aws yourservice close-thing --id {q(t['Id'])}"))
    cov.checked("open things", f"{len(things)} things")
    return ModuleResult(success=True, message=f"Checked {len(things)} things")
```

Register it in `cli.py` with its service label and scope (`SCOPE_GLOBAL` or `SCOPE_REGIONAL`). Rules: every check records `checked` or `not_run`, never a silent `except` (a module that records nothing is listed as not run by the runner); every value that goes into `remediation_cmd` passes through `q()` (`shlex.quote`); the module makes only read calls. `session` is a boto3 `Session` bound to one region for AWS, or for Azure a dict with `credential`, `subscription_id` and `tenant_id`.

## Testing

```bash
python -m unittest discover -s tests -v
```

Offline. Every SDK client is faked and the socket layer is guarded so no test can reach a cloud API. GitHub Actions runs the suite on a base install (no Azure SDK, no WeasyPrint) across Python 3.10 to 3.13, and once more with `.[all]` pinned to `constraints.txt`.

## Part of the atarus- tool suite

- **[atarus-recon](https://github.com/atarus-security/atarus-recon)**: external attack surface recon
- **atarus-cloud**: cloud configuration review (you are here)
- **[atarus-phishcheck](https://github.com/atarus-security/atarus-phishcheck)**: email security analyzer
- **[atarus-report-kit](https://github.com/atarus-security/atarus-report-kit)**: pentest report builder for juniors and students
- **[atarus-webscan](https://github.com/atarus-security/atarus-webscan)**: web application security scanner

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability and for what counts as one in this tool.

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)
