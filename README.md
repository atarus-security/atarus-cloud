# atarus-cloud

Multi-cloud security misconfiguration scanner by [Atarus Offensive Security](https://atarussecurity.com).

Single command. Sixteen modules. Every cloud security check a pentester runs at the start of an engagement, chained into one branded report with attack path correlation, executive summary, and an executable remediation script.

## Quick start

```bash
git clone https://github.com/atarus-security/atarus-cloud.git
cd atarus-cloud
python3 -m venv venv
source venv/bin/activate
pip install -e .

# AWS
aws configure
atarus-cloud -p aws --format all

# Azure
az login
atarus-cloud -p azure --format all
```

That single command produces:

- `atarus-cloud-<account-id>.html` - tabbed report with overview, exec summary, attack paths, findings, compliance, remediation
- `atarus-cloud-<account-id>.pdf` - branded PDF export
- `atarus-cloud-<account-id>.json` - machine-readable output
- `remediation-<account-id>.sh` - executable shell script with every actionable CLI command, ordered by severity

## Why this tool exists

Cloud scanners have been around for years. ScoutSuite dumps 200 findings with no context. Prowler outputs CIS control numbers nobody remembers. Commercial tools charge thousands and produce reports nobody reads.

atarus-cloud was built by pentesters who were tired of delivering audit output pretending to be security work.

**Every finding reads like a pen test report.** Observation of what was found. Risk of what an attacker could do. Recommendation with the exact CLI command to fix it.

**Attack paths chain findings into real scenarios.** Instead of listing "no MFA" and "admin access" separately, the report tells you how an attacker combines them into full account takeover.

**The executive summary auto-generates.** Plain language for the CISO or city manager. Security posture, key risks, recommended actions.

**Compliance mapping is built in.** CIS AWS, CIS Azure, and NIST 800-53 mapped to every finding.

**The remediation script actually runs.** Review it, approve it, execute it. Fix 40 findings with one script instead of clicking through the console.

## Modules

| Provider | Key | Service | What it checks |
|---|---|---|---|
| AWS | iam | IAM | Users, MFA, access keys, password policy, admin access |
| AWS | s3 | S3 | Bucket policies, encryption, versioning, logging, public access |
| AWS | ec2 | EC2 | Security groups, public IPs, EBS encryption |
| AWS | cloudtrail | CloudTrail | Logging gaps, multi-region, log validation |
| AWS | rds | RDS | Public databases, encryption at rest, backup retention |
| AWS | vpc | VPC | Default VPCs, flow logs |
| AWS | lambda | Lambda | Env var secrets, deprecated runtimes, resource policies |
| AWS | kms | KMS | Key rotation, resource policies |
| AWS | secrets | Secrets Manager | Rotation, age, resource policies |
| Azure | identity | Identity | Owner roles, direct assignments, custom roles |
| Azure | storage | Storage | HTTPS, TLS version, public access, blob containers |
| Azure | network | Network | NSG rules, dangerous open ports, public IPs |
| Azure | compute | Compute | Disk encryption, managed disks, boot diagnostics |
| Azure | keyvault | Key Vault | Soft delete, purge protection, network access, RBAC |
| Azure | sql | SQL | Public access, firewall rules, TLS, auditing, Entra admin |
| Azure | cosmosdb | Cosmos DB | Public network access, firewall rules, local auth, failover |

Every module is independently toggleable via `--skip` or `--only`.

## AWS module reference

### iam

Audits AWS IAM for credential hygiene, privilege escalation paths, and access pattern anomalies.

**Checks**:
- Root account MFA status (critical if disabled)
- Root account access keys (critical if any exist)
- Console users without MFA enabled
- Access keys older than 90 days
- IAM users with administrator policies attached directly (not via group)
- Password policy strength (length, complexity, rotation)
- Inline policies that grant `*:*`

**Required IAM permissions**: `iam:GetAccountSummary`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccountPasswordPolicy`, `iam:ListAttachedUserPolicies`, `iam:GetCredentialReport`, `iam:GenerateCredentialReport`

**Compliance mappings**: CIS AWS 1.5, 1.8, 1.10, 1.12, 1.14, 1.16

---

### s3

Audits S3 buckets for public exposure, encryption gaps, and missing protections.

**Checks**:
- Buckets with public ACLs (high)
- Buckets with public bucket policies (high)
- Block Public Access disabled at bucket or account level
- Server-side encryption not enabled
- Versioning disabled (limits ransomware recovery)
- Server access logging disabled
- MFA delete not enabled

**Required IAM permissions**: `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketEncryption`, `s3:GetBucketLogging`, `s3:GetBucketVersioning`, `s3:GetPublicAccessBlock`, `s3:GetAccountPublicAccessBlock`

**Compliance mappings**: CIS AWS 2.1.1, 2.1.3, 2.1.4, 2.1.5

**Notes**: Public bucket detection considers both ACL and policy. A bucket can be public via either path, and both are checked independently.

---

### ec2

Audits EC2 instances and security groups for network exposure and disk encryption.

**Checks**:
- Security groups allowing ingress from `0.0.0.0/0` to admin ports (22, 3389, 3306, 5432, 1433)
- Default VPC security groups not properly restricted
- EC2 instances with public IPv4 addresses
- EBS volumes without encryption at rest
- EBS encryption-by-default not set at the account level

**Required IAM permissions**: `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`, `ec2:GetEbsEncryptionByDefault`

**Compliance mappings**: CIS AWS 5.2, 5.3, 2.2.1

**Notes**: Admin port detection lists the most common SSH, RDP, and database ports. Custom admin ports won't be flagged unless added to the module's port list.

---

### cloudtrail

Audits CloudTrail configuration for logging gaps that would blind incident responders.

**Checks**:
- No CloudTrail trails exist (critical)
- All trails are single-region (incidents in unmonitored regions go unseen)
- Log file validation not enabled
- Trail not delivering to a CloudWatch log group
- S3 bucket holding trail logs is publicly accessible

**Required IAM permissions**: `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`

**Compliance mappings**: CIS AWS 3.1, 3.2

**Notes**: A multi-region trail in any region satisfies the multi-region check. The module reports the worst case across all trails.

---

### rds

Audits RDS instances for public exposure, missing encryption, and weak backup posture.

**Checks**:
- RDS instances with PubliclyAccessible set to true (high)
- Storage encryption not enabled
- Backup retention period of 0 (no backups)
- RDS instances using default username (admin, root, postgres)

**Required IAM permissions**: `rds:DescribeDBInstances`, `rds:DescribeDBSnapshots`

**Compliance mappings**: CIS AWS 2.3.1

**Notes**: Public RDS is high severity even when behind security group restrictions, because misconfiguration of those groups would expose the database directly.

---

### vpc

Audits VPC configuration for missing visibility and unsafe defaults.

**Checks**:
- VPCs without flow logs enabled
- Default VPC still in use (cannot have flow logs added cleanly)
- Default security groups not restricted

**Required IAM permissions**: `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs`, `ec2:DescribeSecurityGroups`

**Compliance mappings**: CIS AWS 3.9, 5.3

---

### lambda

Audits Lambda functions for hardcoded secrets, deprecated runtimes, and overpermissive resource policies.

**Checks**:
- Environment variables containing strings that look like secrets (AKIA, password=, token=, etc.)
- Functions running on deprecated Python or Node runtimes (Python 3.6, 3.7, Node 12, etc.)
- Resource-based policies allowing invocation from any AWS account
- Functions without VPC configuration handling sensitive data

**Required IAM permissions**: `lambda:ListFunctions`, `lambda:GetFunctionConfiguration`, `lambda:GetPolicy`

**Notes**: Secret detection uses pattern matching on environment variable values. False positives possible on test/dummy data. Review flagged functions manually.

---

### kms

Audits KMS keys for rotation policy and resource policy issues.

**Checks**:
- Customer-managed keys without automatic key rotation enabled
- KMS resource policies allowing access from any AWS account
- Disabled keys still being referenced by active resources

**Required IAM permissions**: `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`

**Compliance mappings**: CIS AWS 2.8

---

### secrets

Audits AWS Secrets Manager for rotation gaps and access policy issues.

**Checks**:
- Secrets without automatic rotation enabled
- Secrets older than 90 days that have not been rotated
- Resource policies allowing cross-account access without MFA conditions

**Required IAM permissions**: `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`, `secretsmanager:GetResourcePolicy`

## Azure module reference

### identity

Audits Azure subscription for direct role assignments and custom role exposure.

**Checks**:
- Owner role assigned directly to user principals (should be via PIM-eligible groups)
- Custom roles with overly broad permissions
- Service principals with subscription Owner role

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 1.22, 1.23

**Notes**: Subscription Owner via direct user assignment bypasses PIM controls. The module flags this even when the user is the legitimate subscription admin, because best practice is to use a PIM-eligible group.

---

### storage

Audits Azure Storage Accounts for HTTPS enforcement, TLS version, and public access settings.

**Checks**:
- Secure transfer (HTTPS only) not required
- Minimum TLS version below 1.2
- Blob anonymous access allowed at account level
- Storage account encryption not enabled
- Network rules allowing access from any network

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 3.1, 3.2, 3.6, 3.7, 3.15

---

### network

Audits Network Security Groups for dangerous inbound rules.

**Checks**:
- NSG rules allowing inbound from `*` or `Internet` to admin ports (22, 3389, 3306, 5432, 1433)
- NSG rules allowing inbound from `*` to all ports
- Public IP addresses on resources without justification

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 6.1, 6.2

---

### compute

Audits virtual machines and disks for encryption and management posture.

**Checks**:
- VMs with unmanaged (classic) disks
- Disks without Azure Disk Encryption
- VMs without boot diagnostics enabled

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 7.2, 7.3

---

### keyvault

Audits Azure Key Vault for protection settings against accidental and malicious deletion.

**Checks**:
- Soft delete not enabled
- Purge protection not enabled
- Public network access enabled with no firewall restrictions
- Access policy permission model used instead of Azure RBAC

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 8.1, 8.2, 8.5

**Notes**: Soft delete and purge protection are both irreversible once enabled, by design. The module flags vaults that should have these but don't.

---

### sql

Audits Azure SQL servers for public exposure, weak TLS, and missing controls.

**Checks**:
- Public network access enabled
- Firewall rules allowing `0.0.0.0/0` (entire internet) - critical
- "Allow Azure services" enabled (any Azure tenant can connect)
- Minimum TLS version below 1.2
- Entra ID administrator not configured (forces SQL auth only)
- Auditing not enabled

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 4.1.1, 4.1.2, 4.1.3, 4.1.4, 4.1.5, 4.1.6

**Notes**: A SQL server with `0.0.0.0/0` firewall rule is the highest-impact finding this tool produces. Direct internet exposure of a database is treated as critical regardless of authentication.

---

### cosmosdb

Audits Cosmos DB accounts for network exposure and authentication settings.

**Checks**:
- Public network access enabled with no IP or VNet restrictions
- IP firewall rule of `0.0.0.0` (allows all Azure datacenters)
- Local (key-based) authentication not disabled
- Automatic failover not enabled

**Required Azure RBAC role**: Reader on the subscription

**Compliance mappings**: CIS Azure 4.5.1

## Usage

### Common patterns

```bash
# Default: AWS audit, HTML report only
atarus-cloud -p aws

# All output formats (HTML, PDF, JSON, remediation.sh)
atarus-cloud -p aws --format all

# Specific AWS profile
atarus-cloud -p aws --profile production --format all

# Specific Azure subscription
atarus-cloud -p azure --subscription <SUBSCRIPTION_ID> --format all

# Quick scan: skip slow modules
atarus-cloud -p aws --skip rds,vpc

# Targeted: storage and identity only
atarus-cloud -p azure --only storage,identity

# List all available modules
atarus-cloud --list-modules

# Show version
atarus-cloud --version
```

### Authentication

**AWS**: Uses standard AWS SDK credential chain. Configure via `aws configure`, environment variables, or IAM instance role. The tool reads credentials from your local environment, never from arguments.

**Azure**: Uses Azure CLI authentication. Run `az login` first. The tool reads the active subscription unless you specify one with `--subscription`.

### Required permissions

Both clouds need read-only access. The tool never modifies any resource.

**AWS**: Easiest path is the AWS-managed `SecurityAudit` policy. For granular per-module permissions, see the module reference sections above.

**Azure**: Reader role at the subscription scope. No custom permissions needed for any module.

## Reports

### HTML

Tabbed dark-themed report with sections for:
- **Overview** - Score, finding counts by severity, services breakdown
- **Executive Summary** - Auto-generated plain language summary for non-technical readers
- **Attack Paths** - Chained finding scenarios showing realistic compromise paths
- **Findings** - Every finding with observation, risk, recommendation, remediation command, effort estimate
- **Compliance** - CIS and NIST controls failed, grouped by category
- **Remediation** - Every actionable command in execution order

### PDF

Branded export of the HTML report. Page numbers, confidential footer, Atarus branding. Ready to attach to a client email.

### JSON

Full machine-readable output with every finding, attack path, compliance mapping, and executive summary field. Use for SIEM/SOAR integration, custom dashboards, or piping into other tools.

### remediation.sh

Auto-generated shell script with every actionable CLI command, ordered by severity (critical first). Each finding's remediation command is included with comments explaining what the command does and why. Review every command before running.

## Compliance frameworks

- **CIS AWS Foundations Benchmark 2.0** (18 controls mapped)
- **CIS Azure Foundations Benchmark 2.0** (21 controls mapped)
- **NIST 800-53 Rev 5** (14 controls mapped, shared across AWS and Azure)

The Compliance tab in the HTML report shows controls that failed, grouped by framework. Findings link back to the controls they violate.

## Adding a custom module

Every module is a function with this signature:

```python
def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Module docstring"""
    # ... do work ...
    return ModuleResult(success=True, message="Did the thing")
```

Save it as `src/atarus_cloud/providers/aws/yourmodule.py` (or `azure/yourmodule.py`). Register it in `cli.py`:

```python
from atarus_cloud.providers.aws import yourmodule

AWS_MODULES = [
    # ... existing modules ...
    ("Your module description", "yourmodule", yourmodule.run),
]
```

Reinstall with `pip install -e .` and your module is now available via `--only yourmodule`.

The module receives the running `AuditResult`, a `session` dict containing the cloud SDK clients, and a verbose flag. Mutate `result.findings` to add findings.

## Roadmap

- GCP provider (gcloud authentication, IAM, storage, compute)
- Multi-account AWS / multi-subscription Azure scanning
- ECR, ECS, EKS audit modules (AWS containers)
- AKS audit module (Azure Kubernetes)
- API Gateway audit modules (AWS and Azure)
- Additional compliance frameworks (PCI DSS, HIPAA, SOC 2)
- Scan comparison mode (diff two scans over time)

## Part of the atarus- tool suite

- **[atarus-recon](https://github.com/atarus-security/atarus-recon)** - External attack surface recon
- **atarus-cloud** - Multi-cloud misconfiguration scanner (you are here)
- **[atarus-phishcheck](https://github.com/atarus-security/atarus-phishcheck)** - Email security analyzer
- **[atarus-report-kit](https://github.com/atarus-security/atarus-report-kit)** - Pentest report builder for juniors and students

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)

We are building the groundwork for the AI pentesting tool of the future, one module at a time.
