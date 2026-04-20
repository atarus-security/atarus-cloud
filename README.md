# atarus-cloud

Multi-cloud security misconfiguration scanner by [Atarus Offensive Security](https://atarussecurity.com).

Audit your AWS and Azure environments. Get findings in plain English with observation, risk, and recommendation. Chain findings into realistic attack paths. Generate an executive summary for leadership. Map findings to CIS and NIST controls. Run an auto-generated remediation script to fix it all.

## Supported providers

- **AWS** (9 modules): IAM, S3, EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager
- **Azure** (7 modules): Identity, Storage, Network, Compute, Key Vault, SQL, Cosmos DB
- GCP (planned)

## Why atarus-cloud

Cloud scanners have been around for years. ScoutSuite dumps 200 findings with no context. Prowler outputs CIS control numbers nobody remembers. Commercial tools charge thousands and produce reports no one reads.

atarus-cloud was built by pentesters who were tired of delivering audit output pretending to be security work.

**Every finding reads like a pen test report.** Observation of what was found. Risk of what an attacker could do. Recommendation with the exact CLI command to fix it. No CIS control numbers unless the client asks.

**Attack paths chain findings into real scenarios.** Instead of listing "no MFA" and "admin access" separately, the report tells you how an attacker combines them into full account takeover.

**The executive summary auto-generates.** Plain language for the CISO or city manager. Security posture, key risks, recommended actions. No translator needed.

**Compliance mapping is built in.** CIS AWS, CIS Azure, and NIST 800-53 controls mapped to every finding. The Compliance tab shows failed controls grouped by framework.

**The remediation script actually runs.** Review it, approve it, execute it. Fix 40 findings with one script instead of clicking through the console.

## Install

```bash
git clone https://github.com/atarus-security/atarus-cloud.git
cd atarus-cloud
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Requirements

**For AWS:**
- AWS CLI configured (`aws configure`)
- IAM permissions to read account config (SecurityAudit managed policy works)

**For Azure:**
- Azure CLI installed and logged in (`az login`)
- Reader role on the subscription being scanned

**Python 3.10+ required.**

## Usage

### AWS

```bash
# Full audit
atarus-cloud -p aws

# All output formats (HTML, JSON, PDF, remediation.sh)
atarus-cloud -p aws --format all

# Specific AWS profile
atarus-cloud -p aws --profile production --format all

# Specific region
atarus-cloud -p aws --region us-east-1
```

### Azure

```bash
# Full audit using default subscription
atarus-cloud -p azure

# All output formats
atarus-cloud -p azure --format all

# Specific subscription
atarus-cloud -p azure --subscription <SUBSCRIPTION_ID>
```

### Module selection

```bash
# Skip specific modules
atarus-cloud -p aws --skip rds,vpc

# Only run specific modules
atarus-cloud -p azure --only storage,network

# List all modules
atarus-cloud --list-modules

# Version
atarus-cloud --version
```

## What it checks

### AWS modules (9)

| Key | Service | What it checks |
|---|---|---|
| iam | IAM | Users, MFA, access keys, password policy, admin access |
| s3 | S3 | Bucket policies, encryption, versioning, logging |
| ec2 | EC2 | Security groups, public IPs, EBS encryption |
| cloudtrail | CloudTrail | Logging gaps, multi-region, validation |
| rds | RDS | Public databases, encryption, backups |
| vpc | VPC | Default VPCs, flow logs |
| lambda | Lambda | Env var secrets, deprecated runtimes, policies |
| kms | KMS | Key rotation, resource policies |
| secrets | Secrets Manager | Rotation, age, resource policies |

### Azure modules (7)

| Key | Service | What it checks |
|---|---|---|
| identity | Identity | Owner roles, direct assignments, custom roles |
| storage | Storage | HTTPS, TLS, public access, encryption, containers |
| network | Network | NSG rules, dangerous ports, public IPs |
| compute | Compute | Disk encryption, managed disks, boot diagnostics |
| keyvault | Key Vault | Soft delete, purge protection, network access, RBAC |
| sql | SQL | Public access, firewall rules, TLS, auditing, Entra admin |
| cosmosdb | Cosmos DB | Public access, firewall, local auth, failover |

## Output

### HTML report

Tabbed interface: Overview, Executive Summary, Attack Paths, Findings, Compliance, Remediation. Responsive, dark-themed, ready to share.

### PDF report

Every section on its own page. Atarus branding, confidential footer, page numbers. Ready to attach to a client email.

### JSON

Machine-readable output with every finding, attack path, compliance mapping, and executive summary field. Integrate with SIEM, ticketing, or custom dashboards.

### remediation.sh

Auto-generated shell script with every actionable CLI command, ordered by severity. Review, approve, run.

## Every finding includes

- **Observation** - What was found
- **Risk** - What an attacker could do with it
- **Recommendation** - How to fix it
- **Remediation command** - The exact CLI to run (AWS CLI or Azure CLI)
- **Remediation effort** - How long the fix takes
- **Compliance mapping** - CIS and NIST control references

## Compliance frameworks

- CIS AWS Foundations Benchmark 2.0 (18 controls mapped)
- CIS Azure Foundations Benchmark 2.0 (21 controls mapped)
- NIST 800-53 Rev 5 (14 controls mapped, shared across AWS and Azure)

## Roadmap

- GCP provider (gcloud authentication, IAM, storage, compute)
- Multi-account AWS / multi-subscription Azure support
- ECR, ECS, EKS audit modules (AWS containers)
- AKS audit module (Azure Kubernetes)
- API Gateway audit modules (AWS and Azure)
- Additional compliance frameworks (PCI DSS, HIPAA, SOC 2)
- Scan comparison mode (diff two scans over time)

## Part of the atarus- tool suite

Open source offensive security tools built by practitioners.

- **[atarus-recon](https://github.com/atarus-security/atarus-recon)** - External attack surface recon
- **atarus-cloud** - Multi-cloud misconfiguration scanner (you are here)
- **[atarus-report-kit](https://github.com/atarus-security/atarus-report-kit)** - Single-file offline pentest reporting tool

## License

MIT License. See LICENSE for details.

## Built by

[Atarus Offensive Security LLC](https://atarussecurity.com)

Critical infrastructure security. SoCal-based. Real pentesters, real engagements, real tools.
