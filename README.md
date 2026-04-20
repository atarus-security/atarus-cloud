# atarus-cloud

Multi-cloud security misconfiguration scanner by [Atarus Offensive Security](https://atarussecurity.com).

Audit your AWS and Azure environments. Get findings in plain English with observation, risk, and recommendation. Chain findings into realistic attack paths. Generate an executive summary for leadership. Map findings to CIS and NIST controls. Run an auto-generated remediation script to fix it all.

## Supported providers

- **AWS** (9 modules): IAM, S3, EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager
- **Azure** (4 modules): Identity, Storage, Network, Compute
- GCP (planned)

## What it does

**AWS audit modules:**

- IAM: Root MFA, user MFA, access key age, password policy, admin users, unused accounts
- S3: Public access blocks, encryption, versioning, access logging
- EC2: Security group exposure, public IPs, EBS encryption
- CloudTrail: Multi-region logging, log file validation, active logging status
- RDS: Public databases, encryption, auto minor version upgrade, backup retention
- VPC: Default VPC usage, flow logs
- Lambda: Environment variable secrets, deprecated runtimes, function resource policies
- KMS: Customer-managed key rotation, overly permissive key policies
- Secrets Manager: Automatic rotation, secret age, resource policies, deletion protection

**Azure audit modules:**

- Identity: Owner role assignments, direct user privilege, custom roles with wildcards
- Storage: HTTPS enforcement, TLS version, public network access, blob anonymous access, container public access
- Network: NSG rules allowing admin ports from internet, public IPs
- Compute: Disk encryption, managed disks, boot diagnostics

**Attack path correlation:**

Findings are chained into realistic attack narratives. Instead of listing "no MFA" and "admin access" as separate findings, atarus-cloud shows you the scenario: "Full account takeover via username. Attacker obtains password, logs in without MFA, inherits admin access, disables logging, exfiltrates data."

**Executive summary:**

Auto-generated plain-language summary for non-technical stakeholders. Three sections: Security posture, Key risks, Recommended actions.

**Compliance mapping:**

Every finding maps to CIS AWS Foundations Benchmark, CIS Azure Benchmark, and NIST 800-53 Rev 5 controls. The Compliance tab shows failed controls grouped by framework and category.

**Every finding includes:**

- Observation: What was found
- Risk: What an attacker could do
- Recommendation: How to fix it
- Remediation command: The exact CLI command to fix it (AWS CLI or Azure CLI)
- Remediation effort: How long it takes
- Compliance mapping: CIS and NIST references

**Output formats:**

- HTML report with tabbed navigation: Overview, Executive Summary, Attack Paths, Findings, Compliance, Remediation
- PDF with Atarus branding, page breaks per section, confidential footer
- JSON for integration with other tools
- Runnable remediation script with all CLI fixes ordered by severity

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
- AWS CLI configured with credentials (`aws configure`)
- IAM permissions to read account configuration (SecurityAudit managed policy works)

**For Azure:**
- Azure CLI installed and logged in (`az login`)
- Reader role on the subscription being scanned

**Python 3.10+ required for both.**

## Usage

### AWS

```bash
# Full audit with HTML report
atarus-cloud -p aws

# All output formats
atarus-cloud -p aws --format all

# Specific AWS profile
atarus-cloud -p aws --profile production --format all

# Specific region
atarus-cloud -p aws --region us-east-1
```

### Azure

```bash
# Full audit using default subscription from az login
atarus-cloud -p azure

# All output formats
atarus-cloud -p azure --format all

# Specific subscription
atarus-cloud -p azure --subscription <SUBSCRIPTION_ID>
```

### Module selection (both providers)

```bash
# Skip specific modules
atarus-cloud -p aws --skip rds,vpc

# Only run specific modules
atarus-cloud -p azure --only storage,network

# List all modules across all providers
atarus-cloud --list-modules

# Version
atarus-cloud --version
```

## Modules

### AWS

| Key | Module | What it checks |
|---|---|---|
| iam | IAM audit | Users, MFA, access keys, password policy, admin access |
| s3 | S3 audit | Bucket policies, encryption, versioning, logging |
| ec2 | EC2 audit | Security groups, public IPs, EBS encryption |
| cloudtrail | CloudTrail audit | Logging gaps, multi-region, validation |
| rds | RDS audit | Public databases, encryption, backups |
| vpc | VPC audit | Default VPCs, flow logs |
| lambda | Lambda audit | Env var secrets, deprecated runtimes, policies |
| kms | KMS audit | Key rotation, resource policies |
| secrets | Secrets Manager audit | Rotation, age, resource policies |

### Azure

| Key | Module | What it checks |
|---|---|---|
| identity | Identity audit | Owner roles, user vs group assignments, custom role permissions |
| storage | Storage audit | HTTPS, TLS, public access, encryption, blob containers |
| network | Network audit | NSG rules, dangerous ports, public IPs |
| compute | Compute audit | Disk encryption, managed disks, boot diagnostics |

## What sets it apart

**Observation, Risk, Recommendation format.** Every finding reads like a pen test report, not a compliance dump. Your client or their CISO can understand it without Googling CIS benchmark numbers.

**Attack path chaining.** No other cloud scanner connects the dots between findings. atarus-cloud tells you how an attacker would combine misconfigurations to achieve real impact. Fix any finding in the chain to break the path.

**Auto-generated executive summary.** Plain-language posture analysis, key risks, and recommended actions. Ready for leadership review without a translator.

**Compliance mapping.** CIS AWS, CIS Azure, and NIST 800-53 Rev 5 coverage built into every report. Failed controls surface as their own section with the underlying findings linked.

**Auto-generated remediation script.** Review it, approve it, run it. Fix dozens of findings with one script instead of clicking through the console.

**Clean, branded output.** Hand the PDF directly to a client. Every page has a confidential footer and page numbers.

## Roadmap

- GCP provider (gcloud authentication, IAM, storage, compute)
- Multi-account AWS / multi-subscription Azure support
- ECR and ECS audit modules (AWS containers)
- API Gateway audit module (AWS)
- EKS / AKS audit modules (managed Kubernetes)
- Azure Key Vault module
- Azure SQL / Cosmos DB modules
- Additional compliance frameworks (PCI DSS, HIPAA)

## Part of the atarus- tool suite

- **[atarus-recon](https://github.com/atarus-security/atarus-recon)** - External attack surface recon (11 modules)
- **atarus-cloud** - Multi-cloud misconfiguration scanner (you are here)
- **atarus-report** - AI-powered pentest report generator (planned)
- **atarus-phish** - Phishing campaign analysis (planned)
- **atarus-cred** - Credential exposure checker (planned)

## License

MIT License. See LICENSE for details.

## Built by

[Atarus Offensive Security LLC](https://atarussecurity.com)
