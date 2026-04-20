# atarus-cloud

Cloud security misconfiguration scanner by [Atarus Offensive Security](https://atarussecurity.com).

Audit your cloud environment. Get findings in plain English with observation, risk, and recommendation. Chain findings into realistic attack paths. Generate an executive summary for leadership. Run an auto-generated remediation script to fix it all.

## What it does

**Nine AWS audit modules:**

- IAM: Root MFA, user MFA, access key age, password policy, admin users, unused accounts
- S3: Public access blocks, encryption, versioning, access logging
- EC2: Security group exposure (SSH, RDP, databases open to internet), public IPs, EBS encryption
- CloudTrail: Multi-region logging, log file validation, active logging status
- RDS: Public databases, encryption, auto minor version upgrade, backup retention
- VPC: Default VPC usage, flow logs
- Lambda: Environment variable secrets, deprecated runtimes, function resource policies
- KMS: Customer-managed key rotation, overly permissive key policies
- Secrets Manager: Automatic rotation, secret age, resource policies, deletion protection

**Attack path correlation:**

Findings are chained into realistic attack narratives. Instead of listing "no MFA" and "admin access" as separate findings, atarus-cloud shows you the scenario: "Full account takeover via username. Attacker obtains password, logs in without MFA, inherits admin access, disables logging, exfiltrates data." Every attack path includes severity, impact, numbered attack sequence, and references to the underlying findings.

**Executive summary:**

Auto-generated plain-language summary for non-technical stakeholders. Three sections: Security posture, Key risks, Recommended actions. Ready to hand to a city manager, CISO, or board.

**Every finding includes:**

- Observation: What was found
- Risk: What an attacker could do
- Recommendation: How to fix it
- Remediation command: The exact AWS CLI command to fix it
- Remediation effort: How long it takes
- Compliance mapping: CIS benchmark reference

**Output formats:**

- HTML report with tabbed navigation: Overview, Executive Summary, Attack Paths, Findings, Remediation
- PDF with Atarus branding, page breaks per section, confidential footer
- JSON for integration with other tools
- Runnable remediation.sh script with all CLI fixes ordered by severity

## Install

```bash
git clone https://github.com/atarus-security/atarus-cloud.git
cd atarus-cloud
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Requirements

- Python 3.10+
- AWS CLI configured with credentials (`aws configure`)
- IAM permissions to read account configuration (SecurityAudit managed policy works)

## Usage

```bash
# Full audit with HTML report
atarus-cloud -p aws

# All output formats (HTML, JSON, PDF, remediation.sh)
atarus-cloud -p aws --format all

# Specific AWS profile
atarus-cloud -p aws --profile production --format all

# Specific region
atarus-cloud -p aws --region us-east-1

# Skip slow modules
atarus-cloud -p aws --skip rds,vpc

# Only run specific modules
atarus-cloud -p aws --only iam,s3

# List all modules
atarus-cloud --list-modules

# Version
atarus-cloud --version
```

## Modules

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

## What sets it apart

**Observation, Risk, Recommendation format.** Every finding reads like a pen test report, not a compliance dump. Your client or their CISO can understand it without Googling CIS benchmark numbers.

**Attack path chaining.** No other cloud scanner connects the dots between findings. atarus-cloud tells you how an attacker would combine misconfigurations to achieve real impact. Fix any finding in the chain to break the path.

**Auto-generated executive summary.** Plain-language posture analysis, key risks, and recommended actions. Ready for leadership review without a translator.

**Auto-generated remediation script.** Review it, approve it, run it. Fix 40 findings with one script instead of clicking through the console.

**Fix these first prioritization.** No more staring at 200 findings wondering where to start. Critical and high severity fixes surface at the top of every report.

**Clean, branded output.** Hand the PDF directly to a client. Every page has a confidential footer and page numbers. No post-processing required.

## Roadmap

- Azure provider (az login authentication, identity, storage, network, compute, keyvault)
- GCP provider (gcloud authentication, IAM, storage, compute)
- Multi-account support (organization-wide scans)
- ECR and ECS audit modules (container registry and compute)
- API Gateway audit module
- EKS audit module
- Compliance report mode (CIS, NIST, PCI export)

## Part of the atarus- tool suite

- **[atarus-recon](https://github.com/atarus-security/atarus-recon)** - External attack surface recon (11 modules)
- **atarus-cloud** - Cloud misconfiguration scanner (you are here)
- **atarus-report** - AI-powered pentest report generator (planned)
- **atarus-phish** - Phishing campaign analysis (planned)
- **atarus-cred** - Credential exposure checker (planned)

## License

MIT License. See LICENSE for details.

## Built by

[Atarus Offensive Security LLC](https://atarussecurity.com)
