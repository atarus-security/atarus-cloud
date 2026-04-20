# atarus-cloud v1.0.0

First stable release of the multi-cloud security scanner.

## What's in this release

**16 audit modules across AWS and Azure**

AWS (9): IAM, S3, EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager
Azure (7): Identity, Storage, Network, Compute, Key Vault, SQL, Cosmos DB

**Report features**

- Observation, Risk, Recommendation format on every finding
- Attack path correlation engine with 6 attack scenarios
- Auto-generated executive summary for non-technical stakeholders
- CIS AWS, CIS Azure, and NIST 800-53 compliance mapping
- Auto-generated remediation.sh script with severity-ordered CLI commands

**Output formats**

- HTML with tabbed navigation
- PDF with Atarus branding and per-section page breaks
- JSON for integration
- Executable remediation script

## Installation

```bash
git clone https://github.com/atarus-security/atarus-cloud.git
cd atarus-cloud
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Quick start

```bash
# AWS
atarus-cloud -p aws --format all

# Azure
atarus-cloud -p azure --format all
```

## What's next

GCP support, multi-account AWS, multi-subscription Azure, Kubernetes modules, scan comparison mode.

Built by [Atarus Offensive Security LLC](https://atarussecurity.com).
