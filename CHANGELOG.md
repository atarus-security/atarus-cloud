# Changelog

All notable changes to atarus-cloud. Dates are commit dates. Only v1.0.0 was tagged and published as a GitHub release; earlier versions were development builds on the same day.

## Unreleased (refresh-2026-10)

### Fixed
- Fresh installs crashed on every command (including `--version` and AWS-only scans) with `ModuleNotFoundError`: `cli.py` imports all Azure modules, but `pyproject.toml` declared no Azure SDKs and `requirements.txt` was missing `azure-mgmt-sql` and `azure-mgmt-cosmosdb`. Both files now declare exactly the SDKs the code imports; the unused `azure-mgmt-resource` and `azure-mgmt-monitor` were dropped.
- HTML report template moved into the package so non-editable installs can find it.
- WeasyPrint is imported only for PDF export; a missing Pango library now prints a PDF error instead of aborting before the remediation script is written.

### Added
- Offline unit tests (`tests/`), GitHub Actions workflow, `constraints.txt`, SECURITY.md and this changelog.

### Docs
- README: Pango requirement for PDF, remediation script caveats (`set -e`, placeholders, unquoted resource names), correct description of the module `session` argument, atarus-webscan added to the suite list.

## 1.0.0 (2026-04-19)
- First stable release: 16 modules (AWS IAM, S3, EC2, CloudTrail, RDS, VPC, Lambda, KMS, Secrets Manager; Azure Identity, Storage, Network, Compute, Key Vault, SQL, Cosmos DB).
- Attack path correlation, executive summary, CIS AWS, CIS Azure and NIST 800-53 mapping, remediation script, HTML, PDF and JSON reports.

## Development builds (2026-04-19)
- 0.1.0 IAM and S3 auditing with remediation scripts; 0.2.1 PDF polish; 0.3.0 Lambda and KMS; 0.4.0 attack paths; 0.5.0 executive summary; 0.7.0 CIS AWS and NIST mapping; 0.8.0 Azure provider; 0.9.0 Azure Key Vault, SQL and Cosmos DB.
