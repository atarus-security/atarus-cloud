from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS RDS database configuration"""

    rds = session.client("rds")
    findings_before = len(result.findings)

    try:
        instances = rds.describe_db_instances()["DBInstances"]
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot describe RDS instances: {e}")

    if not instances:
        return ModuleResult(success=True, message="No RDS instances found")

    for db in instances:
        db_id = db["DBInstanceIdentifier"]
        db_arn = db["DBInstanceArn"]

        if db.get("PubliclyAccessible", False):
            endpoint = db.get("Endpoint", {}).get("Address", "unknown")
            result.add_finding(CloudFinding(
                service="RDS",
                resource_id=db_arn,
                resource_name=db_id,
                severity="critical",
                observation=f"RDS instance '{db_id}' is publicly accessible at {endpoint}.",
                risk=f"The database is reachable from the internet. Attackers can attempt brute force attacks against the database credentials or exploit any known vulnerabilities in the database engine.",
                recommendation=f"Disable public access for RDS instance '{db_id}'. Place it in a private subnet.",
                remediation_cmd=f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible --apply-immediately",
                remediation_effort="10 minutes",
                compliance=["CIS 2.3.1"],
            ))

        if not db.get("StorageEncrypted", False):
            result.add_finding(CloudFinding(
                service="RDS",
                resource_id=db_arn,
                resource_name=db_id,
                severity="high",
                observation=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                risk="Database contents are stored in plaintext on disk. If the underlying storage is compromised or a snapshot is shared, all data including credentials and PII is exposed.",
                recommendation=f"Enable encryption for RDS instance '{db_id}'. Note: existing instances require creating an encrypted copy.",
                remediation_cmd=f"# Encryption cannot be enabled on existing instances. Create encrypted snapshot:\naws rds create-db-snapshot --db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-encrypt-snap\n# Then restore from encrypted copy",
                remediation_effort="1 hour",
                compliance=["CIS 2.3.1"],
            ))

        if not db.get("AutoMinorVersionUpgrade", True):
            result.add_finding(CloudFinding(
                service="RDS",
                resource_id=db_arn,
                resource_name=db_id,
                severity="medium",
                observation=f"RDS instance '{db_id}' does not have auto minor version upgrade enabled.",
                risk="Security patches for the database engine will not be applied automatically. Known vulnerabilities remain exploitable until manually patched.",
                recommendation=f"Enable auto minor version upgrade for '{db_id}'.",
                remediation_cmd=f"aws rds modify-db-instance --db-instance-identifier {db_id} --auto-minor-version-upgrade --apply-immediately",
                remediation_effort="5 minutes",
            ))

        backup_days = db.get("BackupRetentionPeriod", 0)
        if backup_days < 7:
            result.add_finding(CloudFinding(
                service="RDS",
                resource_id=db_arn,
                resource_name=db_id,
                severity="low",
                observation=f"RDS instance '{db_id}' has a backup retention of only {backup_days} days.",
                risk="Short backup retention limits recovery options in case of data corruption, ransomware, or accidental deletion.",
                recommendation=f"Set backup retention to at least 7 days for '{db_id}'.",
                remediation_cmd=f"aws rds modify-db-instance --db-instance-identifier {db_id} --backup-retention-period 7 --apply-immediately",
                remediation_effort="5 minutes",
            ))

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(instances)} databases, {new_findings} findings")
