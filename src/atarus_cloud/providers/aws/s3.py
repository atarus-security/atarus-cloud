from atarus_cloud.models import AuditResult, CloudFinding, GLOBAL
from atarus_cloud.providers.aws.common import q, error_code
from atarus_cloud.runner import ModuleResult


CHECKS = ("public access block", "default encryption", "versioning", "access logging")


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS S3 bucket configuration (the bucket list is global, runs once per account)"""

    s3 = session.client("s3")
    cov = result.recorder("s3", "S3", GLOBAL)
    findings_before = len(result.findings)

    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list buckets: {e}")

    ok = {check: 0 for check in CHECKS}
    for bucket in buckets:
        name = bucket["Name"]
        ok["public access block"] += _check_public_access(s3, name, result, cov)
        ok["default encryption"] += _check_encryption(s3, name, result, cov)
        ok["versioning"] += _check_versioning(s3, name, result, cov)
        ok["access logging"] += _check_logging(s3, name, result, cov)

    for check in CHECKS:
        if ok[check] == len(buckets):
            cov.checked(check, f"{len(buckets)} buckets")
        elif ok[check]:
            cov.checked(check, f"{ok[check]} of {len(buckets)} buckets; the rest are listed as not run")

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(buckets)} buckets, {new_findings} findings")


def _check_public_access(s3, bucket_name, result, cov) -> int:
    try:
        public_block = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]

        if not all([
            public_block.get("BlockPublicAcls", False),
            public_block.get("IgnorePublicAcls", False),
            public_block.get("BlockPublicPolicy", False),
            public_block.get("RestrictPublicBuckets", False),
        ]):
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="high",
                observation=f"S3 bucket '{bucket_name}' does not have all public access blocks enabled.",
                risk=f"Without full public access blocking, bucket '{bucket_name}' could be made publicly accessible through ACL or policy changes. Any data in this bucket could be exposed to the internet.",
                recommendation=f"Enable all four S3 Block Public Access settings for bucket '{bucket_name}'.",
                remediation_cmd=f"aws s3api put-public-access-block --bucket {q(bucket_name)} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.5"],
            ))
        return 1
    except Exception as e:
        if error_code(e) == "NoSuchPublicAccessBlockConfiguration" or "NoSuchPublicAccessBlockConfiguration" in str(e):
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="high",
                observation=f"S3 bucket '{bucket_name}' has no public access block configuration.",
                risk=f"Without any public access controls, bucket '{bucket_name}' is vulnerable to being made publicly accessible. ACL or policy changes could expose all data to the internet.",
                recommendation=f"Enable S3 Block Public Access for bucket '{bucket_name}'.",
                remediation_cmd=f"aws s3api put-public-access-block --bucket {q(bucket_name)} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.5"],
            ))
            return 1
        cov.not_run(f"public access block ({bucket_name})", e)
        return 0


def _check_encryption(s3, bucket_name, result, cov) -> int:
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return 1
    except Exception as e:
        if error_code(e) == "ServerSideEncryptionConfigurationNotFoundError" or "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="medium",
                observation=f"S3 bucket '{bucket_name}' does not have default encryption enabled.",
                risk=f"Objects stored in '{bucket_name}' without explicit encryption will be stored unencrypted. If the underlying storage is compromised or data is accessed through a misconfiguration, contents are readable in plaintext.",
                recommendation=f"Enable default SSE-S3 or SSE-KMS encryption for bucket '{bucket_name}'.",
                remediation_cmd=f'aws s3api put-bucket-encryption --bucket {q(bucket_name)} --server-side-encryption-configuration \'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\'',
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.1"],
            ))
            return 1
        cov.not_run(f"default encryption ({bucket_name})", e)
        return 0


def _check_versioning(s3, bucket_name, result, cov) -> int:
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        status = versioning.get("Status", "Disabled")

        if status != "Enabled":
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="low",
                observation=f"S3 bucket '{bucket_name}' does not have versioning enabled.",
                risk="Without versioning, deleted or overwritten objects cannot be recovered. A ransomware attack or accidental deletion would result in permanent data loss.",
                recommendation=f"Enable versioning for bucket '{bucket_name}'.",
                remediation_cmd=f"aws s3api put-bucket-versioning --bucket {q(bucket_name)} --versioning-configuration Status=Enabled",
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.3"],
            ))
        return 1
    except Exception as e:
        cov.not_run(f"versioning ({bucket_name})", e)
        return 0


def _check_logging(s3, bucket_name, result, cov) -> int:
    try:
        logging_config = s3.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in logging_config:
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="low",
                observation=f"S3 bucket '{bucket_name}' does not have access logging enabled.",
                risk="Without access logging, there is no audit trail of who accessed or modified objects in this bucket. Unauthorized access or data exfiltration would go undetected.",
                recommendation=f"Enable server access logging for bucket '{bucket_name}'.",
                remediation_cmd=f"# Enable via Console: S3 > {bucket_name} > Properties > Server access logging > Enable",
                remediation_effort="5 minutes",
                compliance=["CIS 2.1.4"],
            ))
        return 1
    except Exception as e:
        cov.not_run(f"access logging ({bucket_name})", e)
        return 0
