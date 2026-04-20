import boto3
import json
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS S3 bucket configuration"""

    s3 = session.client("s3")
    findings_before = len(result.findings)

    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list buckets: {e}")

    for bucket in buckets:
        name = bucket["Name"]
        _check_public_access(s3, name, result, verbose)
        _check_encryption(s3, name, result, verbose)
        _check_versioning(s3, name, result, verbose)
        _check_logging(s3, name, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(buckets)} buckets, {new_findings} findings")


def _check_public_access(s3, bucket_name, result, verbose):
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
                remediation_cmd=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.5"],
            ))
    except s3.exceptions.ClientError as e:
        if "NoSuchPublicAccessBlockConfiguration" in str(e):
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="high",
                observation=f"S3 bucket '{bucket_name}' has no public access block configuration.",
                risk=f"Without any public access controls, bucket '{bucket_name}' is vulnerable to being made publicly accessible. ACL or policy changes could expose all data to the internet.",
                recommendation=f"Enable S3 Block Public Access for bucket '{bucket_name}'.",
                remediation_cmd=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.5"],
            ))


def _check_encryption(s3, bucket_name, result, verbose):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
    except s3.exceptions.ClientError as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            result.add_finding(CloudFinding(
                service="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                severity="medium",
                observation=f"S3 bucket '{bucket_name}' does not have default encryption enabled.",
                risk=f"Objects stored in '{bucket_name}' without explicit encryption will be stored unencrypted. If the underlying storage is compromised or data is accessed through a misconfiguration, contents are readable in plaintext.",
                recommendation=f"Enable default SSE-S3 or SSE-KMS encryption for bucket '{bucket_name}'.",
                remediation_cmd=f'aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration \'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\'',
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.1"],
            ))


def _check_versioning(s3, bucket_name, result, verbose):
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
                remediation_cmd=f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
                remediation_effort="2 minutes",
                compliance=["CIS 2.1.3"],
            ))
    except Exception as e:
        if verbose:
            print(f"  Versioning check error for {bucket_name}: {e}")


def _check_logging(s3, bucket_name, result, verbose):
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
    except Exception as e:
        if verbose:
            print(f"  Logging check error for {bucket_name}: {e}")
