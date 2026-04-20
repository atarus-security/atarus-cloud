from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS CloudTrail configuration"""

    ct = session.client("cloudtrail")
    findings_before = len(result.findings)

    try:
        trails = ct.describe_trails()["trailList"]
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot describe trails: {e}")

    if not trails:
        result.add_finding(CloudFinding(
            service="CloudTrail",
            resource_id="cloudtrail",
            resource_name="CloudTrail",
            severity="critical",
            observation="No CloudTrail trails are configured in this account.",
            risk="Without CloudTrail, there is no audit log of API activity. An attacker can create resources, modify configurations, exfiltrate data, and delete evidence with no record of their actions.",
            recommendation="Create a multi-region CloudTrail trail with S3 delivery and log file validation enabled.",
            remediation_cmd="aws cloudtrail create-trail --name atarus-audit-trail --s3-bucket-name YOUR-LOG-BUCKET --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name atarus-audit-trail",
            remediation_effort="15 minutes",
            compliance=["CIS 3.1"],
        ))
        new_findings = len(result.findings) - findings_before
        return ModuleResult(success=True, message=f"{new_findings} findings")

    for trail in trails:
        trail_name = trail.get("Name", "unknown")
        trail_arn = trail.get("TrailARN", "")

        if not trail.get("IsMultiRegionTrail", False):
            result.add_finding(CloudFinding(
                service="CloudTrail",
                resource_id=trail_arn,
                resource_name=trail_name,
                severity="high",
                observation=f"CloudTrail '{trail_name}' is not configured for multi-region logging.",
                risk="API activity in other regions will not be logged. An attacker can operate in unmonitored regions to avoid detection.",
                recommendation=f"Enable multi-region logging for trail '{trail_name}'.",
                remediation_cmd=f"aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail",
                remediation_effort="5 minutes",
                compliance=["CIS 3.1"],
            ))

        if not trail.get("LogFileValidationEnabled", False):
            result.add_finding(CloudFinding(
                service="CloudTrail",
                resource_id=trail_arn,
                resource_name=trail_name,
                severity="medium",
                observation=f"CloudTrail '{trail_name}' does not have log file validation enabled.",
                risk="Without log file validation, an attacker who gains access to the S3 bucket can modify or delete log files without detection, destroying forensic evidence.",
                recommendation=f"Enable log file validation for trail '{trail_name}'.",
                remediation_cmd=f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation",
                remediation_effort="2 minutes",
                compliance=["CIS 3.2"],
            ))

        try:
            status = ct.get_trail_status(Name=trail_arn)
            if not status.get("IsLogging", False):
                result.add_finding(CloudFinding(
                    service="CloudTrail",
                    resource_id=trail_arn,
                    resource_name=trail_name,
                    severity="critical",
                    observation=f"CloudTrail '{trail_name}' exists but logging is disabled.",
                    risk="The trail is configured but not recording. All API activity is going unlogged. This is equivalent to having no audit trail.",
                    recommendation=f"Start logging on trail '{trail_name}' immediately.",
                    remediation_cmd=f"aws cloudtrail start-logging --name {trail_name}",
                    remediation_effort="2 minutes",
                    compliance=["CIS 3.1"],
                ))
        except Exception as e:
            if verbose:
                print(f"  Trail status check error for {trail_name}: {e}")

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(trails)} trails, {new_findings} findings")
