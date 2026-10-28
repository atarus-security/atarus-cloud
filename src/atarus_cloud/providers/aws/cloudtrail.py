from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.providers.aws.common import q, region_of
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS CloudTrail coverage of one region.

    describe_trails in a region returns the trails homed there plus shadow copies
    of multi-region trails homed elsewhere. A region with no trail at all gets a
    finding. Per-trail settings are checked only in the trail's home region, so a
    multi-region trail is reported once rather than once per region.
    """

    ct = session.client("cloudtrail")
    region = region_of(session)
    cov = result.recorder("cloudtrail", "CloudTrail", region)
    findings_before = len(result.findings)

    try:
        trails = ct.describe_trails()["trailList"]
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot describe trails: {e}")

    if not trails:
        result.add_finding(CloudFinding(
            service="CloudTrail",
            resource_id=f"cloudtrail/{region}",
            resource_name=f"CloudTrail ({region})",
            severity="critical",
            observation=f"No CloudTrail trail covers region {region}.",
            risk="Without CloudTrail, there is no audit log of API activity in this region. An attacker can create resources, modify configurations, exfiltrate data, and delete evidence with no record of their actions.",
            recommendation="Create a multi-region CloudTrail trail with S3 delivery and log file validation enabled.",
            remediation_cmd="aws cloudtrail create-trail --name atarus-audit-trail --s3-bucket-name YOUR-LOG-BUCKET --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name atarus-audit-trail",
            remediation_effort="15 minutes",
            compliance=["CIS 3.1"],
        ))
        cov.checked("a trail covers this region", "none")
        cov.checked("multi-region logging", "no trails homed here")
        cov.checked("log file validation", "no trails homed here")
        cov.checked("logging status", "no trails homed here")
        new_findings = len(result.findings) - findings_before
        return ModuleResult(success=True, message=f"{new_findings} findings")

    cov.checked("a trail covers this region", f"{len(trails)} trails visible")

    home_trails = [t for t in trails if not t.get("HomeRegion") or t.get("HomeRegion") == region]
    status_ok = 0

    for trail in home_trails:
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
                remediation_cmd=f"aws cloudtrail update-trail --name {q(trail_name)} --is-multi-region-trail",
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
                remediation_cmd=f"aws cloudtrail update-trail --name {q(trail_name)} --enable-log-file-validation",
                remediation_effort="2 minutes",
                compliance=["CIS 3.2"],
            ))

        try:
            status = ct.get_trail_status(Name=trail_arn or trail_name)
            if not status.get("IsLogging", False):
                result.add_finding(CloudFinding(
                    service="CloudTrail",
                    resource_id=trail_arn,
                    resource_name=trail_name,
                    severity="critical",
                    observation=f"CloudTrail '{trail_name}' exists but logging is disabled.",
                    risk="The trail is configured but not recording. All API activity is going unlogged. This is equivalent to having no audit trail.",
                    recommendation=f"Start logging on trail '{trail_name}' immediately.",
                    remediation_cmd=f"aws cloudtrail start-logging --name {q(trail_name)}",
                    remediation_effort="2 minutes",
                    compliance=["CIS 3.1"],
                ))
            status_ok += 1
        except Exception as e:
            cov.not_run(f"logging status ({trail_name})", e)

    homed = f"{len(home_trails)} trails homed here"
    cov.checked("multi-region logging", homed)
    cov.checked("log file validation", homed)
    if status_ok == len(home_trails):
        cov.checked("logging status", homed)
    elif status_ok:
        cov.checked("logging status", f"{status_ok} of {len(home_trails)} trails; the rest are listed as not run")

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(trails)} trails, {new_findings} findings")
