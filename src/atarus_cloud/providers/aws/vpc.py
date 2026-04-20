from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS VPC configuration"""

    ec2 = session.client("ec2")
    findings_before = len(result.findings)

    _check_default_vpcs(ec2, result, verbose)
    _check_flow_logs(ec2, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"{new_findings} findings")


def _check_default_vpcs(ec2, result, verbose):
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]

            sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]

            if enis:
                result.add_finding(CloudFinding(
                    service="VPC",
                    resource_id=vpc_id,
                    resource_name=f"Default VPC ({vpc_id})",
                    severity="medium",
                    observation=f"Default VPC '{vpc_id}' is in use with {len(enis)} network interface(s) attached.",
                    risk="Default VPCs have permissive security group rules and public subnets by default. Resources deployed here may be unintentionally exposed to the internet.",
                    recommendation="Migrate resources to a custom VPC with properly configured private subnets and security groups.",
                    remediation_cmd=f"# Review resources in default VPC:\naws ec2 describe-network-interfaces --filters Name=vpc-id,Values={vpc_id} --query 'NetworkInterfaces[].Description'",
                    remediation_effort="2 hours",
                    compliance=["CIS 5.3"],
                ))
            else:
                result.add_finding(CloudFinding(
                    service="VPC",
                    resource_id=vpc_id,
                    resource_name=f"Default VPC ({vpc_id})",
                    severity="low",
                    observation=f"Default VPC '{vpc_id}' exists but has no resources attached.",
                    risk="Unused default VPCs are unnecessary attack surface. Accidental deployments to this VPC would use permissive default security groups.",
                    recommendation=f"Delete the unused default VPC '{vpc_id}' to prevent accidental use.",
                    remediation_cmd=f"# Delete default VPC (ensure no resources first):\n# aws ec2 delete-vpc --vpc-id {vpc_id}",
                    remediation_effort="10 minutes",
                    compliance=["CIS 5.3"],
                ))
    except Exception as e:
        if verbose:
            print(f"  Default VPC check error: {e}")


def _check_flow_logs(ec2, result, verbose):
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]

            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]

            if not flow_logs:
                name_tag = ""
                for tag in vpc.get("Tags", []):
                    if tag["Key"] == "Name":
                        name_tag = tag["Value"]
                display = name_tag or vpc_id

                result.add_finding(CloudFinding(
                    service="VPC",
                    resource_id=vpc_id,
                    resource_name=display,
                    severity="medium",
                    observation=f"VPC '{display}' ({vpc_id}) does not have flow logs enabled.",
                    risk="Without flow logs, network traffic patterns cannot be analyzed. Unauthorized access, data exfiltration, or lateral movement will not be visible in logs.",
                    recommendation=f"Enable VPC flow logs for '{vpc_id}' with delivery to CloudWatch Logs or S3.",
                    remediation_cmd=f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs/{vpc_id}",
                    remediation_effort="15 minutes",
                    compliance=["CIS 3.9"],
                ))
    except Exception as e:
        if verbose:
            print(f"  Flow logs check error: {e}")
