#!/bin/bash
cd ~/atarus-cloud
source venv/bin/activate

echo "[*] Building v0.2.0: EC2, CloudTrail, RDS, VPC modules..."

# ============================================================
# providers/aws/ec2.py
# ============================================================
cat > src/atarus_cloud/providers/aws/ec2.py << 'PYEOF'
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS EC2 security groups and instances"""

    ec2 = session.client("ec2")
    findings_before = len(result.findings)

    _check_security_groups(ec2, result, verbose)
    _check_public_instances(ec2, result, verbose)
    _check_ebs_encryption(ec2, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"{new_findings} findings")


def _check_security_groups(ec2, result, verbose):
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        dangerous_ports = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            11211: "Memcached",
            23: "Telnet",
            21: "FTP",
            445: "SMB",
        }

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")

                    if cidr == "0.0.0.0/0":
                        if from_port == 0 and to_port == 65535:
                            result.add_finding(CloudFinding(
                                service="EC2",
                                resource_id=sg_id,
                                resource_name=sg_name,
                                severity="critical",
                                observation=f"Security group '{sg_name}' ({sg_id}) allows ALL traffic from the internet (0.0.0.0/0).",
                                risk="Any service running on instances using this security group is directly accessible from the internet. An attacker can scan all ports and attempt exploitation of any listening service.",
                                recommendation=f"Restrict inbound rules to specific ports and source IP ranges.",
                                remediation_cmd=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol all --cidr 0.0.0.0/0",
                                remediation_effort="10 minutes",
                                compliance=["CIS 5.2"],
                            ))
                        elif from_port in dangerous_ports:
                            port_name = dangerous_ports[from_port]
                            severity = "critical" if from_port in (22, 3389) else "high"
                            result.add_finding(CloudFinding(
                                service="EC2",
                                resource_id=sg_id,
                                resource_name=sg_name,
                                severity=severity,
                                observation=f"Security group '{sg_name}' ({sg_id}) allows {port_name} (port {from_port}) from the internet.",
                                risk=f"Port {from_port} ({port_name}) is accessible from any IP address. Attackers actively scan for open {port_name} ports and will attempt brute force attacks, credential stuffing, or exploitation of known vulnerabilities.",
                                recommendation=f"Restrict port {from_port} to specific IP ranges. Use a VPN or bastion host for administrative access.",
                                remediation_cmd=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {from_port} --cidr 0.0.0.0/0",
                                remediation_effort="10 minutes",
                                compliance=["CIS 5.2"],
                            ))

                for ipv6_range in rule.get("Ipv6Ranges", []):
                    cidr = ipv6_range.get("CidrIpv6", "")
                    if cidr == "::/0" and from_port in dangerous_ports:
                        port_name = dangerous_ports[from_port]
                        result.add_finding(CloudFinding(
                            service="EC2",
                            resource_id=sg_id,
                            resource_name=sg_name,
                            severity="high",
                            observation=f"Security group '{sg_name}' ({sg_id}) allows {port_name} (port {from_port}) from all IPv6 addresses.",
                            risk=f"IPv6 ::/0 opens port {from_port} to the entire IPv6 internet. This is often overlooked during security reviews.",
                            recommendation=f"Restrict IPv6 access for port {from_port} to specific ranges.",
                            remediation_cmd=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {from_port} --cidr ::/0",
                            remediation_effort="10 minutes",
                        ))
    except Exception as e:
        if verbose:
            print(f"  Security group check error: {e}")


def _check_public_instances(ec2, result, verbose):
    try:
        reservations = ec2.describe_instances()["Reservations"]
        for res in reservations:
            for instance in res["Instances"]:
                instance_id = instance["InstanceId"]
                state = instance["State"]["Name"]

                if state != "running":
                    continue

                public_ip = instance.get("PublicIpAddress", "")
                name_tag = ""
                for tag in instance.get("Tags", []):
                    if tag["Key"] == "Name":
                        name_tag = tag["Value"]

                display_name = name_tag or instance_id

                if public_ip:
                    result.add_finding(CloudFinding(
                        service="EC2",
                        resource_id=instance_id,
                        resource_name=display_name,
                        severity="medium",
                        observation=f"EC2 instance '{display_name}' ({instance_id}) has a public IP address: {public_ip}.",
                        risk=f"The instance is directly reachable from the internet at {public_ip}. Combined with permissive security groups, this increases the attack surface significantly.",
                        recommendation="Place the instance behind a load balancer or in a private subnet. Use a bastion host or VPN for access.",
                        remediation_cmd=f"# Review if public IP is necessary:\naws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[].Instances[].NetworkInterfaces[].Association.PublicIp'",
                        remediation_effort="30 minutes",
                    ))
    except Exception as e:
        if verbose:
            print(f"  Public instance check error: {e}")


def _check_ebs_encryption(ec2, result, verbose):
    try:
        encryption = ec2.get_ebs_encryption_by_default()
        if not encryption.get("EbsEncryptionByDefault", False):
            result.add_finding(CloudFinding(
                service="EC2",
                resource_id="ebs-default-encryption",
                resource_name="EBS default encryption",
                severity="medium",
                observation="EBS encryption by default is not enabled for this region.",
                risk="New EBS volumes created without explicit encryption will store data in plaintext. If a snapshot is shared or a volume is accessed through a misconfiguration, data is exposed.",
                recommendation="Enable EBS encryption by default for all regions.",
                remediation_cmd="aws ec2 enable-ebs-encryption-by-default",
                remediation_effort="2 minutes",
                compliance=["CIS 2.2.1"],
            ))
    except Exception as e:
        if verbose:
            print(f"  EBS encryption check error: {e}")
PYEOF

# ============================================================
# providers/aws/cloudtrail.py
# ============================================================
cat > src/atarus_cloud/providers/aws/cloudtrail.py << 'PYEOF'
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
PYEOF

# ============================================================
# providers/aws/rds.py
# ============================================================
cat > src/atarus_cloud/providers/aws/rds.py << 'PYEOF'
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
PYEOF

# ============================================================
# providers/aws/vpc.py
# ============================================================
cat > src/atarus_cloud/providers/aws/vpc.py << 'PYEOF'
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
PYEOF

# ============================================================
# cli.py - register new modules
# ============================================================
cat > src/atarus_cloud/cli.py << 'PYEOF'
import click
from rich.console import Console
from rich.table import Table
from atarus_cloud.runner import CloudRunner
from atarus_cloud.providers.aws import auth as aws_auth
from atarus_cloud.providers.aws import iam, s3, ec2, cloudtrail, rds, vpc
from atarus_cloud.reports import html, json_export, pdf, remediation

console = Console()

VERSION = "0.2.0"

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╔═╗╦  ╔═╗╦ ╦╔╦╗
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ║  ║  ║ ║║ ║ ║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╚═╝╩═╝╚═╝╚═╝═╩╝
   Atarus Offensive Security | v{VERSION}
"""

AWS_MODULES = [
    ("IAM audit", "iam", iam.run),
    ("S3 audit", "s3", s3.run),
    ("EC2 audit", "ec2", ec2.run),
    ("CloudTrail audit", "cloudtrail", cloudtrail.run),
    ("RDS audit", "rds", rds.run),
    ("VPC audit", "vpc", vpc.run),
]


@click.command()
@click.option("-p", "--provider", default="aws", type=click.Choice(["aws"]), help="Cloud provider")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--region", default="us-west-1", help="AWS region")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--format", "out_format", default="html", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--skip", default="", help="Comma-separated modules to skip")
@click.option("--only", default="", help="Comma-separated modules to run exclusively")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.version_option(version=VERSION, prog_name="atarus-cloud")
def main(provider, profile, region, output, out_format, verbose, skip, only, list_modules):
    """atarus-cloud: Cloud security misconfiguration scanner by Atarus Offensive Security"""

    if list_modules:
        table = Table(title="Available modules (AWS)")
        table.add_column("Key", style="bold cyan")
        table.add_column("Description")
        for name, key, _ in AWS_MODULES:
            table.add_row(key, name)
        console.print(table)
        return

    console.print(BANNER, style="bold red")

    if provider == "aws":
        console.print(f"[bold white]Authenticating to AWS...[/]")
        session, identity = aws_auth.get_session(profile=profile, region=region)
        account_id = identity["Account"]
        user_arn = identity["Arn"]
        console.print(f"[bold white]Account:[/] {account_id}")
        console.print(f"[bold white]Identity:[/] {user_arn}")
        console.print(f"[bold white]Region:[/] {region}")

        skip_list = [s.strip() for s in skip.split(",") if s.strip()] if skip else []
        only_list = [s.strip() for s in only.split(",") if s.strip()] if only else []

        runner = CloudRunner(
            provider="aws",
            session=session,
            regions=[region],
            verbose=verbose,
            skip=skip_list,
            only=only_list,
        )
        runner.result.account_id = account_id
        runner.result.account_alias = aws_auth.get_account_alias(session)

        for name, key, func in AWS_MODULES:
            runner.register(name, key, func)

        result = runner.run()

        if out_format in ("html", "all"):
            report_path = html.generate(result, output)
            console.print(f"\n[bold green]HTML report:[/] {report_path}")

        if out_format in ("json", "all"):
            json_path = json_export.generate(result, output)
            console.print(f"[bold green]JSON report:[/] {json_path}")

        if out_format in ("pdf", "all"):
            pdf_path = pdf.generate(result, output)
            console.print(f"[bold green]PDF report:[/] {pdf_path}")

        rem_path = remediation.generate(result, output)
        console.print(f"[bold green]Remediation script:[/] {rem_path}")


if __name__ == "__main__":
    main()
PYEOF

sed -i 's/version = "0.1.0"/version = "0.2.0"/' pyproject.toml
pip install -e . 2>&1 | tail -1

echo ""
echo "[+] v0.2.0 built. Test:"
echo "  atarus-cloud --list-modules"
echo "  atarus-cloud -p aws --format all -v"
