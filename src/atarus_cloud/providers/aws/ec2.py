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
