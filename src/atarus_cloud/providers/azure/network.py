from azure.mgmt.network import NetworkManagementClient
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


DANGEROUS_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    23: "Telnet", 21: "FTP", 445: "SMB",
}


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure network security groups and public IPs"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    findings_before = len(result.findings)

    try:
        client = NetworkManagementClient(credential, subscription_id)
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot create network client: {e}")

    try:
        nsgs = list(client.network_security_groups.list_all())
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list NSGs: {e}")

    for nsg in nsgs:
        _check_nsg_rules(nsg, result, verbose)

    try:
        public_ips = list(client.public_ip_addresses.list_all())
        if public_ips:
            for ip in public_ips:
                if ip.ip_address:
                    result.add_finding(CloudFinding(
                        service="Network",
                        resource_id=ip.id,
                        resource_name=ip.name,
                        severity="low",
                        observation=f"Public IP '{ip.name}' allocated: {ip.ip_address}.",
                        risk="Public IPs expand attack surface. Any resource attached to a public IP is reachable from the internet and subject to scanning, brute force, and targeted attacks.",
                        recommendation=f"Review if '{ip.name}' requires public exposure. Consider Azure Bastion or private endpoints as alternatives.",
                        remediation_cmd=f"# Review attached resource via portal: Public IP address > Associated resource",
                        remediation_effort="30 minutes",
                        provider="azure",
                    ))
    except Exception as e:
        if verbose:
            print(f"  Public IP check error: {e}")

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(nsgs)} NSGs, {new_findings} findings")


def _check_nsg_rules(nsg, result, verbose):
    for rule in (nsg.security_rules or []):
        if rule.access != "Allow" or rule.direction != "Inbound":
            continue

        source = rule.source_address_prefix or ""
        sources = rule.source_address_prefixes or []
        all_sources = [source] + list(sources)

        is_open_to_internet = any(
            s in ("*", "Internet", "0.0.0.0/0", "any", "Any") for s in all_sources if s
        )

        if not is_open_to_internet:
            continue

        dest_port = rule.destination_port_range or ""
        dest_ports = rule.destination_port_ranges or []

        all_ports = set()
        for pr in [dest_port] + list(dest_ports):
            if not pr:
                continue
            if pr == "*":
                all_ports.add("all")
            elif "-" in pr:
                try:
                    start, end = [int(x) for x in pr.split("-")]
                    for p in range(start, end + 1):
                        all_ports.add(p)
                except ValueError:
                    pass
            else:
                try:
                    all_ports.add(int(pr))
                except ValueError:
                    pass

        if "all" in all_ports:
            result.add_finding(CloudFinding(
                service="Network",
                resource_id=nsg.id,
                resource_name=nsg.name,
                severity="critical",
                observation=f"NSG '{nsg.name}' rule '{rule.name}' allows ALL inbound traffic from the internet.",
                risk="Any service on any port is reachable from the internet. Attackers can scan every port and attempt exploitation of any listening service.",
                recommendation=f"Restrict NSG rule '{rule.name}' to specific ports and source IP ranges.",
                remediation_cmd=f"# Review NSG rules via portal: Network security group > {nsg.name}",
                remediation_effort="15 minutes",
                provider="azure",
                compliance=["CIS Azure 6.1"],
            ))
            continue

        for port in all_ports:
            if port in DANGEROUS_PORTS:
                port_name = DANGEROUS_PORTS[port]
                severity = "critical" if port in (22, 3389) else "high"
                result.add_finding(CloudFinding(
                    service="Network",
                    resource_id=nsg.id,
                    resource_name=nsg.name,
                    severity=severity,
                    observation=f"NSG '{nsg.name}' rule '{rule.name}' allows {port_name} (port {port}) from the internet.",
                    risk=f"Port {port} ({port_name}) is accessible from any IP. Attackers actively scan and brute force these ports. Known CVEs in services listening on this port can lead to remote code execution.",
                    recommendation=f"Restrict port {port} to specific IP ranges. Use Azure Bastion for administrative access.",
                    remediation_cmd=f"# Update NSG rule via portal or:\naz network nsg rule update --resource-group <RG> --nsg-name {nsg.name} --name {rule.name} --source-address-prefixes <TRUSTED_IP>",
                    remediation_effort="10 minutes",
                    provider="azure",
                    compliance=["CIS Azure 6.1" if port == 22 else "CIS Azure 6.2"],
                ))
