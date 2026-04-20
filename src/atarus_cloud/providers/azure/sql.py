from azure.mgmt.sql import SqlManagementClient
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure SQL servers and databases"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    findings_before = len(result.findings)

    try:
        client = SqlManagementClient(credential, subscription_id)
        servers = list(client.servers.list())
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list SQL servers: {e}")

    if not servers:
        return ModuleResult(success=True, message="No SQL servers found")

    for server in servers:
        rg = server.id.split("/resourceGroups/")[1].split("/")[0]
        server_name = server.name
        server_id = server.id

        _check_public_network_access(server, server_name, server_id, result, verbose)
        _check_firewall_rules(client, rg, server_name, server_id, result, verbose)
        _check_tls_version(server, server_name, server_id, result, verbose)
        _check_ad_admin(client, rg, server_name, server_id, result, verbose)
        _check_auditing(client, rg, server_name, server_id, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(servers)} SQL servers, {new_findings} findings")


def _check_public_network_access(server, name, server_id, result, verbose):
    public_access = getattr(server, "public_network_access", "Enabled")
    if public_access == "Enabled":
        result.add_finding(CloudFinding(
            service="SQL",
            resource_id=server_id,
            resource_name=name,
            severity="high",
            observation=f"SQL server '{name}' allows public network access.",
            risk="Databases reachable from the public internet are prime targets for credential brute force, exploitation of database CVEs, and automated scanning tools. Any leak of connection strings or credentials becomes a direct data breach vector.",
            recommendation=f"Disable public network access for '{name}'. Use private endpoints for application connectivity.",
            remediation_cmd=f"az sql server update --name {name} --resource-group <RG> --enable-public-network false",
            remediation_effort="30 minutes",
            provider="azure",
            compliance=["CIS Azure 4.1.1"],
        ))


def _check_firewall_rules(client, rg, server_name, server_id, result, verbose):
    try:
        rules = list(client.firewall_rules.list_by_server(rg, server_name))
        for rule in rules:
            if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                result.add_finding(CloudFinding(
                    service="SQL",
                    resource_id=f"{server_id}/firewallRules/{rule.name}",
                    resource_name=f"{server_name}/{rule.name}",
                    severity="critical",
                    observation=f"SQL server '{server_name}' has a firewall rule '{rule.name}' allowing connections from 0.0.0.0/0 (entire internet).",
                    risk="Any IP on the internet can attempt to connect to this SQL server. Attackers scan for exposed SQL endpoints constantly. Combined with weak credentials or a credential leak, this is a direct data breach path.",
                    recommendation=f"Delete firewall rule '{rule.name}' and replace with specific IP ranges for known clients.",
                    remediation_cmd=f"az sql server firewall-rule delete --resource-group {rg} --server {server_name} --name {rule.name}",
                    remediation_effort="5 minutes",
                    provider="azure",
                    compliance=["CIS Azure 4.1.2"],
                ))
            elif rule.name == "AllowAllWindowsAzureIps" or (rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "0.0.0.0"):
                result.add_finding(CloudFinding(
                    service="SQL",
                    resource_id=f"{server_id}/firewallRules/{rule.name}",
                    resource_name=f"{server_name}/{rule.name}",
                    severity="medium",
                    observation=f"SQL server '{server_name}' allows access from all Azure services.",
                    risk="Any Azure resource in any subscription worldwide can connect to this SQL server. An attacker who gains access to any Azure tenant can attempt connections to this database.",
                    recommendation=f"Disable the 'Allow Azure services and resources' option. Use specific firewall rules or private endpoints.",
                    remediation_cmd=f"az sql server firewall-rule delete --resource-group {rg} --server {server_name} --name AllowAllWindowsAzureIps",
                    remediation_effort="10 minutes",
                    provider="azure",
                    compliance=["CIS Azure 4.1.3"],
                ))
    except Exception as e:
        if verbose:
            print(f"  Firewall rules check error for {server_name}: {e}")


def _check_tls_version(server, name, server_id, result, verbose):
    tls = getattr(server, "minimal_tls_version", None)
    if tls and tls not in ("1.2", "1.3"):
        result.add_finding(CloudFinding(
            service="SQL",
            resource_id=server_id,
            resource_name=name,
            severity="medium",
            observation=f"SQL server '{name}' accepts connections using TLS {tls}.",
            risk="TLS 1.0 and 1.1 have known cryptographic weaknesses. Attackers can exploit these to downgrade connections and decrypt database traffic containing credentials and query results.",
            recommendation=f"Set minimum TLS version to 1.2 on '{name}'.",
            remediation_cmd=f"az sql server update --name {name} --resource-group <RG> --minimal-tls-version 1.2",
            remediation_effort="5 minutes",
            provider="azure",
            compliance=["CIS Azure 4.1.4"],
        ))


def _check_ad_admin(client, rg, server_name, server_id, result, verbose):
    try:
        admins = list(client.server_azure_ad_administrators.list_by_server(rg, server_name))
        if not admins:
            result.add_finding(CloudFinding(
                service="SQL",
                resource_id=server_id,
                resource_name=server_name,
                severity="medium",
                observation=f"SQL server '{server_name}' does not have an Entra ID (Azure AD) administrator configured.",
                risk="Without Entra ID authentication, the server relies only on SQL authentication (username/password). SQL auth bypasses Azure AD controls including MFA, conditional access, and centralized audit.",
                recommendation=f"Configure an Entra ID administrator for '{server_name}' to enable modern authentication.",
                remediation_cmd=f"az sql server ad-admin create --server {server_name} --resource-group {rg} --display-name <GROUP_NAME> --object-id <OBJECT_ID>",
                remediation_effort="15 minutes",
                provider="azure",
                compliance=["CIS Azure 4.1.5"],
            ))
    except Exception as e:
        if verbose:
            print(f"  AD admin check error for {server_name}: {e}")


def _check_auditing(client, rg, server_name, server_id, result, verbose):
    try:
        settings = client.server_blob_auditing_policies.get(rg, server_name)
        if getattr(settings, "state", "Disabled") != "Enabled":
            result.add_finding(CloudFinding(
                service="SQL",
                resource_id=server_id,
                resource_name=server_name,
                severity="high",
                observation=f"SQL server '{server_name}' does not have auditing enabled.",
                risk="Without auditing, there is no record of database access, queries, or administrative actions. A breach or insider threat would leave no forensic trail to support investigation or compliance.",
                recommendation=f"Enable auditing on '{server_name}' with log delivery to a Log Analytics workspace or storage account.",
                remediation_cmd=f"az sql server audit-policy update --resource-group {rg} --name {server_name} --state Enabled --storage-account <STORAGE_ACCOUNT>",
                remediation_effort="15 minutes",
                provider="azure",
                compliance=["CIS Azure 4.1.6"],
            ))
    except Exception as e:
        if verbose:
            print(f"  Auditing check error for {server_name}: {e}")
