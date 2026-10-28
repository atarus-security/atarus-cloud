from atarus_cloud.models import AuditResult, CloudFinding, SUBSCRIPTION
from atarus_cloud.providers.azure.common import q, resource_group_of, sdk_missing
from atarus_cloud.runner import ModuleResult


def _client(credential, subscription_id):
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    return CosmosDBManagementClient(credential, subscription_id)


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure Cosmos DB accounts"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    cov = result.recorder("cosmosdb", "CosmosDB", SUBSCRIPTION)
    findings_before = len(result.findings)

    try:
        client = _client(credential, subscription_id)
        accounts = list(client.database_accounts.list())
    except ImportError as e:
        return ModuleResult(success=False, message=sdk_missing(e))
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list Cosmos DB accounts: {e}")

    for acct in accounts:
        name = acct.name
        resource_id = acct.id
        rg = resource_group_of(resource_id)

        _check_public_network_access(acct, name, resource_id, result)
        _check_firewall(acct, name, resource_id, result)
        _check_local_auth(acct, name, resource_id, rg, result)
        _check_automatic_failover(acct, name, resource_id, rg, result)

    count = f"{len(accounts)} Cosmos DB accounts"
    for check in ("public network access without restrictions", "0.0.0.0 firewall rule",
                  "local key-based authentication", "automatic failover"):
        cov.checked(check, count)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(accounts)} Cosmos DB accounts, {new_findings} findings")


def _rg_arg(rg):
    return q(rg) if rg else "<RG>"


def _check_public_network_access(acct, name, resource_id, result):
    public_access = getattr(acct, "public_network_access", "Enabled")
    if public_access == "Enabled":
        ip_rules = getattr(acct, "ip_rules", []) or []
        vnet_rules = getattr(acct, "virtual_network_rules", []) or []

        if not ip_rules and not vnet_rules:
            result.add_finding(CloudFinding(
                service="CosmosDB",
                resource_id=resource_id,
                resource_name=name,
                severity="high",
                observation=f"Cosmos DB account '{name}' allows public network access with no IP or VNet restrictions.",
                risk="The database is reachable from any IP on the internet. Attackers scan for exposed Cosmos DB endpoints and attempt to exploit leaked connection strings, which are common in source code leaks and misconfigured CI/CD pipelines.",
                recommendation=f"Configure IP firewall rules or use private endpoints for '{name}'.",
                remediation_cmd="# Configure via portal: Cosmos DB > Networking > Selected networks",
                remediation_effort="30 minutes",
                provider="azure",
                compliance=["CIS Azure 4.5.1"],
            ))


def _check_firewall(acct, name, resource_id, result):
    ip_rules = getattr(acct, "ip_rules", []) or []
    for rule in ip_rules:
        ip_range = getattr(rule, "ip_address_or_range", "")
        if ip_range == "0.0.0.0":
            result.add_finding(CloudFinding(
                service="CosmosDB",
                resource_id=resource_id,
                resource_name=name,
                severity="medium",
                observation=f"Cosmos DB account '{name}' allows access from all Azure datacenters (0.0.0.0 IP rule).",
                risk="Any Azure resource can connect to this Cosmos DB account. A compromised resource in any Azure tenant could attempt connections.",
                recommendation="Remove the 0.0.0.0 rule and restrict to specific source IP ranges.",
                remediation_cmd="# Update via portal: Cosmos DB > Networking > Firewall rules",
                remediation_effort="10 minutes",
                provider="azure",
            ))


def _check_local_auth(acct, name, resource_id, rg, result):
    disable_local_auth = getattr(acct, "disable_local_auth", False)
    if not disable_local_auth:
        result.add_finding(CloudFinding(
            service="CosmosDB",
            resource_id=resource_id,
            resource_name=name,
            severity="medium",
            observation=f"Cosmos DB account '{name}' allows local (key-based) authentication.",
            risk="Account keys provide full access to all data and bypass Entra ID controls. Leaked keys in code or logs are a common initial access vector. Keys also bypass MFA, conditional access, and audit trails.",
            recommendation=f"Disable local authentication on '{name}' and use Entra ID RBAC exclusively.",
            remediation_cmd=f"az cosmosdb update --name {q(name)} --resource-group {_rg_arg(rg)} --disable-local-auth true",
            remediation_effort="1 hour",
            provider="azure",
        ))


def _check_automatic_failover(acct, name, resource_id, rg, result):
    automatic_failover = getattr(acct, "enable_automatic_failover", False)
    if not automatic_failover:
        result.add_finding(CloudFinding(
            service="CosmosDB",
            resource_id=resource_id,
            resource_name=name,
            severity="low",
            observation=f"Cosmos DB account '{name}' does not have automatic failover enabled.",
            risk="If the primary region becomes unavailable due to outage or ransomware event, application downtime extends until manual failover. This is a resilience concern rather than a direct security vulnerability.",
            recommendation=f"Enable automatic failover on '{name}' for critical workloads.",
            remediation_cmd=f"az cosmosdb update --name {q(name)} --resource-group {_rg_arg(rg)} --enable-automatic-failover true",
            remediation_effort="5 minutes",
            provider="azure",
        ))
