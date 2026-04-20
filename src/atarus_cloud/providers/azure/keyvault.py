from azure.mgmt.keyvault import KeyVaultManagementClient
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure Key Vault configuration"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    findings_before = len(result.findings)

    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(client.vaults.list())
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list key vaults: {e}")

    if not vaults:
        return ModuleResult(success=True, message="No key vaults found")

    for vault_ref in vaults:
        rg = vault_ref.id.split("/resourceGroups/")[1].split("/")[0]
        vault_name = vault_ref.name

        try:
            vault = client.vaults.get(rg, vault_name)
        except Exception as e:
            if verbose:
                print(f"  Cannot get vault {vault_name}: {e}")
            continue

        props = vault.properties
        vault_id = vault.id

        _check_soft_delete(props, vault_name, vault_id, result, verbose)
        _check_purge_protection(props, vault_name, vault_id, result, verbose)
        _check_public_access(props, vault_name, vault_id, result, verbose)
        _check_rbac(props, vault_name, vault_id, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(vaults)} key vaults, {new_findings} findings")


def _check_soft_delete(props, name, vault_id, result, verbose):
    if not getattr(props, "enable_soft_delete", True):
        result.add_finding(CloudFinding(
            service="KeyVault",
            resource_id=vault_id,
            resource_name=name,
            severity="high",
            observation=f"Key Vault '{name}' does not have soft delete enabled.",
            risk="Without soft delete, accidentally or maliciously deleted keys, secrets, and certificates are permanently gone. An attacker with vault delete permissions can destroy crypto material and cause permanent data loss for anything encrypted with those keys.",
            recommendation=f"Enable soft delete on Key Vault '{name}'. This cannot be disabled once enabled, which is the point.",
            remediation_cmd=f"az keyvault update --name {name} --enable-soft-delete true",
            remediation_effort="2 minutes",
            provider="azure",
            compliance=["CIS Azure 8.1"],
        ))


def _check_purge_protection(props, name, vault_id, result, verbose):
    if not getattr(props, "enable_purge_protection", False):
        result.add_finding(CloudFinding(
            service="KeyVault",
            resource_id=vault_id,
            resource_name=name,
            severity="medium",
            observation=f"Key Vault '{name}' does not have purge protection enabled.",
            risk="Without purge protection, soft-deleted keys and secrets can be permanently purged before the retention period expires. An attacker can delete and then purge material within the same session, bypassing the soft delete safety net.",
            recommendation=f"Enable purge protection on Key Vault '{name}'. This cannot be disabled once enabled.",
            remediation_cmd=f"az keyvault update --name {name} --enable-purge-protection true",
            remediation_effort="2 minutes",
            provider="azure",
            compliance=["CIS Azure 8.2"],
        ))


def _check_public_access(props, name, vault_id, result, verbose):
    public_access = getattr(props, "public_network_access", "Enabled")
    network_acls = getattr(props, "network_acls", None)

    default_action = "Allow"
    if network_acls:
        default_action = getattr(network_acls, "default_action", "Allow")

    if public_access == "Enabled" and default_action == "Allow":
        result.add_finding(CloudFinding(
            service="KeyVault",
            resource_id=vault_id,
            resource_name=name,
            severity="high",
            observation=f"Key Vault '{name}' is accessible from all networks with no firewall restrictions.",
            risk="The key vault's management endpoints are reachable from the public internet. If an attacker obtains vault access credentials through any means, they can connect directly from anywhere to exfiltrate secrets.",
            recommendation=f"Restrict '{name}' to specific virtual networks or IP ranges using firewall rules. Consider private endpoints for maximum isolation.",
            remediation_cmd=f"az keyvault update --name {name} --default-action Deny",
            remediation_effort="15 minutes",
            provider="azure",
            compliance=["CIS Azure 8.5"],
        ))


def _check_rbac(props, name, vault_id, result, verbose):
    uses_rbac = getattr(props, "enable_rbac_authorization", False)
    if not uses_rbac:
        result.add_finding(CloudFinding(
            service="KeyVault",
            resource_id=vault_id,
            resource_name=name,
            severity="low",
            observation=f"Key Vault '{name}' uses the legacy access policy permission model instead of Azure RBAC.",
            risk="Access policies are a separate permission system from the rest of Azure, creating operational complexity and audit gaps. RBAC provides unified permission management, PIM integration, and better conditional access support.",
            recommendation=f"Migrate '{name}' to use Azure RBAC for data plane authorization.",
            remediation_cmd=f"az keyvault update --name {name} --enable-rbac-authorization true",
            remediation_effort="30 minutes",
            provider="azure",
        ))
