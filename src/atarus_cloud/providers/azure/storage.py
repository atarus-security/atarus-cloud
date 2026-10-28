from atarus_cloud.models import AuditResult, CloudFinding, SUBSCRIPTION
from atarus_cloud.providers.azure.common import q, resource_group_of, sdk_missing
from atarus_cloud.runner import ModuleResult


def _client(credential, subscription_id):
    from azure.mgmt.storage import StorageManagementClient
    return StorageManagementClient(credential, subscription_id)


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure storage accounts"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    cov = result.recorder("storage", "Storage", SUBSCRIPTION)

    try:
        client = _client(credential, subscription_id)
        accounts = list(client.storage_accounts.list())
    except ImportError as e:
        return ModuleResult(success=False, message=sdk_missing(e))
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list storage accounts: {e}")

    findings_before = len(result.findings)
    containers_ok = 0

    for acct in accounts:
        name = acct.name
        resource_id = acct.id
        rg = resource_group_of(resource_id)

        _check_https_only(acct, name, resource_id, result)
        _check_tls_version(acct, name, resource_id, result)
        _check_public_access(acct, name, resource_id, result)
        _check_blob_public_access(acct, name, resource_id, result)
        _check_encryption(acct, name, resource_id, result)

        try:
            containers = list(client.blob_containers.list(rg, name))
            for c in containers:
                if c.public_access and c.public_access != "None":
                    result.add_finding(CloudFinding(
                        service="Storage",
                        resource_id=f"{resource_id}/blobServices/default/containers/{c.name}",
                        resource_name=f"{name}/{c.name}",
                        severity="critical",
                        observation=f"Blob container '{c.name}' in storage account '{name}' allows anonymous public access ({c.public_access}).",
                        risk="Any unauthenticated user on the internet can list and download all objects in this container. If any data has been uploaded, it is publicly exposed.",
                        recommendation=f"Disable public access on container '{c.name}'.",
                        remediation_cmd=f"az storage container set-permission --name {q(c.name)} --account-name {q(name)} --public-access off",
                        remediation_effort="2 minutes",
                        provider="azure",
                        compliance=["CIS Azure 3.7"],
                    ))
            containers_ok += 1
        except Exception as e:
            cov.not_run(f"public blob containers ({name})", e)

    count = f"{len(accounts)} storage accounts"
    for check in ("secure transfer required", "minimum TLS version", "network default action",
                  "account-level blob public access", "blob encryption"):
        cov.checked(check, count)
    if containers_ok == len(accounts):
        cov.checked("public blob containers", count)
    elif containers_ok:
        cov.checked("public blob containers", f"{containers_ok} of {len(accounts)} accounts; the rest are listed as not run")

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(accounts)} storage accounts, {new_findings} findings")


def _check_https_only(acct, name, resource_id, result):
    if not getattr(acct, "enable_https_traffic_only", True):
        result.add_finding(CloudFinding(
            service="Storage",
            resource_id=resource_id,
            resource_name=name,
            severity="high",
            observation=f"Storage account '{name}' allows HTTP traffic (secure transfer not required).",
            risk="Data and access keys can be transmitted in cleartext over HTTP. Attackers on the network path can intercept credentials and exfiltrate data without any authentication bypass.",
            recommendation=f"Enable 'Secure transfer required' on storage account '{name}'.",
            remediation_cmd=f"az storage account update --name {q(name)} --https-only true",
            remediation_effort="2 minutes",
            provider="azure",
            compliance=["CIS Azure 3.1"],
        ))


def _check_tls_version(acct, name, resource_id, result):
    tls = getattr(acct, "minimum_tls_version", None)
    if tls and tls != "TLS1_2" and tls != "TLS1_3":
        result.add_finding(CloudFinding(
            service="Storage",
            resource_id=resource_id,
            resource_name=name,
            severity="medium",
            observation=f"Storage account '{name}' accepts connections using outdated TLS version ({tls}).",
            risk="TLS 1.0 and 1.1 contain known cryptographic weaknesses. Attackers can downgrade connections and exploit protocol vulnerabilities to decrypt traffic.",
            recommendation=f"Set minimum TLS version to 1.2 or higher on '{name}'.",
            remediation_cmd=f"az storage account update --name {q(name)} --min-tls-version TLS1_2",
            remediation_effort="2 minutes",
            provider="azure",
            compliance=["CIS Azure 3.15"],
        ))


def _check_public_access(acct, name, resource_id, result):
    public_access = getattr(acct, "public_network_access", None)
    if public_access == "Enabled":
        network_rules = getattr(acct, "network_rule_set", None)
        default_action = getattr(network_rules, "default_action", "Allow") if network_rules else "Allow"

        if default_action == "Allow":
            result.add_finding(CloudFinding(
                service="Storage",
                resource_id=resource_id,
                resource_name=name,
                severity="high",
                observation=f"Storage account '{name}' is reachable from any network with no firewall restrictions.",
                risk="The storage account is accessible from the public internet. Combined with any key leakage or misconfiguration, this enables direct data exfiltration from anywhere.",
                recommendation=f"Enable firewall rules and restrict access to specific IP ranges or virtual networks for '{name}'.",
                remediation_cmd=f"az storage account update --name {q(name)} --default-action Deny",
                remediation_effort="15 minutes",
                provider="azure",
                compliance=["CIS Azure 3.6"],
            ))


def _check_blob_public_access(acct, name, resource_id, result):
    allow_blob_public = getattr(acct, "allow_blob_public_access", True)
    if allow_blob_public:
        result.add_finding(CloudFinding(
            service="Storage",
            resource_id=resource_id,
            resource_name=name,
            severity="medium",
            observation=f"Storage account '{name}' allows anonymous public access to blob containers.",
            risk="Even if no container is currently public, this setting allows any container owner to make data public without further authorization. A single misconfigured container exposes all its data.",
            recommendation=f"Disable blob anonymous access at the account level for '{name}'.",
            remediation_cmd=f"az storage account update --name {q(name)} --allow-blob-public-access false",
            remediation_effort="2 minutes",
            provider="azure",
            compliance=["CIS Azure 3.7"],
        ))


def _check_encryption(acct, name, resource_id, result):
    encryption = getattr(acct, "encryption", None)
    if encryption:
        services = getattr(encryption, "services", None)
        if services:
            blob_enc = getattr(services, "blob", None)
            if blob_enc and not getattr(blob_enc, "enabled", True):
                result.add_finding(CloudFinding(
                    service="Storage",
                    resource_id=resource_id,
                    resource_name=name,
                    severity="high",
                    observation=f"Storage account '{name}' does not have blob encryption enabled.",
                    risk="Blob data is stored unencrypted. Physical access to underlying storage or a snapshot leak exposes all data in plaintext.",
                    recommendation=f"Enable Microsoft-managed encryption for blobs on '{name}'.",
                    remediation_cmd="# Encryption settings are configured at account creation. Review via portal.",
                    remediation_effort="1 hour",
                    provider="azure",
                    compliance=["CIS Azure 3.2"],
                ))
