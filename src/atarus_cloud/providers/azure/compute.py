from atarus_cloud.models import AuditResult, CloudFinding, SUBSCRIPTION
from atarus_cloud.providers.azure.common import q, resource_group_of, sdk_missing
from atarus_cloud.runner import ModuleResult


def _client(credential, subscription_id):
    from azure.mgmt.compute import ComputeManagementClient
    return ComputeManagementClient(credential, subscription_id)


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure virtual machines"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    cov = result.recorder("compute", "Compute", SUBSCRIPTION)
    findings_before = len(result.findings)

    try:
        client = _client(credential, subscription_id)
        vms = list(client.virtual_machines.list_all())
    except ImportError as e:
        return ModuleResult(success=False, message=sdk_missing(e))
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list VMs: {e}")

    for vm in vms:
        _check_disk_encryption(vm, result)
        _check_managed_disks(vm, result)
        _check_boot_diagnostics(vm, result)

    count = f"{len(vms)} virtual machines"
    cov.checked("OS disk encryption settings", count)
    cov.checked("managed disks", count)
    cov.checked("boot diagnostics", count)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(vms)} VMs, {new_findings} findings")


def _check_disk_encryption(vm, result):
    storage_profile = vm.storage_profile
    if not storage_profile:
        return

    os_disk = storage_profile.os_disk
    if not os_disk:
        return

    encryption_settings = getattr(os_disk, "encryption_settings", None)
    if not encryption_settings or not getattr(encryption_settings, "enabled", False):
        result.add_finding(CloudFinding(
            service="Compute",
            resource_id=vm.id,
            resource_name=vm.name,
            severity="medium",
            observation=f"VM '{vm.name}' does not have Azure Disk Encryption (ADE) enabled on the OS disk.",
            risk="The OS disk is not encrypted with customer-managed keys. While Azure provides platform-level encryption by default, Azure Disk Encryption adds defense-in-depth for compliance and data protection.",
            recommendation=f"Enable Azure Disk Encryption for VM '{vm.name}'.",
            remediation_cmd="# Enable via portal: VM > Disks > Additional settings > Encryption",
            remediation_effort="30 minutes",
            provider="azure",
            compliance=["CIS Azure 7.2"],
        ))


def _check_managed_disks(vm, result):
    storage_profile = vm.storage_profile
    if not storage_profile:
        return

    os_disk = storage_profile.os_disk
    if not os_disk:
        return

    managed_disk = getattr(os_disk, "managed_disk", None)
    if not managed_disk:
        rg = resource_group_of(vm.id)
        rg_arg = q(rg) if rg else "<RG>"
        result.add_finding(CloudFinding(
            service="Compute",
            resource_id=vm.id,
            resource_name=vm.name,
            severity="medium",
            observation=f"VM '{vm.name}' uses unmanaged (blob-based) disks.",
            risk="Unmanaged disks are stored in a storage account you manage. They lack automatic replication guarantees, cannot use some modern Azure features, and require manual management of storage account security.",
            recommendation=f"Migrate VM '{vm.name}' to managed disks.",
            remediation_cmd=f"# Migration requires VM stop:\naz vm deallocate --name {q(vm.name)} --resource-group {rg_arg}\naz vm convert --name {q(vm.name)} --resource-group {rg_arg}",
            remediation_effort="1 hour",
            provider="azure",
            compliance=["CIS Azure 7.3"],
        ))


def _check_boot_diagnostics(vm, result):
    diag = getattr(vm, "diagnostics_profile", None)
    if not diag:
        return

    boot_diag = getattr(diag, "boot_diagnostics", None)
    if not boot_diag or not getattr(boot_diag, "enabled", False):
        result.add_finding(CloudFinding(
            service="Compute",
            resource_id=vm.id,
            resource_name=vm.name,
            severity="low",
            observation=f"VM '{vm.name}' does not have boot diagnostics enabled.",
            risk="Without boot diagnostics, troubleshooting VM boot failures or security incidents is significantly harder. You lose visibility into console output and serial logs.",
            recommendation=f"Enable boot diagnostics for VM '{vm.name}' with a managed storage account.",
            remediation_cmd="# Enable via portal: VM > Boot diagnostics > Settings",
            remediation_effort="5 minutes",
            provider="azure",
        ))
