"""
Compliance framework mapping.
Groups findings by CIS AWS, CIS Azure, and NIST 800-53 controls.
"""
from dataclasses import dataclass, field
from atarus_cloud.models import AuditResult


CONTROL_LIBRARY = {
    # CIS AWS Foundations Benchmark 2.0
    "CIS 1.5": {"framework": "CIS AWS", "title": "Ensure MFA is enabled for the root account", "category": "Identity and Access Management"},
    "CIS 1.8": {"framework": "CIS AWS", "title": "Ensure IAM password policy requires minimum length and complexity", "category": "Identity and Access Management"},
    "CIS 1.10": {"framework": "CIS AWS", "title": "Ensure MFA is enabled for all IAM users with console passwords", "category": "Identity and Access Management"},
    "CIS 1.12": {"framework": "CIS AWS", "title": "Ensure credentials unused for 90 days are disabled", "category": "Identity and Access Management"},
    "CIS 1.14": {"framework": "CIS AWS", "title": "Ensure access keys are rotated every 90 days or less", "category": "Identity and Access Management"},
    "CIS 1.16": {"framework": "CIS AWS", "title": "Ensure IAM policies are attached only to groups or roles", "category": "Identity and Access Management"},
    "CIS 2.1.1": {"framework": "CIS AWS", "title": "Ensure all S3 buckets employ encryption at rest", "category": "Storage"},
    "CIS 2.1.3": {"framework": "CIS AWS", "title": "Ensure MFA delete is enabled on S3 buckets", "category": "Storage"},
    "CIS 2.1.4": {"framework": "CIS AWS", "title": "Ensure S3 bucket access logging is enabled", "category": "Storage"},
    "CIS 2.1.5": {"framework": "CIS AWS", "title": "Ensure S3 Block Public Access is enabled at the bucket level", "category": "Storage"},
    "CIS 2.2.1": {"framework": "CIS AWS", "title": "Ensure EBS volume encryption is enabled", "category": "Storage"},
    "CIS 2.3.1": {"framework": "CIS AWS", "title": "Ensure RDS instances have encryption at rest enabled", "category": "Storage"},
    "CIS 2.8": {"framework": "CIS AWS", "title": "Ensure rotation for customer-created KMS keys is enabled", "category": "Storage"},
    "CIS 3.1": {"framework": "CIS AWS", "title": "Ensure CloudTrail is enabled in all regions", "category": "Logging"},
    "CIS 3.2": {"framework": "CIS AWS", "title": "Ensure CloudTrail log file validation is enabled", "category": "Logging"},
    "CIS 3.9": {"framework": "CIS AWS", "title": "Ensure VPC flow logging is enabled in all VPCs", "category": "Logging"},
    "CIS 5.2": {"framework": "CIS AWS", "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports", "category": "Networking"},
    "CIS 5.3": {"framework": "CIS AWS", "title": "Ensure the default security group of every VPC restricts all traffic", "category": "Networking"},

    # CIS Azure Foundations Benchmark 2.0
    "CIS Azure 1.22": {"framework": "CIS Azure", "title": "Ensure that 'Owners' custom role assignments are limited", "category": "Identity and Access Management"},
    "CIS Azure 1.23": {"framework": "CIS Azure", "title": "Ensure that no custom subscription administrator roles exist", "category": "Identity and Access Management"},
    "CIS Azure 3.1": {"framework": "CIS Azure", "title": "Ensure that 'Secure transfer required' is set to 'Enabled'", "category": "Storage"},
    "CIS Azure 3.2": {"framework": "CIS Azure", "title": "Ensure that storage account encryption is enabled", "category": "Storage"},
    "CIS Azure 3.6": {"framework": "CIS Azure", "title": "Ensure default network access rule for Storage Accounts is set to deny", "category": "Storage"},
    "CIS Azure 3.7": {"framework": "CIS Azure", "title": "Ensure 'Public access level' is set to Private for blob containers", "category": "Storage"},
    "CIS Azure 3.15": {"framework": "CIS Azure", "title": "Ensure the Minimum TLS version for storage is set to Version 1.2", "category": "Storage"},
    "CIS Azure 6.1": {"framework": "CIS Azure", "title": "Ensure RDP access from the Internet is restricted", "category": "Networking"},
    "CIS Azure 6.2": {"framework": "CIS Azure", "title": "Ensure SSH access from the Internet is restricted", "category": "Networking"},
    "CIS Azure 7.2": {"framework": "CIS Azure", "title": "Ensure Azure Disk Encryption is enabled on VMs", "category": "Compute"},
    "CIS Azure 7.3": {"framework": "CIS Azure", "title": "Ensure only managed disks are used for VMs", "category": "Compute"},
    "CIS Azure 4.1.1": {"framework": "CIS Azure", "title": "Ensure public network access is disabled for SQL servers", "category": "Databases"},
    "CIS Azure 4.1.2": {"framework": "CIS Azure", "title": "Ensure SQL server firewall rules do not allow 0.0.0.0/0", "category": "Databases"},
    "CIS Azure 4.1.3": {"framework": "CIS Azure", "title": "Ensure 'Allow Azure services' is disabled for SQL servers", "category": "Databases"},
    "CIS Azure 4.1.4": {"framework": "CIS Azure", "title": "Ensure minimum TLS version for SQL servers is 1.2", "category": "Databases"},
    "CIS Azure 4.1.5": {"framework": "CIS Azure", "title": "Ensure Entra ID admin is configured for SQL servers", "category": "Databases"},
    "CIS Azure 4.1.6": {"framework": "CIS Azure", "title": "Ensure SQL auditing is enabled", "category": "Databases"},
    "CIS Azure 4.5.1": {"framework": "CIS Azure", "title": "Ensure Cosmos DB network access is restricted", "category": "Databases"},
    "CIS Azure 8.1": {"framework": "CIS Azure", "title": "Ensure Key Vault soft delete is enabled", "category": "Key Vault"},
    "CIS Azure 8.2": {"framework": "CIS Azure", "title": "Ensure Key Vault purge protection is enabled", "category": "Key Vault"},
    "CIS Azure 8.5": {"framework": "CIS Azure", "title": "Ensure Key Vault network access is restricted", "category": "Key Vault"},


    # NIST 800-53 Rev 5 (applicable to both AWS and Azure)
    "NIST AC-2": {"framework": "NIST 800-53", "title": "Account Management", "category": "Access Control"},
    "NIST AC-3": {"framework": "NIST 800-53", "title": "Access Enforcement", "category": "Access Control"},
    "NIST AC-6": {"framework": "NIST 800-53", "title": "Least Privilege", "category": "Access Control"},
    "NIST AU-2": {"framework": "NIST 800-53", "title": "Event Logging", "category": "Audit and Accountability"},
    "NIST AU-3": {"framework": "NIST 800-53", "title": "Content of Audit Records", "category": "Audit and Accountability"},
    "NIST AU-9": {"framework": "NIST 800-53", "title": "Protection of Audit Information", "category": "Audit and Accountability"},
    "NIST AU-12": {"framework": "NIST 800-53", "title": "Audit Record Generation", "category": "Audit and Accountability"},
    "NIST IA-2": {"framework": "NIST 800-53", "title": "Identification and Authentication", "category": "Identification and Authentication"},
    "NIST IA-5": {"framework": "NIST 800-53", "title": "Authenticator Management", "category": "Identification and Authentication"},
    "NIST SC-7": {"framework": "NIST 800-53", "title": "Boundary Protection", "category": "System and Communications Protection"},
    "NIST SC-8": {"framework": "NIST 800-53", "title": "Transmission Confidentiality and Integrity", "category": "System and Communications Protection"},
    "NIST SC-12": {"framework": "NIST 800-53", "title": "Cryptographic Key Establishment and Management", "category": "System and Communications Protection"},
    "NIST SC-28": {"framework": "NIST 800-53", "title": "Protection of Information at Rest", "category": "System and Communications Protection"},
    "NIST SI-4": {"framework": "NIST 800-53", "title": "System Monitoring", "category": "System and Information Integrity"},
}


CIS_TO_NIST = {
    "CIS 1.5": ["NIST IA-2", "NIST AC-2"],
    "CIS 1.8": ["NIST IA-5"],
    "CIS 1.10": ["NIST IA-2", "NIST AC-2"],
    "CIS 1.12": ["NIST AC-2"],
    "CIS 1.14": ["NIST IA-5", "NIST AC-2"],
    "CIS 1.16": ["NIST AC-6"],
    "CIS 2.1.1": ["NIST SC-28"],
    "CIS 2.1.3": ["NIST SC-28"],
    "CIS 2.1.4": ["NIST AU-2", "NIST AU-12"],
    "CIS 2.1.5": ["NIST AC-3", "NIST SC-7"],
    "CIS 2.2.1": ["NIST SC-28"],
    "CIS 2.3.1": ["NIST SC-28"],
    "CIS 2.8": ["NIST SC-12"],
    "CIS 3.1": ["NIST AU-2", "NIST AU-12"],
    "CIS 3.2": ["NIST AU-9"],
    "CIS 3.9": ["NIST SI-4", "NIST AU-2"],
    "CIS 5.2": ["NIST SC-7", "NIST AC-3"],
    "CIS 5.3": ["NIST SC-7"],
    # Azure CIS to NIST
    "CIS Azure 1.22": ["NIST AC-6"],
    "CIS Azure 1.23": ["NIST AC-6", "NIST AC-2"],
    "CIS Azure 3.1": ["NIST SC-8"],
    "CIS Azure 3.2": ["NIST SC-28"],
    "CIS Azure 3.6": ["NIST SC-7", "NIST AC-3"],
    "CIS Azure 3.7": ["NIST AC-3", "NIST SC-7"],
    "CIS Azure 3.15": ["NIST SC-8"],
    "CIS Azure 6.1": ["NIST SC-7", "NIST AC-3"],
    "CIS Azure 6.2": ["NIST SC-7", "NIST AC-3"],
    "CIS Azure 7.2": ["NIST SC-28"],
    "CIS Azure 7.3": ["NIST SC-28"],
    "CIS Azure 4.1.1": ["NIST SC-7", "NIST AC-3"],
    "CIS Azure 4.1.2": ["NIST SC-7"],
    "CIS Azure 4.1.3": ["NIST SC-7", "NIST AC-3"],
    "CIS Azure 4.1.4": ["NIST SC-8"],
    "CIS Azure 4.1.5": ["NIST IA-2", "NIST AC-2"],
    "CIS Azure 4.1.6": ["NIST AU-2", "NIST AU-12"],
    "CIS Azure 4.5.1": ["NIST SC-7"],
    "CIS Azure 8.1": ["NIST SC-12"],
    "CIS Azure 8.2": ["NIST SC-12"],
    "CIS Azure 8.5": ["NIST SC-7", "NIST AC-3"],

}


@dataclass
class ControlResult:
    control_id: str
    framework: str
    title: str
    category: str
    status: str
    findings: list = field(default_factory=list)


def analyze(result: AuditResult) -> dict:
    finding_to_controls = {}
    for f in result.findings:
        expanded = set(f.compliance)
        for cis in list(f.compliance):
            if cis in CIS_TO_NIST:
                expanded.update(CIS_TO_NIST[cis])
        finding_to_controls[id(f)] = list(expanded)

    controls_failed = {}
    for f in result.findings:
        for control in finding_to_controls[id(f)]:
            if control not in controls_failed:
                controls_failed[control] = []
            controls_failed[control].append(f)

    all_controls = {}
    for control_id, meta in CONTROL_LIBRARY.items():
        status = "fail" if control_id in controls_failed else "not_checked"
        all_controls[control_id] = ControlResult(
            control_id=control_id,
            framework=meta["framework"],
            title=meta["title"],
            category=meta["category"],
            status=status,
            findings=controls_failed.get(control_id, []),
        )

    # Filter by provider-relevant frameworks
    provider = result.provider
    if provider == "aws":
        relevant_cis_framework = "CIS AWS"
    elif provider == "azure":
        relevant_cis_framework = "CIS Azure"
    else:
        relevant_cis_framework = None

    cis_controls = [c for c in all_controls.values() if c.framework == relevant_cis_framework] if relevant_cis_framework else []
    nist_controls = [c for c in all_controls.values() if c.framework == "NIST 800-53"]

    cis_failed = [c for c in cis_controls if c.status == "fail"]
    nist_failed = [c for c in nist_controls if c.status == "fail"]

    cis_by_category = {}
    for c in cis_failed:
        cis_by_category.setdefault(c.category, []).append(c)

    nist_by_category = {}
    for c in nist_failed:
        nist_by_category.setdefault(c.category, []).append(c)

    return {
        "cis_framework_name": relevant_cis_framework or "CIS",
        "cis_total": len(cis_controls),
        "cis_failed": len(cis_failed),
        "cis_by_category": cis_by_category,
        "nist_total": len(nist_controls),
        "nist_failed": len(nist_failed),
        "nist_by_category": nist_by_category,
        "all_controls": all_controls,
        "finding_controls": finding_to_controls,
    }
