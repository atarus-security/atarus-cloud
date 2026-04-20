"""
Compliance framework mapping.
Groups findings by CIS AWS Foundations Benchmark and NIST 800-53 controls.
"""
from dataclasses import dataclass, field
from atarus_cloud.models import AuditResult


CONTROL_LIBRARY = {
    # CIS AWS Foundations Benchmark 2.0
    "CIS 1.5": {
        "framework": "CIS",
        "title": "Ensure MFA is enabled for the root account",
        "category": "Identity and Access Management",
    },
    "CIS 1.8": {
        "framework": "CIS",
        "title": "Ensure IAM password policy requires minimum length and complexity",
        "category": "Identity and Access Management",
    },
    "CIS 1.10": {
        "framework": "CIS",
        "title": "Ensure MFA is enabled for all IAM users with console passwords",
        "category": "Identity and Access Management",
    },
    "CIS 1.12": {
        "framework": "CIS",
        "title": "Ensure credentials unused for 90 days are disabled",
        "category": "Identity and Access Management",
    },
    "CIS 1.14": {
        "framework": "CIS",
        "title": "Ensure access keys are rotated every 90 days or less",
        "category": "Identity and Access Management",
    },
    "CIS 1.16": {
        "framework": "CIS",
        "title": "Ensure IAM policies are attached only to groups or roles",
        "category": "Identity and Access Management",
    },
    "CIS 2.1.1": {
        "framework": "CIS",
        "title": "Ensure all S3 buckets employ encryption at rest",
        "category": "Storage",
    },
    "CIS 2.1.3": {
        "framework": "CIS",
        "title": "Ensure MFA delete is enabled on S3 buckets",
        "category": "Storage",
    },
    "CIS 2.1.4": {
        "framework": "CIS",
        "title": "Ensure S3 bucket access logging is enabled",
        "category": "Storage",
    },
    "CIS 2.1.5": {
        "framework": "CIS",
        "title": "Ensure S3 Block Public Access is enabled at the bucket level",
        "category": "Storage",
    },
    "CIS 2.2.1": {
        "framework": "CIS",
        "title": "Ensure EBS volume encryption is enabled",
        "category": "Storage",
    },
    "CIS 2.3.1": {
        "framework": "CIS",
        "title": "Ensure RDS instances have encryption at rest enabled",
        "category": "Storage",
    },
    "CIS 2.8": {
        "framework": "CIS",
        "title": "Ensure rotation for customer-created KMS keys is enabled",
        "category": "Storage",
    },
    "CIS 3.1": {
        "framework": "CIS",
        "title": "Ensure CloudTrail is enabled in all regions",
        "category": "Logging",
    },
    "CIS 3.2": {
        "framework": "CIS",
        "title": "Ensure CloudTrail log file validation is enabled",
        "category": "Logging",
    },
    "CIS 3.9": {
        "framework": "CIS",
        "title": "Ensure VPC flow logging is enabled in all VPCs",
        "category": "Logging",
    },
    "CIS 5.2": {
        "framework": "CIS",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports",
        "category": "Networking",
    },
    "CIS 5.3": {
        "framework": "CIS",
        "title": "Ensure the default security group of every VPC restricts all traffic",
        "category": "Networking",
    },

    # NIST 800-53 Rev 5
    "NIST AC-2": {
        "framework": "NIST 800-53",
        "title": "Account Management",
        "category": "Access Control",
    },
    "NIST AC-3": {
        "framework": "NIST 800-53",
        "title": "Access Enforcement",
        "category": "Access Control",
    },
    "NIST AC-6": {
        "framework": "NIST 800-53",
        "title": "Least Privilege",
        "category": "Access Control",
    },
    "NIST AU-2": {
        "framework": "NIST 800-53",
        "title": "Event Logging",
        "category": "Audit and Accountability",
    },
    "NIST AU-3": {
        "framework": "NIST 800-53",
        "title": "Content of Audit Records",
        "category": "Audit and Accountability",
    },
    "NIST AU-9": {
        "framework": "NIST 800-53",
        "title": "Protection of Audit Information",
        "category": "Audit and Accountability",
    },
    "NIST AU-12": {
        "framework": "NIST 800-53",
        "title": "Audit Record Generation",
        "category": "Audit and Accountability",
    },
    "NIST IA-2": {
        "framework": "NIST 800-53",
        "title": "Identification and Authentication",
        "category": "Identification and Authentication",
    },
    "NIST IA-5": {
        "framework": "NIST 800-53",
        "title": "Authenticator Management",
        "category": "Identification and Authentication",
    },
    "NIST SC-7": {
        "framework": "NIST 800-53",
        "title": "Boundary Protection",
        "category": "System and Communications Protection",
    },
    "NIST SC-8": {
        "framework": "NIST 800-53",
        "title": "Transmission Confidentiality and Integrity",
        "category": "System and Communications Protection",
    },
    "NIST SC-12": {
        "framework": "NIST 800-53",
        "title": "Cryptographic Key Establishment and Management",
        "category": "System and Communications Protection",
    },
    "NIST SC-28": {
        "framework": "NIST 800-53",
        "title": "Protection of Information at Rest",
        "category": "System and Communications Protection",
    },
    "NIST SI-4": {
        "framework": "NIST 800-53",
        "title": "System Monitoring",
        "category": "System and Information Integrity",
    },
}


# Map CIS controls to related NIST controls
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
}


@dataclass
class ControlResult:
    """A compliance control and whether it failed"""
    control_id: str
    framework: str
    title: str
    category: str
    status: str  # "fail", "not_checked"
    findings: list = field(default_factory=list)


def analyze(result: AuditResult) -> dict:
    """Build compliance mapping from findings"""

    # Expand each finding's compliance list with related NIST controls
    finding_to_controls = {}
    for f in result.findings:
        expanded = set(f.compliance)
        for cis in list(f.compliance):
            if cis in CIS_TO_NIST:
                expanded.update(CIS_TO_NIST[cis])
        finding_to_controls[id(f)] = list(expanded)

    # Group findings by control
    controls_failed = {}
    for f in result.findings:
        for control in finding_to_controls[id(f)]:
            if control not in controls_failed:
                controls_failed[control] = []
            controls_failed[control].append(f)

    # Build control results for every control in the library
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

    # Stats by framework
    cis_controls = [c for c in all_controls.values() if c.framework == "CIS"]
    nist_controls = [c for c in all_controls.values() if c.framework == "NIST 800-53"]

    cis_failed = [c for c in cis_controls if c.status == "fail"]
    nist_failed = [c for c in nist_controls if c.status == "fail"]

    # Group failed controls by framework category for display
    cis_by_category = {}
    for c in cis_failed:
        cis_by_category.setdefault(c.category, []).append(c)

    nist_by_category = {}
    for c in nist_failed:
        nist_by_category.setdefault(c.category, []).append(c)

    return {
        "cis_total": len(cis_controls),
        "cis_failed": len(cis_failed),
        "cis_by_category": cis_by_category,
        "nist_total": len(nist_controls),
        "nist_failed": len(nist_failed),
        "nist_by_category": nist_by_category,
        "all_controls": all_controls,
        "finding_controls": finding_to_controls,
    }
