"""
Attack path correlation engine.
Chains individual findings into realistic attack narratives.
"""
from dataclasses import dataclass, field
from atarus_cloud.models import AuditResult, CloudFinding


@dataclass
class AttackPath:
    """A chained attack narrative across multiple findings"""
    title: str
    severity: str
    narrative: str
    impact: str
    steps: list = field(default_factory=list)
    related_findings: list = field(default_factory=list)


def analyze(result: AuditResult) -> list:
    """Correlate findings into attack paths"""
    paths = []

    by_service = {}
    for f in result.findings:
        by_service.setdefault(f.service, []).append(f)

    paths.extend(_path_compromised_user(by_service))
    paths.extend(_path_exposed_infra_no_logging(by_service))
    paths.extend(_path_public_db_exposure(by_service))
    paths.extend(_path_credential_sprawl(by_service))
    paths.extend(_path_blind_environment(by_service))
    paths.extend(_path_backdoor_persistence(by_service))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    paths.sort(key=lambda p: severity_order.get(p.severity, 4))

    return paths


def _find(findings: list, keyword: str) -> list:
    return [f for f in findings if keyword.lower() in f.observation.lower()]


def _path_compromised_user(by_service):
    """IAM user without MFA + admin access = full account takeover"""
    iam = by_service.get("IAM", [])

    no_mfa = _find(iam, "no MFA enabled")
    has_admin = _find(iam, "AdministratorAccess policy")
    no_policy = _find(iam, "No account password policy")

    paths = []
    for user_finding in no_mfa:
        username = user_finding.resource_name
        admin_match = [f for f in has_admin if f.resource_name == username]

        if admin_match:
            paths.append(AttackPath(
                title=f"Full account takeover via '{username}'",
                severity="critical",
                narrative=(
                    f"User '{username}' has console access without MFA and AdministratorAccess attached directly. "
                    f"An attacker only needs to compromise the password through phishing, credential stuffing, "
                    f"or a breach of a reused password. Once authenticated, they have full control of the AWS account."
                    + (" The lack of a password policy makes the initial compromise even easier." if no_policy else "")
                ),
                impact="Complete AWS account compromise: create or delete any resource, access all data, modify billing, exfiltrate credentials.",
                steps=[
                    f"Attacker obtains '{username}' password via phishing or breach",
                    "Logs into AWS console (no MFA to stop them)",
                    "Inherits full AdministratorAccess permissions",
                    "Can create new access keys, modify IAM, disable logging, exfiltrate data",
                ],
                related_findings=[user_finding.resource_id, admin_match[0].resource_id],
            ))

    return paths


def _path_exposed_infra_no_logging(by_service):
    """Public EC2 + no CloudTrail = attacker gets in, leaves no trace"""
    ec2 = by_service.get("EC2", [])
    ct = by_service.get("CloudTrail", [])

    public_instances = _find(ec2, "public IP address")
    no_logging = _find(ct, "No CloudTrail") + _find(ct, "logging is disabled")

    paths = []
    if public_instances and no_logging:
        instance_names = [f.resource_name for f in public_instances[:3]]
        instance_list = ", ".join(instance_names)
        more = f" and {len(public_instances) - 3} more" if len(public_instances) > 3 else ""

        paths.append(AttackPath(
            title="Exposed infrastructure with no audit trail",
            severity="critical",
            narrative=(
                f"Public-facing instances ({instance_list}{more}) are reachable from the internet while "
                f"CloudTrail is not logging API activity. An attacker who compromises any of these instances "
                f"can pivot laterally into the AWS control plane without creating any audit record. "
                f"Incident response would have no timeline, no attribution, and no evidence."
            ),
            impact="Silent compromise. Attackers can operate undetected, create persistence, and exfiltrate data with no forensic trail.",
            steps=[
                f"Attacker scans and identifies exposed instances ({instance_list})",
                "Exploits services listening on public IP (SSH brute force, known CVE, misconfigured app)",
                "Uses instance metadata service to steal IAM role credentials",
                "Accesses AWS APIs with stolen credentials, no CloudTrail to record actions",
                "Creates backdoor access, exfiltrates data, covers tracks",
            ],
            related_findings=[public_instances[0].resource_id, no_logging[0].resource_id],
        ))

    return paths


def _path_public_db_exposure(by_service):
    """Public RDS + no encryption = direct database breach"""
    rds = by_service.get("RDS", [])

    public_dbs = _find(rds, "publicly accessible")
    unencrypted = _find(rds, "does not have storage encryption")

    paths = []
    for db_finding in public_dbs:
        db_name = db_finding.resource_name
        unencrypted_match = [f for f in unencrypted if f.resource_name == db_name]

        severity = "critical" if unencrypted_match else "high"

        paths.append(AttackPath(
            title=f"Direct database exposure: {db_name}",
            severity=severity,
            narrative=(
                f"RDS instance '{db_name}' is publicly accessible from the internet. "
                + ("The storage is also unencrypted, " if unencrypted_match else "")
                + f"Attackers will find this via Shodan scans or AWS IP range enumeration within hours. "
                f"Brute force attacks against database credentials or exploitation of database engine "
                f"vulnerabilities become the only barriers to full data compromise."
            ),
            impact="Direct theft of database contents including customer data, credentials, and PII. Potential ransomware via database encryption.",
            steps=[
                f"Attacker enumerates public RDS endpoints",
                f"Identifies '{db_name}' via Shodan or AWS IP scanning",
                "Attempts credential brute force or known database CVE exploitation",
                "On successful access, dumps all database contents",
                "Uses stolen data for further attacks (credential reuse, PII fraud, ransomware demand)",
            ],
            related_findings=[db_finding.resource_id] + [f.resource_id for f in unencrypted_match],
        ))

    return paths


def _path_credential_sprawl(by_service):
    """Lambda env secrets + old IAM keys = credential proliferation"""
    lam = by_service.get("Lambda", [])
    iam = by_service.get("IAM", [])

    env_secrets = _find(lam, "environment variable") + _find(lam, "appears to contain")
    old_keys = _find(iam, "days old")

    paths = []
    if env_secrets or old_keys:
        targets = []
        if env_secrets:
            targets.append(f"Lambda environment variables ({len(env_secrets)} functions)")
        if old_keys:
            targets.append(f"stale IAM access keys ({len(old_keys)} keys)")

        paths.append(AttackPath(
            title="Credential sprawl and exposure",
            severity="high" if env_secrets else "medium",
            narrative=(
                f"Credentials are scattered across the environment in {' and '.join(targets)}. "
                f"Any read access to Lambda function configuration exposes the environment variables in plaintext. "
                f"Long-lived IAM access keys extend the exposure window if they were ever leaked in code, "
                f"logs, git history, or a past breach. Credential hygiene failures like these are the most "
                f"common initial access vector in cloud breaches."
            ),
            impact="Attackers obtain credentials without exploitation, then use them to authenticate as legitimate users.",
            steps=[
                "Attacker obtains read access (phishing, compromised CI/CD, lambda:GetFunction permission)",
                "Extracts secrets from Lambda environment variables or finds leaked access keys in git history",
                "Authenticates to AWS APIs or downstream services as a legitimate user",
                "Operates with the same permissions as the compromised identity",
            ],
            related_findings=[f.resource_id for f in (env_secrets + old_keys)[:5]],
        ))

    return paths


def _path_blind_environment(by_service):
    """No flow logs + no CloudTrail = you cannot see attacks"""
    vpc = by_service.get("VPC", [])
    ct = by_service.get("CloudTrail", [])

    no_flow_logs = _find(vpc, "does not have flow logs")
    no_logging = _find(ct, "No CloudTrail") + _find(ct, "logging is disabled")

    paths = []
    if no_flow_logs and no_logging:
        paths.append(AttackPath(
            title="Blind environment: no network or API visibility",
            severity="high",
            narrative=(
                f"Neither VPC flow logs nor CloudTrail are capturing activity. Network-level attacks "
                f"(lateral movement, data exfiltration, C2 traffic) will not appear in flow logs. "
                f"AWS API activity (IAM changes, resource creation, credential theft) will not appear "
                f"in CloudTrail. Detection and incident response depend on logs that do not exist. "
                f"An attacker can operate freely until they cause a visible outage or a third party notices."
            ),
            impact="Complete loss of detection capability. Breaches go undiscovered for months, matching industry average dwell time.",
            steps=[
                "Attacker gains initial access via any vector",
                "Explores the environment with no network traffic logging",
                "Makes API calls to escalate privileges with no audit log",
                "Exfiltrates data over normal-looking traffic with no detection",
                "Maintains persistence indefinitely until external notification",
            ],
            related_findings=[no_flow_logs[0].resource_id, no_logging[0].resource_id],
        ))

    return paths


def _path_backdoor_persistence(by_service):
    """Permissive SGs + default VPC + no logs = ready-made attack environment"""
    ec2 = by_service.get("EC2", [])
    vpc = by_service.get("VPC", [])

    open_ports = [f for f in ec2 if "allows" in f.observation.lower() and "internet" in f.observation.lower()]
    default_vpcs = _find(vpc, "Default VPC")

    paths = []
    if open_ports and default_vpcs:
        port_list = ", ".join([f.observation.split("(port ")[1].split(")")[0] for f in open_ports[:3] if "(port " in f.observation])
        if not port_list:
            port_list = "multiple administrative ports"

        paths.append(AttackPath(
            title="Insecure defaults with public exposure",
            severity="medium",
            narrative=(
                f"Default VPCs remain in use and security groups expose administrative ports ({port_list}) "
                f"to the internet. Default VPCs come with permissive route tables and network ACLs that "
                f"favor connectivity over security. Attackers scan for cloud environments running on defaults "
                f"because misconfigurations are predictable and exploitation is reliable."
            ),
            impact="Low effort reconnaissance reveals a target that is known to be poorly hardened, increasing the probability of targeted attack.",
            steps=[
                "Attacker fingerprints the environment as using AWS defaults",
                f"Identifies exposed administrative ports ({port_list})",
                "Attempts credential attacks or known CVE exploitation",
                "Leverages default VPC's permissive networking for lateral movement",
            ],
            related_findings=[open_ports[0].resource_id, default_vpcs[0].resource_id],
        ))

    return paths
