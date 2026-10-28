from atarus_cloud.models import AuditResult, CloudFinding, SUBSCRIPTION
from atarus_cloud.providers.azure.common import q, sdk_missing
from atarus_cloud.runner import ModuleResult


def _client(credential, subscription_id):
    from azure.mgmt.authorization import AuthorizationManagementClient
    return AuthorizationManagementClient(credential, subscription_id)


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit Azure identity and role assignments"""

    credential = session["credential"]
    subscription_id = session["subscription_id"]
    cov = result.recorder("identity", "Identity", SUBSCRIPTION)
    findings_before = len(result.findings)

    try:
        client = _client(credential, subscription_id)
    except ImportError as e:
        return ModuleResult(success=False, message=sdk_missing(e))
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot create auth client: {e}")

    try:
        role_assignments = list(client.role_assignments.list_for_subscription())
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list role assignments: {e}")

    try:
        role_defs = list(client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"))
        role_def_map = {rd.id: rd for rd in role_defs}
    except Exception as e:
        # Without the definitions no assignment can be classified, so every
        # check below would silently pass. Record each as not run instead.
        cov.not_run("Owner assignments at subscription scope", f"role definitions could not be listed: {e}")
        cov.not_run("direct user Owner assignments", f"role definitions could not be listed: {e}")
        cov.not_run("custom roles with wildcard actions", f"role definitions could not be listed: {e}")
        return ModuleResult(success=True, message=f"Listed {len(role_assignments)} role assignments, none classified")

    owner_assignments = []
    unresolved = 0

    for ra in role_assignments:
        role_def = role_def_map.get(ra.role_definition_id)
        if not role_def:
            unresolved += 1
            continue

        role_name = role_def.role_name
        principal_id = ra.principal_id
        principal_type = ra.principal_type or "Unknown"

        if role_name == "Owner":
            owner_assignments.append({
                "principal_id": principal_id,
                "principal_type": principal_type,
                "scope": ra.scope,
                "id": ra.id,
            })

    if len(owner_assignments) > 3:
        result.add_finding(CloudFinding(
            service="Identity",
            resource_id=f"/subscriptions/{subscription_id}",
            resource_name="Owner role assignments",
            severity="high",
            observation=f"Found {len(owner_assignments)} Owner role assignments at subscription scope.",
            risk="Excessive Owner role assignments expand the blast radius of a compromise. Each Owner can manage all resources including role assignments, effectively granting them persistent admin access.",
            recommendation="Audit Owner assignments. Move users to Contributor or custom roles. Use Privileged Identity Management for just-in-time elevation.",
            remediation_cmd=f"az role assignment list --role Owner --scope {q('/subscriptions/' + str(subscription_id))}",
            remediation_effort="30 minutes",
            provider="azure",
            compliance=["CIS Azure 1.22"],
        ))

    user_owners = [a for a in owner_assignments if a["principal_type"] == "User"]
    for ua in user_owners:
        result.add_finding(CloudFinding(
            service="Identity",
            resource_id=ua["id"],
            resource_name=f"Owner: {ua['principal_id']}",
            severity="medium",
            observation=f"User principal {ua['principal_id']} has direct Owner role assignment on the subscription.",
            risk="Direct user assignments bypass group-based access controls. If this user is compromised, the attacker immediately gains subscription-wide ownership. Group-based assignments with PIM provide better audit trails and can enforce MFA.",
            recommendation="Move user to a group with PIM-eligible Owner assignment. Require MFA and approval workflows.",
            remediation_cmd="# Review via portal: Subscriptions > Access control (IAM)",
            remediation_effort="30 minutes",
            provider="azure",
            compliance=["CIS Azure 1.23"],
        ))

    detail = f"{len(role_assignments)} assignments"
    if unresolved:
        detail += f", {unresolved} with a role definition not in the subscription listing (skipped)"
    cov.checked("Owner assignments at subscription scope", detail)
    cov.checked("direct user Owner assignments", detail)

    custom_roles = [rd for rd in role_def_map.values() if getattr(rd, "role_type", "") == "CustomRole"]
    for role in custom_roles:
        for perm in (role.permissions or []):
            actions = perm.actions or []
            if "*" in actions:
                result.add_finding(CloudFinding(
                    service="Identity",
                    resource_id=role.id,
                    resource_name=role.role_name,
                    severity="high",
                    observation=f"Custom role '{role.role_name}' grants wildcard (*) action permissions.",
                    risk="A custom role with * actions is equivalent to Owner but without the review scrutiny applied to built-in privileged roles. It is a common privilege escalation target.",
                    recommendation=f"Scope down custom role '{role.role_name}' to specific actions required for its purpose.",
                    remediation_cmd="# Review role definition via portal: Access control > Roles",
                    remediation_effort="1 hour",
                    provider="azure",
                    compliance=["CIS Azure 1.23"],
                ))
    cov.checked("custom roles with wildcard actions", f"{len(custom_roles)} custom roles")

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(role_assignments)} role assignments, {new_findings} findings")
