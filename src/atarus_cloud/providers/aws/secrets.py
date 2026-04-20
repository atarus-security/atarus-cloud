import json
from datetime import datetime, timezone
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS Secrets Manager configuration"""

    sm = session.client("secretsmanager")
    findings_before = len(result.findings)

    try:
        paginator = sm.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            secrets.extend(page["SecretList"])
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list secrets: {e}")

    if not secrets:
        return ModuleResult(success=True, message="No secrets found")

    for secret in secrets:
        secret_name = secret.get("Name", "")
        secret_arn = secret.get("ARN", "")

        _check_rotation(secret, secret_name, secret_arn, result, verbose)
        _check_last_rotated(secret, secret_name, secret_arn, result, verbose)
        _check_resource_policy(sm, secret_name, secret_arn, result, verbose)
        _check_deletion_protection(secret, secret_name, secret_arn, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(secrets)} secrets, {new_findings} findings")


def _check_rotation(secret, secret_name, secret_arn, result, verbose):
    rotation_enabled = secret.get("RotationEnabled", False)

    if not rotation_enabled:
        result.add_finding(CloudFinding(
            service="SecretsManager",
            resource_id=secret_arn,
            resource_name=secret_name,
            severity="medium",
            observation=f"Secret '{secret_name}' does not have automatic rotation enabled.",
            risk="Long-lived secrets accumulate risk over time. If the secret was ever exposed in logs, code, or a past breach, it remains valid indefinitely without rotation. Rotation limits the blast radius of credential exposure.",
            recommendation=f"Enable automatic rotation for '{secret_name}' using a Lambda rotation function.",
            remediation_cmd=f"# Rotation requires a Lambda function. Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html\naws secretsmanager rotate-secret --secret-id {secret_name} --rotation-lambda-arn <LAMBDA_ARN>",
            remediation_effort="1 hour",
        ))


def _check_last_rotated(secret, secret_name, secret_arn, result, verbose):
    last_rotated = secret.get("LastRotatedDate")
    last_changed = secret.get("LastChangedDate")

    reference_date = last_rotated or last_changed
    if not reference_date:
        return

    age_days = (datetime.now(timezone.utc) - reference_date).days

    if age_days > 365:
        result.add_finding(CloudFinding(
            service="SecretsManager",
            resource_id=secret_arn,
            resource_name=secret_name,
            severity="high",
            observation=f"Secret '{secret_name}' was last rotated or changed {age_days} days ago.",
            risk=f"The secret has remained unchanged for over a year. Any past exposure through leaked code, logs, or a breach of a service that used this secret remains exploitable. The longer the exposure window, the greater the chance of compromise.",
            recommendation=f"Rotate '{secret_name}' immediately and enable automatic rotation going forward.",
            remediation_cmd=f"aws secretsmanager update-secret --secret-id {secret_name} --secret-string 'NEW_VALUE'",
            remediation_effort="30 minutes",
        ))
    elif age_days > 180:
        result.add_finding(CloudFinding(
            service="SecretsManager",
            resource_id=secret_arn,
            resource_name=secret_name,
            severity="medium",
            observation=f"Secret '{secret_name}' was last rotated or changed {age_days} days ago.",
            risk="Secrets older than 6 months should be rotated as part of standard security hygiene.",
            recommendation=f"Schedule rotation for '{secret_name}' within the next 30 days.",
            remediation_cmd=f"aws secretsmanager update-secret --secret-id {secret_name} --secret-string 'NEW_VALUE'",
            remediation_effort="30 minutes",
        ))


def _check_resource_policy(sm, secret_name, secret_arn, result, verbose):
    try:
        policy_response = sm.get_resource_policy(SecretId=secret_name)
        policy_str = policy_response.get("ResourcePolicy")

        if not policy_str:
            return

        policy = json.loads(policy_str)

        for statement in policy.get("Statement", []):
            effect = statement.get("Effect")
            principal = statement.get("Principal", {})

            if effect == "Allow":
                is_wildcard = (
                    principal == "*" or
                    (isinstance(principal, dict) and principal.get("AWS") == "*")
                )

                has_condition = "Condition" in statement

                if is_wildcard and not has_condition:
                    result.add_finding(CloudFinding(
                        service="SecretsManager",
                        resource_id=secret_arn,
                        resource_name=secret_name,
                        severity="critical",
                        observation=f"Secret '{secret_name}' has a resource policy allowing any AWS principal without conditions.",
                        risk=f"Any AWS account can retrieve this secret. If the secret contains database credentials, API keys, or other sensitive material, the entire AWS ecosystem could access it.",
                        recommendation=f"Restrict the resource policy for '{secret_name}' to specific AWS accounts or add IAM conditions.",
                        remediation_cmd=f"aws secretsmanager delete-resource-policy --secret-id {secret_name}\n# Then apply a restrictive policy:\n# aws secretsmanager put-resource-policy --secret-id {secret_name} --resource-policy file://policy.json",
                        remediation_effort="15 minutes",
                    ))

    except sm.exceptions.ResourceNotFoundException:
        pass
    except Exception as e:
        if verbose:
            print(f"  Policy check error for {secret_name}: {e}")


def _check_deletion_protection(secret, secret_name, secret_arn, result, verbose):
    deleted_date = secret.get("DeletedDate")

    if deleted_date:
        result.add_finding(CloudFinding(
            service="SecretsManager",
            resource_id=secret_arn,
            resource_name=secret_name,
            severity="low",
            observation=f"Secret '{secret_name}' is scheduled for deletion on {deleted_date.strftime('%Y-%m-%d')}.",
            risk="If this secret is still in use by any service, deletion will cause an outage. If it was compromised and marked for deletion as remediation, ensure no backups or restore paths exist.",
            recommendation=f"Confirm no services depend on '{secret_name}' before the deletion date. If this was remediation for a compromise, verify the new secret is rotated at all consumers.",
            remediation_cmd=f"# To cancel deletion:\naws secretsmanager restore-secret --secret-id {secret_name}",
            remediation_effort="15 minutes",
        ))
