import json
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.providers.aws.common import q, region_of
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS KMS customer-managed keys in one region"""

    kms = session.client("kms")
    cov = result.recorder("kms", "KMS", region_of(session))
    findings_before = len(result.findings)

    try:
        paginator = kms.get_paginator("list_keys")
        keys = []
        for page in paginator.paginate():
            keys.extend(page["Keys"])
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list keys: {e}")

    customer_keys = []
    described = 0
    for key in keys:
        try:
            metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            described += 1
            if metadata.get("KeyManager") == "CUSTOMER" and metadata.get("KeyState") == "Enabled":
                customer_keys.append(metadata)
        except Exception as e:
            cov.not_run(f"describe key ({key['KeyId']})", e)

    if described == len(keys):
        cov.checked("key inventory", f"{len(keys)} keys, {len(customer_keys)} customer-managed and enabled")
    elif described:
        cov.checked("key inventory", f"{described} of {len(keys)} keys described; the rest are listed as not run")

    rotation_ok = 0
    policy_ok = 0
    for key in customer_keys:
        key_id = key["KeyId"]
        key_arn = key.get("Arn", key_id)
        key_desc = key.get("Description", "")
        display_name = key_desc if key_desc else key_id

        rotation_ok += _check_key_rotation(kms, key_id, key_arn, display_name, result, cov)
        policy_ok += _check_key_policy(kms, key_id, key_arn, display_name, result, cov)

    count = f"{len(customer_keys)} customer-managed keys"
    _record(cov, "automatic key rotation", rotation_ok, len(customer_keys), count)
    _record(cov, "key policy open to any principal", policy_ok, len(customer_keys), count)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(customer_keys)} customer keys, {new_findings} findings")


def _record(cov, check, ok, total, count):
    if ok == total:
        cov.checked(check, count)
    elif ok:
        cov.checked(check, f"{ok} of {total} keys; the rest are listed as not run")


def _check_key_rotation(kms, key_id, key_arn, display_name, result, cov) -> int:
    try:
        rotation = kms.get_key_rotation_status(KeyId=key_id)
        if not rotation.get("KeyRotationEnabled", False):
            result.add_finding(CloudFinding(
                service="KMS",
                resource_id=key_arn,
                resource_name=display_name,
                severity="medium",
                observation=f"KMS key '{display_name}' does not have automatic key rotation enabled.",
                risk="Without annual rotation, the same cryptographic material is used indefinitely. If key material is ever compromised, all data encrypted with it remains vulnerable. Rotation limits the blast radius of a key compromise.",
                recommendation=f"Enable automatic annual key rotation for '{display_name}'.",
                remediation_cmd=f"aws kms enable-key-rotation --key-id {q(key_id)}",
                remediation_effort="2 minutes",
                compliance=["CIS 2.8"],
            ))
        return 1
    except kms.exceptions.UnsupportedOperationException:
        # Asymmetric and HMAC keys cannot rotate automatically; nothing to check.
        return 1
    except Exception as e:
        cov.not_run(f"automatic key rotation ({display_name})", e)
        return 0


def _check_key_policy(kms, key_id, key_arn, display_name, result, cov) -> int:
    try:
        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        policy = json.loads(policy_str)

        for statement in policy.get("Statement", []):
            effect = statement.get("Effect")
            principal = statement.get("Principal", {})

            if effect == "Allow":
                is_wildcard_principal = (
                    principal == "*" or
                    (isinstance(principal, dict) and principal.get("AWS") == "*")
                )

                if is_wildcard_principal and "Condition" not in statement:
                    result.add_finding(CloudFinding(
                        service="KMS",
                        resource_id=key_arn,
                        resource_name=display_name,
                        severity="critical",
                        observation=f"KMS key '{display_name}' has a policy statement allowing any AWS principal without conditions.",
                        risk="Any AWS account can use this key to encrypt or decrypt data. This defeats the purpose of encryption and could allow unauthorized access to any data protected by this key.",
                        recommendation=f"Restrict the key policy for '{display_name}' to specific AWS accounts or principals.",
                        remediation_cmd=f"# Review and update key policy:\naws kms get-key-policy --key-id {q(key_id)} --policy-name default\naws kms put-key-policy --key-id {q(key_id)} --policy-name default --policy file://new-policy.json",
                        remediation_effort="30 minutes",
                    ))
        return 1
    except Exception as e:
        cov.not_run(f"key policy ({display_name})", e)
        return 0
