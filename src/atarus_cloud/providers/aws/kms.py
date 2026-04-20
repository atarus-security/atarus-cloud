from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS KMS keys"""

    kms = session.client("kms")
    findings_before = len(result.findings)

    try:
        paginator = kms.get_paginator("list_keys")
        keys = []
        for page in paginator.paginate():
            keys.extend(page["Keys"])
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list keys: {e}")

    customer_keys = []
    for key in keys:
        try:
            metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if metadata.get("KeyManager") == "CUSTOMER" and metadata.get("KeyState") == "Enabled":
                customer_keys.append(metadata)
        except Exception as e:
            if verbose:
                print(f"  Cannot describe key {key['KeyId']}: {e}")

    if not customer_keys:
        return ModuleResult(success=True, message="No customer-managed KMS keys found")

    for key in customer_keys:
        key_id = key["KeyId"]
        key_arn = key["Arn"]
        key_desc = key.get("Description", "")
        display_name = key_desc if key_desc else key_id

        _check_key_rotation(kms, key_id, key_arn, display_name, result, verbose)
        _check_key_policy(kms, key_id, key_arn, display_name, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(customer_keys)} customer keys, {new_findings} findings")


def _check_key_rotation(kms, key_id, key_arn, display_name, result, verbose):
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
                remediation_cmd=f"aws kms enable-key-rotation --key-id {key_id}",
                remediation_effort="2 minutes",
                compliance=["CIS 2.8"],
            ))
    except kms.exceptions.UnsupportedOperationException:
        pass
    except Exception as e:
        if verbose:
            print(f"  Rotation check error for {key_id}: {e}")


def _check_key_policy(kms, key_id, key_arn, display_name, result, verbose):
    try:
        import json
        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        policy = json.loads(policy_str)

        for statement in policy.get("Statement", []):
            effect = statement.get("Effect")
            principal = statement.get("Principal", {})
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if effect == "Allow":
                is_wildcard_principal = (
                    principal == "*" or
                    (isinstance(principal, dict) and principal.get("AWS") == "*")
                )

                if is_wildcard_principal:
                    has_condition = "Condition" in statement
                    if not has_condition:
                        result.add_finding(CloudFinding(
                            service="KMS",
                            resource_id=key_arn,
                            resource_name=display_name,
                            severity="critical",
                            observation=f"KMS key '{display_name}' has a policy statement allowing any AWS principal without conditions.",
                            risk="Any AWS account can use this key to encrypt or decrypt data. This defeats the purpose of encryption and could allow unauthorized access to any data protected by this key.",
                            recommendation=f"Restrict the key policy for '{display_name}' to specific AWS accounts or principals.",
                            remediation_cmd=f"# Review and update key policy:\naws kms get-key-policy --key-id {key_id} --policy-name default\naws kms put-key-policy --key-id {key_id} --policy-name default --policy file://new-policy.json",
                            remediation_effort="30 minutes",
                        ))

    except Exception as e:
        if verbose:
            print(f"  Policy check error for {key_id}: {e}")
