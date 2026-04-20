import boto3
from datetime import datetime, timezone
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS IAM configuration"""

    iam = session.client("iam")
    findings_before = len(result.findings)

    _check_root_account(iam, result, verbose)
    _check_mfa(iam, result, verbose)
    _check_access_keys(iam, result, verbose)
    _check_password_policy(iam, result, verbose)
    _check_admin_users(iam, result, verbose)
    _check_unused_users(iam, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"{new_findings} findings")


def _check_root_account(iam, result, verbose):
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            result.add_finding(CloudFinding(
                service="IAM",
                resource_id="root",
                resource_name="Root account",
                severity="critical",
                observation="The root account does not have MFA enabled.",
                risk="The root account has unrestricted access to all AWS resources. Without MFA, a compromised password gives an attacker full control of the entire AWS environment including billing, all services, and the ability to delete all data.",
                recommendation="Enable MFA on the root account immediately. Use a hardware MFA device for maximum security.",
                remediation_cmd="# Enable via AWS Console: IAM > Security credentials > Assign MFA device",
                remediation_effort="5 minutes",
                compliance=["CIS 1.5"],
            ))
    except Exception as e:
        if verbose:
            print(f"  Root account check error: {e}")


def _check_mfa(iam, result, verbose):
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

            if not mfa_devices:
                has_password = True
                try:
                    iam.get_login_profile(UserName=username)
                except iam.exceptions.NoSuchEntityException:
                    has_password = False

                if has_password:
                    result.add_finding(CloudFinding(
                        service="IAM",
                        resource_id=f"user/{username}",
                        resource_name=username,
                        severity="high",
                        observation=f"IAM user '{username}' has console access but no MFA enabled.",
                        risk=f"If the password for '{username}' is compromised through phishing or credential stuffing, an attacker can log into the AWS console without any additional verification and access all resources this user has permissions for.",
                        recommendation=f"Enable MFA for user '{username}'. Enforce MFA via IAM policy for all console users.",
                        remediation_cmd=f"# Enable via Console: IAM > Users > {username} > Security credentials > Assign MFA",
                        remediation_effort="5 minutes per user",
                        compliance=["CIS 1.10"],
                    ))
    except Exception as e:
        if verbose:
            print(f"  MFA check error: {e}")


def _check_access_keys(iam, result, verbose):
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            for key in keys:
                key_id = key["AccessKeyId"]
                created = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - created).days

                if age_days > 90:
                    result.add_finding(CloudFinding(
                        service="IAM",
                        resource_id=f"user/{username}/key/{key_id}",
                        resource_name=f"{username} ({key_id})",
                        severity="medium",
                        observation=f"Access key '{key_id}' for user '{username}' is {age_days} days old.",
                        risk=f"Long-lived access keys increase the window of exposure if compromised. This key has been active for {age_days} days without rotation, giving a potential attacker extended access if the key was leaked in code, logs, or a breach.",
                        recommendation=f"Rotate access key '{key_id}' for user '{username}'. Establish a 90-day key rotation policy.",
                        remediation_cmd=f"aws iam create-access-key --user-name {username}\naws iam delete-access-key --user-name {username} --access-key-id {key_id}",
                        remediation_effort="10 minutes",
                        compliance=["CIS 1.14"],
                    ))

                if key["Status"] == "Inactive":
                    result.add_finding(CloudFinding(
                        service="IAM",
                        resource_id=f"user/{username}/key/{key_id}",
                        resource_name=f"{username} ({key_id})",
                        severity="low",
                        observation=f"Inactive access key '{key_id}' exists for user '{username}'.",
                        risk="Inactive keys are unnecessary attack surface. If reactivated by an attacker with IAM access, they could be used for unauthorized API calls.",
                        recommendation=f"Delete inactive access key '{key_id}' for user '{username}'.",
                        remediation_cmd=f"aws iam delete-access-key --user-name {username} --access-key-id {key_id}",
                        remediation_effort="2 minutes",
                    ))
    except Exception as e:
        if verbose:
            print(f"  Access key check error: {e}")


def _check_password_policy(iam, result, verbose):
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        if policy.get("MinimumPasswordLength", 0) < 14:
            result.add_finding(CloudFinding(
                service="IAM",
                resource_id="password-policy",
                resource_name="Account password policy",
                severity="medium",
                observation=f"Password minimum length is {policy.get('MinimumPasswordLength', 'not set')} characters.",
                risk="Short passwords are vulnerable to brute force attacks. Industry standard requires minimum 14 characters.",
                recommendation="Set minimum password length to 14 characters.",
                remediation_cmd="aws iam update-account-password-policy --minimum-password-length 14",
                remediation_effort="2 minutes",
                compliance=["CIS 1.8"],
            ))

        if not policy.get("RequireUppercaseCharacters", False) or \
           not policy.get("RequireLowercaseCharacters", False) or \
           not policy.get("RequireNumbers", False) or \
           not policy.get("RequireSymbols", False):
            result.add_finding(CloudFinding(
                service="IAM",
                resource_id="password-policy",
                resource_name="Account password policy",
                severity="medium",
                observation="Password policy does not require all character types.",
                risk="Passwords without complexity requirements are easier to crack through brute force or dictionary attacks.",
                recommendation="Require uppercase, lowercase, numbers, and symbols in passwords.",
                remediation_cmd="aws iam update-account-password-policy --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols",
                remediation_effort="2 minutes",
                compliance=["CIS 1.8"],
            ))

    except iam.exceptions.NoSuchEntityException:
        result.add_finding(CloudFinding(
            service="IAM",
            resource_id="password-policy",
            resource_name="Account password policy",
            severity="high",
            observation="No account password policy is configured.",
            risk="Without a password policy, users can set weak passwords like 'password123' which are trivially compromised through brute force or credential stuffing attacks.",
            recommendation="Create a password policy requiring minimum 14 characters, complexity, and 90-day rotation.",
            remediation_cmd="aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --max-password-age 90",
            remediation_effort="5 minutes",
            compliance=["CIS 1.8"],
        ))
    except Exception as e:
        if verbose:
            print(f"  Password policy check error: {e}")


def _check_admin_users(iam, result, verbose):
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]

            for policy in policies:
                if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                    result.add_finding(CloudFinding(
                        service="IAM",
                        resource_id=f"user/{username}",
                        resource_name=username,
                        severity="medium",
                        observation=f"IAM user '{username}' has the AdministratorAccess policy directly attached.",
                        risk=f"Direct admin access means '{username}' can create, modify, or delete any resource in the account. If compromised, the blast radius is the entire AWS environment.",
                        recommendation=f"Use role-based access instead. Create an admin role and allow '{username}' to assume it with MFA required.",
                        remediation_cmd=f"# Review and replace direct admin policy:\naws iam detach-user-policy --user-name {username} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        remediation_effort="30 minutes",
                        compliance=["CIS 1.16"],
                    ))
    except Exception as e:
        if verbose:
            print(f"  Admin users check error: {e}")


def _check_unused_users(iam, result, verbose):
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]

            last_used = user.get("PasswordLastUsed")
            if last_used:
                days_since = (datetime.now(timezone.utc) - last_used).days
                if days_since > 90:
                    result.add_finding(CloudFinding(
                        service="IAM",
                        resource_id=f"user/{username}",
                        resource_name=username,
                        severity="low",
                        observation=f"IAM user '{username}' has not logged in for {days_since} days.",
                        risk="Dormant accounts are prime targets for attackers. Unused credentials that remain active can be compromised without the legitimate user noticing.",
                        recommendation=f"Disable or delete the unused account '{username}' if no longer needed.",
                        remediation_cmd=f"aws iam delete-login-profile --user-name {username}",
                        remediation_effort="5 minutes",
                        compliance=["CIS 1.12"],
                    ))
    except Exception as e:
        if verbose:
            print(f"  Unused users check error: {e}")
