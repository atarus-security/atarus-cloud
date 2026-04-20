import re
from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.runner import ModuleResult


SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+', "password"),
    (r'(?i)(secret|api[_-]?key|apikey)\s*[=:]\s*\S+', "API key or secret"),
    (r'(?i)(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*\S+', "auth token"),
    (r'(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*\S+', "private key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key', "AWS secret key reference"),
    (r'(?i)(db|database)[_-]?(password|passwd|pwd)', "database password"),
    (r'(?i)(github|gitlab|bitbucket)[_-]?token', "Git hosting token"),
]

SUSPICIOUS_KEY_NAMES = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "access_token", "private_key", "db_password",
    "aws_secret_access_key", "stripe_key", "github_token",
}


def run(result: AuditResult, session, verbose: bool) -> ModuleResult:
    """Audit AWS Lambda functions"""

    lam = session.client("lambda")
    findings_before = len(result.findings)

    try:
        paginator = lam.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page["Functions"])
    except Exception as e:
        return ModuleResult(success=False, message=f"Cannot list functions: {e}")

    if not functions:
        return ModuleResult(success=True, message="No Lambda functions found")

    for func in functions:
        func_name = func["FunctionName"]
        func_arn = func["FunctionArn"]
        runtime = func.get("Runtime", "")

        _check_env_secrets(func, func_name, func_arn, result, verbose)
        _check_runtime_deprecated(func_name, func_arn, runtime, result, verbose)
        _check_function_policy(lam, func_name, func_arn, result, verbose)

    new_findings = len(result.findings) - findings_before
    return ModuleResult(success=True, message=f"Checked {len(functions)} functions, {new_findings} findings")


def _check_env_secrets(func, func_name, func_arn, result, verbose):
    env = func.get("Environment", {}).get("Variables", {})
    if not env:
        return

    for key, value in env.items():
        key_lower = key.lower().replace("-", "_")

        for suspicious in SUSPICIOUS_KEY_NAMES:
            if suspicious in key_lower:
                result.add_finding(CloudFinding(
                    service="Lambda",
                    resource_id=func_arn,
                    resource_name=func_name,
                    severity="high",
                    observation=f"Lambda function '{func_name}' has environment variable '{key}' that appears to contain a secret.",
                    risk="Secrets stored in Lambda environment variables are visible in plaintext to anyone with lambda:GetFunction or lambda:ListFunctions permissions. These values are also logged in CloudTrail and can be exposed through IAM policy misconfigurations.",
                    recommendation=f"Move '{key}' from environment variables to AWS Secrets Manager or Systems Manager Parameter Store.",
                    remediation_cmd=f"# Create secret in Secrets Manager:\naws secretsmanager create-secret --name {func_name}/{key} --secret-string 'VALUE'\n# Update Lambda to fetch from Secrets Manager instead of env var",
                    remediation_effort="30 minutes",
                ))
                break

        if value and isinstance(value, str) and len(value) > 10:
            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, f"{key}={value}"):
                    result.add_finding(CloudFinding(
                        service="Lambda",
                        resource_id=func_arn,
                        resource_name=func_name,
                        severity="critical",
                        observation=f"Lambda function '{func_name}' environment variable '{key}' appears to contain a {secret_type}.",
                        risk=f"The value stored in '{key}' matches the pattern of a {secret_type}. If compromised, this credential could be used for unauthorized access to the service it protects.",
                        recommendation=f"Rotate this credential immediately. Move it to AWS Secrets Manager.",
                        remediation_cmd=f"# Rotate the credential at the source service\n# Then migrate to Secrets Manager:\naws secretsmanager create-secret --name {func_name}/{key} --secret-string 'NEW_VALUE'",
                        remediation_effort="1 hour",
                    ))
                    break


def _check_runtime_deprecated(func_name, func_arn, runtime, result, verbose):
    deprecated_runtimes = {
        "python2.7": "Python 2.7 (EOL 2020)",
        "python3.6": "Python 3.6 (EOL 2022)",
        "python3.7": "Python 3.7 (EOL 2023)",
        "nodejs10.x": "Node.js 10 (EOL 2021)",
        "nodejs12.x": "Node.js 12 (EOL 2022)",
        "nodejs14.x": "Node.js 14 (EOL 2023)",
        "dotnetcore2.1": ".NET Core 2.1 (EOL 2021)",
        "dotnetcore3.1": ".NET Core 3.1 (EOL 2022)",
        "ruby2.5": "Ruby 2.5 (EOL 2021)",
        "ruby2.7": "Ruby 2.7 (EOL 2023)",
    }

    if runtime in deprecated_runtimes:
        result.add_finding(CloudFinding(
            service="Lambda",
            resource_id=func_arn,
            resource_name=func_name,
            severity="medium",
            observation=f"Lambda function '{func_name}' uses deprecated runtime: {deprecated_runtimes[runtime]}.",
            risk="Deprecated runtimes no longer receive security patches. Known vulnerabilities in the runtime or its dependencies remain exploitable.",
            recommendation=f"Update '{func_name}' to a supported runtime version.",
            remediation_cmd=f"aws lambda update-function-configuration --function-name {func_name} --runtime <NEW_RUNTIME>",
            remediation_effort="1 hour",
        ))


def _check_function_policy(lam, func_name, func_arn, result, verbose):
    try:
        policy_response = lam.get_policy(FunctionName=func_name)
        import json
        policy = json.loads(policy_response["Policy"])

        for statement in policy.get("Statement", []):
            principal = statement.get("Principal", {})

            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                result.add_finding(CloudFinding(
                    service="Lambda",
                    resource_id=func_arn,
                    resource_name=func_name,
                    severity="critical",
                    observation=f"Lambda function '{func_name}' has a resource policy allowing invocation by any AWS principal.",
                    risk="Any AWS account or service can invoke this function. If the function processes sensitive data or triggers downstream actions, this allows unauthorized access.",
                    recommendation=f"Restrict the function policy to specific AWS accounts or services.",
                    remediation_cmd=f"# Review policy:\naws lambda get-policy --function-name {func_name}\n# Remove overly permissive statements:\naws lambda remove-permission --function-name {func_name} --statement-id <STATEMENT_ID>",
                    remediation_effort="15 minutes",
                ))

    except lam.exceptions.ResourceNotFoundException:
        pass
    except Exception as e:
        if verbose:
            print(f"  Policy check error for {func_name}: {e}")
