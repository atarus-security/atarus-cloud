import os
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str) -> str:
    """Generate a remediation shell script from findings"""
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, f"remediation-{result.account_id}.sh")

    lines = [
        "#!/bin/bash",
        "# atarus-cloud remediation script",
        f"# Account: {result.account_id}",
        f"# Generated: {result.finished_at}",
        "#",
        "# REVIEW EACH COMMAND BEFORE RUNNING",
        "# This script contains destructive operations",
        "",
        'set -e',
        "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 4))

    for i, finding in enumerate(sorted_findings, 1):
        if not finding.remediation_cmd or finding.remediation_cmd.startswith("#"):
            continue

        lines.append(f"# [{finding.severity.upper()}] {finding.observation[:80]}")
        lines.append(f"# Resource: {finding.resource_name}")
        lines.append(f"# Effort: {finding.remediation_effort}")

        for cmd_line in finding.remediation_cmd.split("\n"):
            cmd_line = cmd_line.strip()
            if cmd_line and not cmd_line.startswith("#"):
                lines.append(f"echo '[{i}] {finding.severity.upper()}: {finding.resource_name[:40]}'")
                lines.append(cmd_line)

        lines.append("")

    lines.append('echo "Remediation complete."')

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    os.chmod(output_path, 0o755)

    return output_path
