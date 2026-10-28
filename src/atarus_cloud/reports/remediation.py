"""Remediation script writer.

Written only when the user passes --remediation-script. Every command line is
commented out, every resource value inside the commands was shell-quoted by the
module that produced the finding, and the file is created with mode 0644, so
nothing runs until a person reads a line, agrees with it and removes its
leading comment marker.
"""
import os
from atarus_cloud.models import AuditResult, file_stem

HEADER_WARNING = "REVIEW BEFORE RUNNING. Nothing in this file is live: every command is commented out."


def generate(result: AuditResult, output_dir: str) -> str:
    """Write remediation-<account>.sh and return its path."""
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, f"remediation-{file_stem(result.account_id)}.sh")

    lines = [
        "#!/bin/bash",
        "# atarus-cloud remediation script",
        f"# Account: {result.account_id}",
        f"# Generated: {result.finished_at}",
        "#",
        f"# {HEADER_WARNING}",
        "# Read each command, confirm the resource and the change it makes against your",
        "# own environment, then remove the leading '# ' from the lines you approve.",
        "# Values are shell-quoted; placeholders in angle brackets or capitals",
        "# (for example <RG>, YOUR-LOG-BUCKET) must be replaced before a command can run.",
        "# These commands change cloud resources. Run them only against accounts you",
        "# are authorized to modify.",
        "",
        "set -euo pipefail",
        "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 4))

    written = 0
    for i, finding in enumerate(sorted_findings, 1):
        if not finding.remediation_cmd or finding.remediation_cmd.startswith("#"):
            continue

        lines.append(f"# [{finding.severity.upper()}] {_one_line(finding.observation, 100)}")
        lines.append(f"# Resource: {_one_line(finding.resource_name, 120)}")
        if finding.region:
            lines.append(f"# Region: {_one_line(finding.region, 40)}")
        lines.append(f"# Effort: {_one_line(finding.remediation_effort, 40)}")

        for cmd_line in finding.remediation_cmd.split("\n"):
            cmd_line = _one_line(cmd_line.strip(), 2000)
            if not cmd_line:
                continue
            if cmd_line.startswith("#"):
                lines.append(cmd_line)
            else:
                lines.append(f"# {cmd_line}")
                written += 1

        lines.append("")

    lines.append(f"# {written} commands listed, all commented out. {HEADER_WARNING}")
    lines.append("")

    # Create with 0644 regardless of umask: readable, never executable.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(output_path, flags, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    os.chmod(output_path, 0o644)

    return output_path


def _one_line(text: str, limit: int) -> str:
    """Collapse newlines and control characters so a value cannot start a new
    script line or escape its comment marker."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in str(text or ""))
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned
