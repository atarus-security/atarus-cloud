import os
import json
from dataclasses import asdict
from atarus_cloud import __version__
from atarus_cloud.models import AuditResult, file_stem


def generate(result: AuditResult, output_dir: str, attack_paths_list=None, summary=None,
             compliance_data=None, remediation_path=None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    data = asdict(result)
    data["tool"] = "atarus-cloud"
    data["version"] = __version__
    # overall_score is null whenever coverage is partial; say so next to it.
    data["score_note"] = (
        "every check ran; score covers the whole account"
        if result.overall_score is not None
        else f"no score: {result.checks_not_run} of {result.checks_total} checks did not run (see coverage)"
    )
    data["remediation_script"] = os.path.basename(remediation_path) if remediation_path else None

    if attack_paths_list:
        data["attack_paths"] = [
            {
                "title": p.title,
                "severity": p.severity,
                "narrative": p.narrative,
                "impact": p.impact,
                "steps": p.steps,
                "related_findings": p.related_findings,
            }
            for p in attack_paths_list
        ]
    else:
        data["attack_paths"] = []

    data["executive_summary"] = summary or {}

    if compliance_data:
        data["compliance"] = {
            "note": (
                "controls without a failing finding are not passes when coverage is partial"
                if result.overall_score is None else
                "controls without a failing finding had no failing resource among the checks this tool makes"
            ),
            "cis": {
                "framework": compliance_data.get("cis_framework_name", "CIS"),
                "total": compliance_data["cis_total"],
                "failed": compliance_data["cis_failed"],
                "failed_controls": [
                    {"id": c.control_id, "title": c.title, "category": c.category}
                    for cat_controls in compliance_data["cis_by_category"].values()
                    for c in cat_controls
                ],
            },
            "nist_800_53": {
                "total": compliance_data["nist_total"],
                "failed": compliance_data["nist_failed"],
                "failed_controls": [
                    {"id": c.control_id, "title": c.title, "category": c.category}
                    for cat_controls in compliance_data["nist_by_category"].values()
                    for c in cat_controls
                ],
            },
        }

    output_path = os.path.join(output_dir, f"atarus-cloud-{file_stem(result.account_id)}.json")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return output_path
