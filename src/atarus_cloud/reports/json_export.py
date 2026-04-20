import os
import json
from dataclasses import asdict
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str, attack_paths_list=None, summary=None, compliance_data=None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    data = asdict(result)
    data["tool"] = "atarus-cloud"
    data["version"] = "0.9.0"
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

    if summary:
        data["executive_summary"] = summary
    else:
        data["executive_summary"] = {}

    if compliance_data:
        data["compliance"] = {
            "cis": {
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

    output_path = os.path.join(output_dir, f"atarus-cloud-{result.account_id}.json")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return output_path
