import os
import json
from dataclasses import asdict
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str, attack_paths_list=None, summary=None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    data = asdict(result)
    data["tool"] = "atarus-cloud"
    data["version"] = "0.5.0"
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

    output_path = os.path.join(output_dir, f"atarus-cloud-{result.account_id}.json")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    return output_path
