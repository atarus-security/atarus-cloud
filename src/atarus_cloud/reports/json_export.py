import os
import json
from dataclasses import asdict
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    data = asdict(result)
    data["tool"] = "atarus-cloud"
    data["version"] = "0.1.0"
    output_path = os.path.join(output_dir, f"atarus-cloud-{result.account_id}.json")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    return output_path
