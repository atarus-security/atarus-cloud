import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    possible_dirs = [
        os.path.join(os.path.dirname(__file__), "..", "templates"),
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "templates"),
    ]

    template_dir = None
    for d in possible_dirs:
        d = os.path.normpath(d)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "cloud_report.html")):
            template_dir = d
            break

    if template_dir is None:
        raise FileNotFoundError("Could not find templates/cloud_report.html")

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(default=True, default_for_string=True),
    )
    template = env.get_template("cloud_report.html")

    crits = [f for f in result.findings if f.severity == "critical"]
    highs = [f for f in result.findings if f.severity == "high"]
    meds = [f for f in result.findings if f.severity == "medium"]
    lows = [f for f in result.findings if f.severity == "low"]

    html_content = template.render(
        result=result,
        crits=crits,
        highs=highs,
        meds=meds,
        lows=lows,
    )

    output_path = os.path.join(output_dir, f"atarus-cloud-{result.account_id}.html")
    with open(output_path, "w") as f:
        f.write(html_content)

    return output_path
