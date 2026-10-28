import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from atarus_cloud import __version__
from atarus_cloud.models import AuditResult, file_stem


def generate(result: AuditResult, output_dir: str, attack_paths_list=None, summary=None,
             compliance_data=None, remediation_path=None) -> str:
    os.makedirs(output_dir, exist_ok=True)

    template_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "templates"))
    if not os.path.exists(os.path.join(template_dir, "cloud_report.html")):
        raise FileNotFoundError("Could not find templates/cloud_report.html inside the atarus_cloud package")

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
        version=__version__,
        crits=crits,
        highs=highs,
        meds=meds,
        lows=lows,
        attack_paths=attack_paths_list or [],
        summary=summary or {},
        compliance=compliance_data or {},
        coverage_rows=result.coverage_rows(),
        not_run=result.not_run_records,
        remediation_path=os.path.basename(remediation_path) if remediation_path else "",
    )

    output_path = os.path.join(output_dir, f"atarus-cloud-{file_stem(result.account_id)}.html")
    with open(output_path, "w") as f:
        f.write(html_content)

    return output_path
