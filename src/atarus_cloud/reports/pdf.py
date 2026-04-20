import os
from weasyprint import HTML
from atarus_cloud.reports import html as html_report
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str, attack_paths_list=None, summary=None, compliance_data=None) -> str:
    os.makedirs(output_dir, exist_ok=True)

    html_path = html_report.generate(result, output_dir, attack_paths_list=attack_paths_list, summary=summary, compliance_data=compliance_data)

    with open(html_path, "r") as f:
        html_content = f.read()

    pdf_css = """
    <style>
      body { background: #060606 !important; color: #e0e0e0 !important; }
      .tabs { display: none !important; }
      .tab-content { display: block !important; }
      .tab-content::before {
        display: block; font-size: 22px; font-weight: 600;
        color: #D4263E; margin-bottom: 20px;
        padding-bottom: 10px; border-bottom: 2px solid #D4263E;
      }
      #tab-overview::before { content: "Overview"; }
      #tab-summary::before { content: "Executive Summary"; }
      #tab-paths::before { content: "Attack Paths"; }
      #tab-findings::before { content: "Findings"; }
      #tab-compliance::before { content: "Compliance"; }
      #tab-remediation::before { content: "Remediation"; }
      #tab-summary { page-break-before: always; }
      #tab-paths { page-break-before: always; }
      #tab-findings { page-break-before: always; }
      #tab-compliance { page-break-before: always; }
      #tab-remediation { page-break-before: always; }
      .scan-info td { color: #e0e0e0 !important; }
      .scan-info td:first-child { color: #888 !important; }
      .fix-item { color: #e0e0e0 !important; font-size: 13px; }
      .service-name { color: #fff !important; }
      .section-title { color: #fff !important; font-size: 18px; margin: 30px 0 16px; padding-bottom: 6px; border-bottom: 1px solid #222; }
      .finding-card { page-break-inside: avoid; margin-bottom: 20px; }
      .finding-title { color: #fff !important; }
      .finding-resource { color: #D4263E !important; }
      .finding-section-label { color: #D4263E !important; }
      .finding-section-text { color: #ccc !important; }
      .finding-cmd { color: #22c55e !important; background: #0a0a0a !important; }
      .meta-pill { color: #aaa !important; }
      .no-data { color: #666 !important; }
      .path-card { page-break-inside: avoid; margin-bottom: 20px; }
      .path-title { color: #fff !important; }
      .path-narrative { color: #ccc !important; }
      .path-impact { color: #F09595 !important; }
      .path-step { color: #ccc !important; }
      .summary-section { page-break-inside: avoid; margin-bottom: 22px; }
      .summary-label { color: #D4263E !important; }
      .summary-text { color: #ccc !important; }
      .compliance-stats { color: #e0e0e0 !important; }
      .control-card { page-break-inside: avoid; }
      .control-title { color: #fff !important; }
      .control-meta { color: #888 !important; }
      .footer { color: #555 !important; }
      .footer a { color: #D4263E !important; }
      @page {
        size: A4;
        margin: 22mm 18mm;
        @bottom-center {
          content: "Atarus Offensive Security | Confidential";
          font-size: 8px; color: #666;
        }
        @bottom-right {
          content: "Page " counter(page) " of " counter(pages);
          font-size: 8px; color: #666;
        }
      }
      @page :first {
        margin-top: 18mm;
        @bottom-center { content: none; }
        @bottom-right { content: none; }
      }
    </style>
    """

    html_content = html_content.replace("</head>", pdf_css + "</head>")

    pdf_path = os.path.join(output_dir, f"atarus-cloud-{result.account_id}.pdf")
    HTML(string=html_content).write_pdf(pdf_path)

    return pdf_path
