import os
from weasyprint import HTML
from atarus_cloud.reports import html as html_report
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    html_path = html_report.generate(result, output_dir)

    with open(html_path, "r") as f:
        html_content = f.read()

    pdf_css = """
    <style>
      body { background: #060606 !important; }
      .tabs { display: none !important; }
      .tab-content { display: block !important; margin-bottom: 40px; }
      @page {
        size: A4;
        margin: 20mm 15mm;
        @bottom-center {
          content: "Atarus Offensive Security | Confidential";
          font-size: 9px; color: #555;
        }
        @bottom-right {
          content: "Page " counter(page) " of " counter(pages);
          font-size: 9px; color: #555;
        }
      }
      .tab-content::before {
        display: block; font-size: 18px; font-weight: 600;
        color: #D4263E; margin-bottom: 16px;
        padding-bottom: 8px; border-bottom: 1px solid #1a1a1a;
      }
      #tab-overview::before { content: "Overview"; }
      #tab-findings::before { content: "Findings"; }
      #tab-remediation::before { content: "Remediation"; }
      .finding-card { page-break-inside: avoid; }
    </style>
    """

    html_content = html_content.replace("</head>", pdf_css + "</head>")

    pdf_path = os.path.join(output_dir, f"atarus-cloud-{result.account_id}.pdf")
    HTML(string=html_content).write_pdf(pdf_path)

    return pdf_path
