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
      body { background: #060606 !important; color: #e0e0e0 !important; }

      .tabs { display: none !important; }
      .tab-content { display: block !important; }

      .tab-content::before {
        display: block;
        font-size: 22px;
        font-weight: 600;
        color: #D4263E;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 2px solid #D4263E;
      }
      #tab-overview::before { content: "Overview"; }
      #tab-findings::before { content: "Findings"; }
      #tab-remediation::before { content: "Remediation"; }

      #tab-findings { page-break-before: always; }
      #tab-remediation { page-break-before: always; }

      .header { margin-bottom: 30px; }
      .header h1 { font-size: 32px; }

      .summary { margin-bottom: 30px; }
      .card .number { font-size: 36px; }
      .card .label { font-size: 10px; }

      .scan-info { margin-bottom: 30px; }
      .scan-info td { color: #e0e0e0 !important; }
      .scan-info td:first-child { color: #888 !important; }

      .fix-first { margin-bottom: 30px; page-break-inside: avoid; }
      .fix-first h3 { font-size: 18px; }
      .fix-item { color: #e0e0e0 !important; font-size: 13px; }

      .service-bar { page-break-inside: avoid; }
      .service-name { color: #fff !important; }

      .section-title { 
        font-size: 18px; 
        color: #fff !important; 
        margin: 30px 0 16px;
        padding-bottom: 6px;
        border-bottom: 1px solid #222;
      }

      .finding-card {
        page-break-inside: avoid;
        margin-bottom: 20px;
        padding: 20px 24px;
      }
      .finding-title { color: #fff !important; font-size: 15px; }
      .finding-resource { color: #D4263E !important; font-size: 12px; }
      .finding-section { margin-top: 14px; }
      .finding-section-label { 
        color: #D4263E !important; 
        font-size: 11px; 
        letter-spacing: 1px;
        margin-bottom: 6px;
      }
      .finding-section-text { color: #ccc !important; font-size: 13px; line-height: 1.6; }
      .finding-cmd { 
        color: #22c55e !important; 
        background: #0a0a0a !important; 
        font-size: 11px;
        padding: 12px 14px;
        margin-top: 10px;
        border-radius: 6px;
        line-height: 1.5;
      }
      .finding-meta { margin-top: 10px; }
      .meta-pill { color: #aaa !important; font-size: 10px; }

      .no-data { color: #666 !important; }

      .footer { 
        margin-top: 40px;
        text-align: center;
        font-size: 11px;
        color: #555 !important;
      }
      .footer a { color: #D4263E !important; }

      @page {
        size: A4;
        margin: 22mm 18mm;
        @bottom-center {
          content: "Atarus Offensive Security | Confidential";
          font-size: 8px;
          color: #666;
          font-family: 'Segoe UI', system-ui, sans-serif;
        }
        @bottom-right {
          content: "Page " counter(page) " of " counter(pages);
          font-size: 8px;
          color: #666;
          font-family: 'Segoe UI', system-ui, sans-serif;
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
