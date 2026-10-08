"""
Turns a pipeline.analyze_cve() result dict into a polished PDF advisory,
for the "show my mam a PDF" part of the demo.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

PRIORITY_COLORS = {
    "P0": colors.HexColor("#b91c1c"),
    "P1": colors.HexColor("#c2410c"),
    "P2": colors.HexColor("#a16207"),
    "P3": colors.HexColor("#15803d"),
}


def _markdown_to_flowables(markdown_text, styles):
    flowables = []
    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if not line:
            flowables.append(Spacer(1, 6))
        elif line.startswith("# "):
            flowables.append(Spacer(1, 10))
            flowables.append(Paragraph(line[2:], styles["Heading2"]))
            flowables.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
        elif line.startswith("- "):
            flowables.append(Paragraph(f"&bull;&nbsp;&nbsp;{line[2:]}", styles["Normal"]))
        else:
            flowables.append(Paragraph(line, styles["Normal"]))
    return flowables


def generate_pdf(result: dict, output_path: str) -> str:
    """
    result: the dict returned by pipeline.analyze_cve() (keys cve_id,
    risk_data, report_markdown, timestamp). Writes a PDF to output_path
    and returns that path.
    """
    cve_id = result["cve_id"]
    risk = result["risk_data"]
    priority_code = str(risk["PRIORITY"]).split(" ")[0]
    priority_color = PRIORITY_COLORS.get(priority_code, colors.HexColor("#334155"))

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="AdvisoryTitle", fontSize=22, leading=26, spaceAfter=4,
        textColor=colors.HexColor("#0f172a"),
    ))
    styles.add(ParagraphStyle(
        name="AdvisorySubtitle", fontSize=11, textColor=colors.HexColor("#475569"),
    ))

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )

    story = [
        Paragraph("Security Vulnerability Advisory", styles["AdvisoryTitle"]),
        Paragraph(
            "Multi-Agent Cybersecurity Intelligence &amp; Dynamic Threat Triage System",
            styles["AdvisorySubtitle"],
        ),
        Spacer(1, 14),
    ]

    summary_table = Table(
        [
            ["CVE ID", cve_id, "Priority", priority_code],
            ["CVSS (static)", f"{risk['CVSS']}", "Fused Risk Score", f"{risk['FUSED_SCORE']:.2f} / 10"],
        ],
        colWidths=[1.3 * inch, 1.9 * inch, 1.4 * inch, 1.4 * inch],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (3, 0), (3, 0), priority_color),
        ("TEXTCOLOR", (3, 1), (3, 1), priority_color),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTNAME", (3, 0), (3, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.extend(_markdown_to_flowables(result["report_markdown"], styles))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Paragraph(
        f"Generated {result.get('timestamp', '')} — evidence sourced from NVD, "
        "Exa live web search, and CISA KEV.",
        styles["AdvisorySubtitle"],
    ))

    doc.build(story)
    return output_path


if __name__ == "__main__":
    # Quick smoke test with a fabricated result, so you can sanity-check
    # the PDF layout without running the full agent pipeline.
    fake_result = {
        "cve_id": "CVE-2021-44228",
        "timestamp": "2026-09-19T12:00:00+00:00",
        "risk_data": {"CVSS": 10.0, "FUSED_SCORE": 9.8, "PRIORITY": "P0"},
        "report_markdown": (
            "# CVE Summary\n"
            "- CVE: CVE-2021-44228\n"
            "- Severity: CRITICAL\n"
            "- CVSS Score: 10.0\n"
            "- Description: Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP.\n\n"
            "# Fused Risk Score & Priority\n"
            "- Fused Risk Score: 9.80\n"
            "- Priority: P0\n"
            "- Exploit Maturity: 1.0\n"
            "- Days Since Latest Evidence: 0\n\n"
            "# Supporting Evidence\n"
            "- https://nvd.nist.gov/vuln/detail/CVE-2021-44228\n\n"
            "# CISA KEV Ground Truth\n"
            "- CISA KEV confirms this CVE is actively exploited.\n\n"
            "# Remediation Steps\n"
            "- Apply the vendor-provided security update.\n"
            "- Validate the installed version after remediation.\n"
        ),
    }
    generate_pdf(fake_result, "smoke_test_advisory.pdf")
    print("Wrote smoke_test_advisory.pdf")
