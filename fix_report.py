from pathlib import Path

p = Path("main.py")
s = p.read_text(encoding="utf-8")

start = s.index("def build_final_report(")
end = s.index("def run(", start)

new = '''def build_final_report(
    cve_id,
    nvd_result,
    exa_result,
    kev_result,
    risk_data,
):
    evidence_urls = extract_urls(exa_result)

    description = "No NVD description available."
    if isinstance(nvd_result, str) and "Description:" in nvd_result:
        description = nvd_result.split("Description:", 1)[1].split("\\n", 1)[0].strip()

    severity = "UNKNOWN"
    if isinstance(nvd_result, str) and "Severity:" in nvd_result:
        severity = nvd_result.split("Severity:", 1)[1].split(",", 1)[0].strip()

    lines = []

    lines.append("# CVE Summary")
    lines.append(f"- CVE: {cve_id}")
    lines.append(f"- Severity: {severity}")
    lines.append(f"- CVSS Score: {risk_data['CVSS']}")
    lines.append(f"- Description: {description}")

    lines.append("")
    lines.append("# Fused Risk Score & Priority")
    lines.append(f"- Fused Risk Score: {risk_data['FUSED_SCORE']:.2f}")
    lines.append(f"- Priority: {risk_data['PRIORITY']}")
    lines.append(f"- Exploit Maturity: {risk_data['EXPLOIT_MATURITY']:.1f}")
    lines.append(f"- Days Since Latest Evidence: {risk_data['DAYS_SINCE_EVIDENCE']}")

    lines.append("")
    lines.append("# Supporting Evidence")

    if evidence_urls:
        for url in evidence_urls:
            lines.append(f"- {url}")
    else:
        lines.append("- No Exa evidence URLs were returned.")

    lines.append("")
    lines.append("# CISA KEV Ground Truth")

    if "IS in the CISA KEV catalog" in kev_result:
        lines.append("- CISA KEV confirms this CVE is actively exploited.")
        lines.append("- Exploit maturity is therefore set to 1.0.")
    else:
        lines.append("- CVE was not found in the CISA KEV catalog.")
        lines.append("- Active exploitation was not confirmed by KEV.")

    lines.append("")
    lines.append("# Remediation Steps")
    lines.append("- Apply the vendor-provided security update for the affected product/version.")
    lines.append("- If immediate patching is not possible, apply available vendor mitigations and reduce exposure.")
    lines.append("- Validate the installed version after remediation.")

    return "\\n".join(lines)


'''

p.write_text(s[:start] + new + s[end:], encoding="utf-8")
print("build_final_report updated successfully.")

