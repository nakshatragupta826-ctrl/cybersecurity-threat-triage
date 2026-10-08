import argparse
import re
from datetime import date, datetime

from crewai import Agent, Crew, Process, Task

from agents import (
    threat_intel_agent,
    risk_assessment_agent,
)

from tools.nvd_tool import nvd_lookup
from tools.exa_tool import exa_exploit_search
from tools.kev_tool import kev_check

from risk_fusion import (
    RiskFusionInputs,
    compute_fused_score,
    priority_from_score_with_kev,
)


def run_agent_task(task):
    crew = Crew(
        agents=[task.agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )

    return str(crew.kickoff())


def parse_intelligence(text):
    data = {}

    for line in str(text).splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()

    return data


def extract_cvss(nvd_text):
    match = re.search(r"Base Score:\s*([0-9.]+)", nvd_text)

    if match:
        return float(match.group(1))

    return None


def extract_latest_exa_date(exa_text):
    dates = re.findall(
        r"EVIDENCE\|(\d{4}-\d{2}-\d{2})\|",
        exa_text,
    )

    if not dates:
        return "UNKNOWN"

    return max(dates)


def extract_urls(exa_text):
    urls = re.findall(
        r"https?://[^\s|]+",
        exa_text,
    )

    clean = []

    for url in urls:
        url = url.rstrip(".,)")

        if url not in clean:
            clean.append(url)

    return clean[:3]


def calculate_risk(intel_output, kev_result, exa_result, nvd_result):

    data = parse_intelligence(intel_output)

    try:
        cvss = float(data["CVSS"])
    except (KeyError, ValueError):
        cvss = extract_cvss(nvd_result)

    if cvss is None:
        raise ValueError("Could not determine CVSS score.")

    kev_active = "IS in the CISA KEV catalog" in kev_result

    if kev_active:
        exploit_maturity = 1.0
        active_exploit = "YES"

    else:
        active_exploit = data.get(
            "ACTIVE_EXPLOIT",
            "NO",
        ).upper()

        if active_exploit == "YES":
            exploit_maturity = 1.0

        elif data.get("POC", "NO").upper() == "YES":
            exploit_maturity = 0.5

        else:
            exploit_maturity = 0.0

    latest_date_text = data.get(
        "LATEST_DATE",
        "UNKNOWN",
    )

    exa_latest = extract_latest_exa_date(exa_result)

    if exa_latest != "UNKNOWN":
        latest_date_text = exa_latest

    if latest_date_text == "UNKNOWN":
        days = 0

    else:
        latest_date = datetime.strptime(
            latest_date_text,
            "%Y-%m-%d",
        ).date()

        days = max(
            (date.today() - latest_date).days,
            0,
        )

    inputs = RiskFusionInputs(
        base_cvss=cvss,
        exploit_maturity=exploit_maturity,
        days_since_evidence=days,
    )

    score = compute_fused_score(inputs)

    priority = priority_from_score_with_kev(score, kev_active).split(" ")[0]
    return {
        "CVSS": cvss,
        "EXPLOIT_MATURITY": exploit_maturity,
        "ACTIVE_EXPLOIT": active_exploit,
        "DAYS": days,
        "LATEST_DATE": latest_date_text,
        "FUSED_SCORE": score,
        "PRIORITY": priority,
    }


def build_final_report(
    cve_id,
    nvd_result,
    exa_result,
    kev_result,
    risk_data,
):
    evidence_urls = extract_urls(exa_result)

    description = "No NVD description available."
    if isinstance(nvd_result, str) and "Description:" in nvd_result:
        description = nvd_result.split("Description:", 1)[1].split("\n", 1)[0].strip()

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
    lines.append(f"- Days Since Latest Evidence: {risk_data['DAYS']}")

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

    return "\n".join(lines)


def run(cve_id):

    print(
        f"\n=== Running Multi-Agent Triage for {cve_id} ===\n"
    )

    print("=== Collecting NVD data ===\n")

    nvd_result = str(
        nvd_lookup.run(cve_id)
    )

    print(nvd_result)

    print("\n=== Collecting Exa web intelligence ===\n")

    exa_result = str(
        exa_exploit_search.run(cve_id)
    )

    print(exa_result)

    print("\n=== Checking CISA KEV ===\n")

    kev_result = str(
        kev_check.run(cve_id)
    )

    print(kev_result)

    # ---------------------------------------------------------
    # AGENT 1: THREAT INTELLIGENCE
    # ---------------------------------------------------------

    intel_agent = Agent(
        role="Threat Intelligence Analyst",
        goal=(
            "Extract accurate structured vulnerability intelligence "
            "from verified NVD, Exa and CISA KEV evidence."
        ),
        backstory=(
            "You are a meticulous cybersecurity intelligence analyst. "
            "Use only supplied evidence and never invent facts."
        ),
        tools=[],
        llm=threat_intel_agent.llm,
        verbose=True,
        allow_delegation=False,
    )

    intel_task = Task(
        description=(
            f"Analyze {cve_id} using the verified evidence below.\n\n"
            f"NVD:\n{nvd_result}\n\n"
            f"EXA:\n{exa_result}\n\n"
            f"CISA KEV:\n{kev_result}\n\n"
            "Return exactly these 8 lines:\n"
            "CVE=<CVE ID>\n"
            "CVSS=<number>\n"
            "SEVERITY=<severity>\n"
            "CWE=<CWE IDs>\n"
            "AFFECTED=<product/component>\n"
            "POC=<YES or NO>\n"
            "ACTIVE_EXPLOIT=<YES or NO>\n"
            "LATEST_DATE=<YYYY-MM-DD>\n\n"
            "If CISA KEV confirms the CVE, "
            "ACTIVE_EXPLOIT must be YES."
        ),
        expected_output=(
            "Exactly 8 short structured lines."
        ),
        agent=intel_agent,
    )

    intelligence_result = run_agent_task(
        intel_task
    )

    print(
        "\n=== THREAT INTELLIGENCE OUTPUT ===\n"
    )

    print(intelligence_result)

    # ---------------------------------------------------------
    # DETERMINISTIC RISK ENGINE
    # ---------------------------------------------------------

    risk_data = calculate_risk(
        intelligence_result,
        kev_result,
        exa_result,
        nvd_result,
    )

    print(
        "\n=== DETERMINISTIC RISK CALCULATION ===\n"
    )

    print(f"CVSS: {risk_data['CVSS']}")
    print(
        f"Exploit Maturity: "
        f"{risk_data['EXPLOIT_MATURITY']}"
    )
    print(
        f"Active Exploit: "
        f"{risk_data['ACTIVE_EXPLOIT']}"
    )
    print(
        f"Days Since Evidence: "
        f"{risk_data['DAYS']}"
    )
    print(
        f"Latest Evidence Date: "
        f"{risk_data['LATEST_DATE']}"
    )
    print(
        f"Fused Score: "
        f"{risk_data['FUSED_SCORE']:.2f}"
    )
    print(
        f"Priority: "
        f"{risk_data['PRIORITY']}"
    )

    # ---------------------------------------------------------
    # AGENT 2: RISK ASSESSMENT
    # ---------------------------------------------------------

    risk_task = Task(
        description=(
            f"Create a concise risk assessment for {cve_id}.\n\n"
            f"CVSS={risk_data['CVSS']}\n"
            f"EXPLOIT_MATURITY="
            f"{risk_data['EXPLOIT_MATURITY']}\n"
            f"DAYS={risk_data['DAYS']}\n"
            f"FUSED_SCORE="
            f"{risk_data['FUSED_SCORE']:.2f}\n"
            f"PRIORITY={risk_data['PRIORITY']}\n\n"
            "These values are authoritative.\n"
            "Do not change them.\n\n"
            "Return exactly 4 lines:\n"
            "FUSED_SCORE=<number>\n"
            "PRIORITY=<P0/P1/P2/P3>\n"
            "JUSTIFICATION=<one short sentence>\n"
            "REMEDIATION=<two short actions>"
        ),
        expected_output=(
            "Exactly 4 short structured lines."
        ),
        agent=risk_assessment_agent,
    )

    risk_result = run_agent_task(
        risk_task
    )

    print(
        "\n=== RISK ASSESSMENT OUTPUT ===\n"
    )

    print(risk_result)

    # ---------------------------------------------------------
    # DETERMINISTIC FINAL REPORT
    # ---------------------------------------------------------

    final_report = build_final_report(
        cve_id,
        nvd_result,
        exa_result,
        kev_result,
        risk_data,
    )

    print(
        "\n=== FINAL VERIFIED REPORT ===\n"
    )

    print(final_report)

    return final_report


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Multi-Agent Cybersecurity Intelligence "
            "& Dynamic Threat Triage System"
        )
    )

    parser.add_argument(
        "cve_id",
        help="CVE ID to analyze, e.g. CVE-2021-44228",
    )

    args = parser.parse_args()

    run(args.cve_id)
