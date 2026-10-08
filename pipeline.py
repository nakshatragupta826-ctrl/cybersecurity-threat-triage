"""
Reusable analysis pipeline: given a CVE ID, runs the full process
(NVD + Exa + KEV evidence -> LLM threat-intel extraction -> deterministic
risk fusion -> LLM risk assessment -> deterministic final report) and
returns a structured result dict instead of printing to stdout.

This mirrors main.py's run() function so the Streamlit dashboard and the
background scanner can reuse the exact same logic without duplicating it,
and without triggering main.py's CLI argument parsing.
"""

from datetime import datetime, timezone

from crewai import Agent, Task

from agents import threat_intel_agent, risk_assessment_agent
from tools.nvd_tool import nvd_lookup
from tools.exa_tool import exa_exploit_search
from tools.kev_tool import kev_check

from main import (
    run_agent_task,
    calculate_risk,
    build_final_report,
)


def analyze_cve(cve_id: str, verbose: bool = False) -> dict:
    """
    Runs the complete 3-agent triage pipeline on a single CVE ID and
    returns a dict with every intermediate artifact plus the final report,
    so callers can store it, alert on it, or render it as a PDF.
    """
    cve_id = cve_id.strip().upper()

    nvd_result = str(nvd_lookup.run(cve_id))
    exa_result = str(exa_exploit_search.run(cve_id))
    kev_result = str(kev_check.run(cve_id))

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
        verbose=verbose,
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
            "If CISA KEV confirms the CVE, ACTIVE_EXPLOIT must be YES."
        ),
        expected_output="Exactly 8 short structured lines.",
        agent=intel_agent,
    )

    intelligence_result = run_agent_task(intel_task)

    risk_data = calculate_risk(intelligence_result, kev_result, exa_result, nvd_result)

    risk_task = Task(
        description=(
            f"Create a concise risk assessment for {cve_id}.\n\n"
            f"CVSS={risk_data['CVSS']}\n"
            f"EXPLOIT_MATURITY={risk_data['EXPLOIT_MATURITY']}\n"
            f"DAYS={risk_data['DAYS']}\n"
            f"FUSED_SCORE={risk_data['FUSED_SCORE']:.2f}\n"
            f"PRIORITY={risk_data['PRIORITY']}\n\n"
            "These values are authoritative.\n"
            "Do not change them.\n\n"
            "Return exactly 4 lines:\n"
            "FUSED_SCORE=<number>\n"
            "PRIORITY=<P0/P1/P2/P3>\n"
            "JUSTIFICATION=<one short sentence>\n"
            "REMEDIATION=<two short actions>"
        ),
        expected_output="Exactly 4 short structured lines.",
        agent=risk_assessment_agent,
    )

    risk_result = run_agent_task(risk_task)

    final_report = build_final_report(cve_id, nvd_result, exa_result, kev_result, risk_data)

    return {
        "cve_id": cve_id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nvd_result": nvd_result,
        "exa_result": exa_result,
        "kev_result": kev_result,
        "intelligence_result": intelligence_result,
        "risk_result": risk_result,
        "risk_data": risk_data,
        "report_markdown": final_report,
    }
