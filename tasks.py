from crewai import Task
from agents import threat_intel_agent, risk_assessment_agent, reflection_agent


def build_tasks(cve_id: str):

    gather_task = Task(
        description=(
            f"Analyze {cve_id} using the NVD and Exa tools.\n\n"
            "Return ONLY these fields:\n"
            "CVE=<CVE ID>\n"
            "CVSS=<number>\n"
            "SEVERITY=<severity>\n"
            "CWE=<CWE IDs>\n"
            "AFFECTED=<product/component>\n"
            "POC=<YES or NO>\n"
            "ACTIVE_EXPLOIT=<YES or NO>\n"
            "LATEST_DATE=<YYYY-MM-DD or UNKNOWN>\n"
            "EVIDENCE=<maximum 3 short source URLs separated by |>\n\n"
            "Keep the response below 800 characters."
        ),
        expected_output=(
            "A compact 9-line structured vulnerability record."
        ),
        agent=threat_intel_agent,
    )

    risk_task = Task(
        description=(
            "Read the Threat Intelligence Analyst output provided in the "
            "task context.\n\n"
            "Determine:\n"
            "- CVSS\n"
            "- Exploit_Maturity: 1.0 if ACTIVE_EXPLOIT=YES, "
            "0.5 if POC=YES and ACTIVE_EXPLOIT=NO, otherwise 0.0\n"
            "- Days since LATEST_DATE\n\n"
            "Use this formula:\n"
            "Fused = (0.5 * CVSS) + "
            "(5.0 * Exploit_Maturity * e^(-0.05 * DAYS))\n"
            "Cap at 10.0.\n\n"
            "Priority: P0 >= 8.5, P1 >= 7.0, P2 >= 5.0, P3 otherwise.\n\n"
            "Return ONLY these 7 lines:\n"
            "CVSS=<number>\n"
            "EXPLOIT_MATURITY=<number>\n"
            "DAYS=<number>\n"
            "FUSED_SCORE=<number>\n"
            "PRIORITY=<P0/P1/P2/P3>\n"
            "JUSTIFICATION=<short sentence>\n"
            "REMEDIATION=<two short actions>"
        ),
        expected_output=(
            "A compact structured risk assessment containing CVSS, "
            "exploit maturity, days, fused score, priority, "
            "justification and remediation."
        ),
        agent=risk_assessment_agent,
        context=[gather_task],
    )

    audit_task = Task(
        description=(
            f"Audit the intelligence and risk assessment for {cve_id}.\n\n"
            "Use the CISA KEV tool to verify active exploitation.\n"
            "Produce a concise final Markdown report with exactly these "
            "sections:\n\n"
            "# CVE Summary\n"
            "# Fused Risk Score & Priority\n"
            "# Supporting Evidence\n"
            "# CISA KEV Ground Truth\n"
            "# Remediation Steps\n\n"
            "Preserve the calculated score and priority. "
            "Do not invent facts."
        ),
        expected_output=(
            "A concise verified Markdown security report with the five "
            "requested sections."
        ),
        agent=reflection_agent,
        context=[gather_task, risk_task],
    )

    return [gather_task, risk_task, audit_task]