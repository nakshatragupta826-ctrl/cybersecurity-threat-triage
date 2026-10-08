import json
import re
import tempfile
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

import db
from pipeline import analyze_cve
from report_pdf import generate_pdf
from scanner import run_scan_once


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cyber Threat Triage Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# DATABASE
# ============================================================

db.init_db()


# ============================================================
# SESSION STATE
# ============================================================

DEFAULTS = {
    "scan_log": [],
    "auto_scan_enabled": False,
    "auto_scan_interval": 5,
    "last_auto_scan": None,
    "next_auto_scan": None,
    "auto_scan_running": False,
    "last_auto_scan_count": 0,
    "auto_scan_status": "Waiting",
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# HELPERS
# ============================================================

def log(message):
    """Store scanner messages in Streamlit session state."""

    timestamp = datetime.now().strftime("%H:%M:%S")

    entry = f"[{timestamp}] {message}"

    st.session_state.scan_log.append(entry)

    if len(st.session_state.scan_log) > 200:
        st.session_state.scan_log = (
            st.session_state.scan_log[-200:]
        )


def current_time_string():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def _raw_result(scan):
    """
    Return the original pipeline JSON stored in the database.
    """

    try:
        return json.loads(
            scan.get("raw_json") or "{}"
        )
    except Exception:
        return {}


def extract_nvd_field(nvd_text, field_name):
    """
    Extract a field from the stored NVD text.

    Example:

        Severity: HIGH
        CWE: CWE-20
    """

    if not nvd_text:
        return None

    pattern = (
        rf"^{re.escape(field_name)}\s*:\s*(.+?)$"
    )

    match = re.search(
        pattern,
        str(nvd_text),
        flags=re.IGNORECASE | re.MULTILINE,
    )

    if match:
        return match.group(1).strip()

    return None


def extract_agent_field(text, field_name):
    """
    Extract values from agent output.

    Example:

        CVSS=8.8
        ACTIVE_EXPLOIT=YES
    """

    if not text:
        return None

    pattern = (
        rf"^{re.escape(field_name)}\s*=\s*(.+?)$"
    )

    match = re.search(
        pattern,
        str(text),
        flags=re.IGNORECASE | re.MULTILINE,
    )

    if match:
        return match.group(1).strip()

    return None


def extract_nvd_description(raw):
    """
    Extract the complete Description field from nvd_result.

    The database stores NVD information in a string such as:

        CVE ID: ...
        Published: ...
        Description: ...
        CVSS Version: ...
    """

    nvd_text = raw.get(
        "nvd_result",
        "",
    )

    if not nvd_text:
        return ""

    match = re.search(
        r"Description:\s*(.*?)(?=\nCVSS Version:|\nCWE:|\Z)",
        str(nvd_text),
        flags=re.IGNORECASE | re.DOTALL,
    )

    if match:
        return " ".join(
            match.group(1).split()
        ).strip()

    return ""


def extract_cvss_details(raw):
    """
    Extract CVSS score, severity and vector.
    """

    nvd_text = raw.get(
        "nvd_result",
        "",
    )

    result = {
        "score": "N/A",
        "severity": "N/A",
        "vector": "N/A",
    }

    if not nvd_text:
        return result

    match = re.search(
        r"Base Score:\s*([0-9.]+).*?"
        r"Severity:\s*([^,]+).*?"
        r"Vector:\s*(.+)",
        str(nvd_text),
        flags=re.IGNORECASE,
    )

    if match:

        result["score"] = match.group(1).strip()

        result["severity"] = (
            match.group(2)
            .strip()
            .upper()
        )

        result["vector"] = (
            match.group(3)
            .strip()
        )

    return result


def extract_cwe(raw):
    """
    Extract CWE information.

    Supports both:

        CWE: CWE-20

    and:

        CWE: CWE-20, CWE-400, ...
    """

    nvd_text = raw.get(
        "nvd_result",
        "",
    )

    cwe = extract_nvd_field(
        nvd_text,
        "CWE",
    )

    if cwe:
        return cwe

    intelligence = raw.get(
        "intelligence_result",
        "",
    )

    cwe = extract_agent_field(
        intelligence,
        "CWE",
    )

    return cwe or "N/A"


def extract_affected(raw):
    intelligence = raw.get(
        "intelligence_result",
        "",
    )

    affected = extract_agent_field(
        intelligence,
        "AFFECTED",
    )

    return affected or "Not specified"


def extract_exploit_status(raw):
    intelligence = raw.get(
        "intelligence_result",
        "",
    )

    return (
        extract_agent_field(
            intelligence,
            "ACTIVE_EXPLOIT",
        )
        or "UNKNOWN"
    ).upper()


def extract_poc_status(raw):
    intelligence = raw.get(
        "intelligence_result",
        "",
    )

    return (
        extract_agent_field(
            intelligence,
            "POC",
        )
        or "UNKNOWN"
    ).upper()


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def get_priority(scan):
    return str(
        scan.get(
            "priority",
            "P3",
        )
    )


def priority_code(priority):
    match = re.match(
        r"(P[0-3])",
        str(priority),
    )

    return (
        match.group(1)
        if match
        else "P3"
    )


def priority_level(priority):
    code = priority_code(priority)

    return {
        "P0": "CRITICAL",
        "P1": "HIGH",
        "P2": "MEDIUM",
        "P3": "LOW",
    }.get(
        code,
        "LOW",
    )


def priority_icon(priority):
    code = priority_code(priority)

    return {
        "P0": "🔴",
        "P1": "🟠",
        "P2": "🟡",
        "P3": "🟢",
    }.get(
        code,
        "⚪",
    )


def count_priorities(scans):

    counts = {
        "P0": 0,
        "P1": 0,
        "P2": 0,
        "P3": 0,
    }

    for scan in scans:

        code = priority_code(
            get_priority(scan)
        )

        if code in counts:
            counts[code] += 1

    return counts


# ============================================================
# PLAIN-ENGLISH VULNERABILITY EXPLANATION
# ============================================================

def build_vulnerability_explanation(
    cve_id,
    description,
    cwe,
    affected,
    active_exploit,
    poc,
):
    """
    Convert the technical NVD description into a
    simple explanation suitable for the dashboard.

    The explanation is based on the actual CVE description.
    """

    text = (
        description or ""
    ).lower()

    # --------------------------------------------------------
    # Specific known vulnerability patterns
    # --------------------------------------------------------

    if (
        "cve-2021-44228" in cve_id.lower()
        or (
            "log4j" in text
            and (
                "jndi" in text
                or "ldap" in text
            )
        )
    ):

        what_is_it = (
            "This is the famous Log4Shell vulnerability in "
            "Apache Log4j. Log4j is a Java logging library used "
            "inside many applications. The problem is that "
            "specially crafted data can cause Log4j to make an "
            "unexpected JNDI lookup. Under vulnerable conditions, "
            "this can ultimately allow an attacker to execute "
            "malicious code on the affected server."
        )

        attacker_action = (
            "An attacker may send specially crafted input to an "
            "application that uses a vulnerable version of Log4j. "
            "If the vulnerable logging path processes that input, "
            "the attacker may be able to trigger the vulnerable "
            "JNDI behavior and potentially execute code remotely."
        )

        why_important = (
            "This vulnerability is considered extremely serious "
            "because it can lead to remote code execution. "
            "CVE-2021-44228 also has a CVSS score of 10.0 and "
            "has extensive real-world exploitation history."
        )

    elif (
        (
            "sandbox escape" in text
            or "escape from the sandbox" in text
        )
        and (
            "chrome" in text
            or "chromium" in text
        )
    ):

        what_is_it = (
            "This is a security weakness in Google Chrome's "
            "ANGLE/GPU processing. Chrome uses a security "
            "sandbox to restrict what potentially dangerous "
            "web content can do. The vulnerability can potentially "
            "allow malicious web content to escape those "
            "restrictions."
        )

        attacker_action = (
            "An attacker can create a specially crafted web page "
            "and try to convince a victim to open it. The malicious "
            "page attempts to trigger the vulnerable Chrome "
            "ANGLE/GPU code. Successful exploitation can potentially "
            "help the attacker escape the browser's security sandbox."
        )

        why_important = (
            "The vulnerability affects a security boundary inside "
            "the browser. Your stored threat-intelligence evidence "
            "also indicates active exploitation, which makes the "
            "finding significantly more important."
        )

    elif (
        "remote code execution" in text
        or "arbitrary code execution" in text
        or "execute arbitrary code" in text
    ):

        what_is_it = (
            "This vulnerability can allow an attacker to make the "
            "affected software execute code chosen by the attacker. "
            "In simple terms, the attacker may be able to make the "
            "computer perform actions using attacker-controlled code."
        )

        attacker_action = (
            "The attacker needs to provide specially crafted input "
            "or trigger the vulnerable functionality described by "
            "the CVE. If exploitation succeeds, the attacker's code "
            "may execute in the security context of the affected "
            "application."
        )

        why_important = (
            "Remote or arbitrary code execution is one of the most "
            "serious vulnerability classes because successful "
            "exploitation can give an attacker substantial control "
            "over the affected system or application."
        )

    elif (
        "privilege escalation" in text
        or "elevation of privilege" in text
    ):

        what_is_it = (
            "This vulnerability allows an attacker with limited "
            "permissions to potentially obtain more privileges "
            "than they should have."
        )

        attacker_action = (
            "The attacker first needs to reach the vulnerable "
            "functionality. They then exploit the weakness to "
            "increase their permissions."
        )

        why_important = (
            "Privilege escalation is dangerous because a limited "
            "account can potentially become an administrator-level "
            "or otherwise more powerful account."
        )

    elif (
        "information disclosure" in text
        or "disclose information" in text
    ):

        what_is_it = (
            "This vulnerability can cause the affected software "
            "to expose information that should normally remain "
            "private or protected."
        )

        attacker_action = (
            "The attacker attempts to trigger the vulnerable "
            "functionality and obtain information that the "
            "application should not reveal."
        )

        why_important = (
            "Exposed information can include sensitive application "
            "data, credentials, system details or other information "
            "that can help an attacker continue an attack."
        )

    elif (
        "denial of service" in text
        or "denial-of-service" in text
    ):

        what_is_it = (
            "This vulnerability can allow an attacker to make the "
            "affected software crash, hang or become unavailable."
        )

        attacker_action = (
            "The attacker sends specially crafted input that causes "
            "the vulnerable application or service to fail."
        )

        why_important = (
            "A successful denial-of-service attack can interrupt "
            "applications or services and affect availability."
        )

    elif (
        "use-after-free" in text
        or "out-of-bounds" in text
        or "memory corruption" in text
    ):

        what_is_it = (
            "This is a memory-safety vulnerability. The software "
            "can mishandle memory while processing specially "
            "crafted data."
        )

        attacker_action = (
            "An attacker prepares input designed to trigger the "
            "incorrect memory operation. Depending on the exact "
            "bug, this can potentially cause crashes, information "
            "disclosure or code execution."
        )

        why_important = (
            "Memory-safety vulnerabilities can have serious "
            "consequences because incorrect memory operations "
            "can sometimes be turned into code execution."
        )

    elif (
        "improper input validation" in text
        or "insufficient validation" in text
        or "untrusted input" in text
        or "input validation" in text
    ):

        what_is_it = (
            "The software does not validate some incoming data "
            "carefully enough before processing it. An attacker "
            "can create specially designed input that takes "
            "advantage of this mistake."
        )

        attacker_action = (
            "The attacker prepares specially crafted input and "
            "delivers it through the vulnerable application "
            "functionality. The goal is to make the software "
            "process the input in an unsafe way."
        )

        why_important = (
            "Input-validation problems can become serious when "
            "the attacker-controlled data reaches sensitive "
            "operations such as memory handling, command execution "
            "or security-sensitive processing."
        )

    else:

        what_is_it = (
            "This CVE identifies a specific security weakness "
            "in the affected software. The technical NVD "
            "description explains how the weakness can be "
            "triggered and what security impact it may have."
        )

        attacker_action = (
            "An attacker would attempt to trigger the vulnerable "
            "functionality using the conditions and input "
            "described in the CVE."
        )

        why_important = (
            "The importance of this vulnerability depends on "
            "its CVSS severity, exploitability, affected "
            "software and evidence of real-world exploitation."
        )

    # --------------------------------------------------------
    # CWE explanation
    # --------------------------------------------------------

    cwe_text = str(
        cwe or ""
    ).upper()

    if "CWE-20" in cwe_text:

        cwe_explanation = (
            "CWE-20 means Improper Input Validation. "
            "The software does not properly check whether "
            "incoming data is safe before processing it."
        )

    elif "CWE-787" in cwe_text:

        cwe_explanation = (
            "CWE-787 means Out-of-bounds Write. "
            "The software can potentially write data outside "
            "the memory area it was supposed to use."
        )

    elif "CWE-79" in cwe_text:

        cwe_explanation = (
            "CWE-79 is Cross-Site Scripting (XSS). "
            "It involves untrusted content being interpreted "
            "as executable web content."
        )

    elif "CWE-502" in cwe_text:

        cwe_explanation = (
            "CWE-502 means Deserialization of Untrusted Data. "
            "The application processes data that can potentially "
            "cause unsafe object or code behavior."
        )

    else:

        cwe_explanation = (
            f"{cwe} is the weakness classification recorded "
            "for this vulnerability."
        )

    # --------------------------------------------------------
    # Exploitation explanation
    # --------------------------------------------------------

    if active_exploit == "YES":

        exploit_explanation = (
            "The system has stored evidence indicating active "
            "exploitation of this vulnerability. This increases "
            "its practical risk because the vulnerability is not "
            "merely theoretical."
        )

    elif active_exploit == "NO":

        exploit_explanation = (
            "The stored threat-intelligence evidence does not "
            "indicate active exploitation."
        )

    else:

        exploit_explanation = (
            "The available intelligence does not provide a "
            "definitive active-exploitation status."
        )

    # --------------------------------------------------------
    # PoC explanation
    # --------------------------------------------------------

    if poc == "YES":

        poc_explanation = (
            "A proof-of-concept or exploitation example was "
            "identified in the stored intelligence."
        )

    elif poc == "NO":

        poc_explanation = (
            "No proof-of-concept was identified in the "
            "stored intelligence."
        )

    else:

        poc_explanation = (
            "The stored intelligence does not provide a "
            "definitive proof-of-concept status."
        )

    return {
        "what_is_it": what_is_it,
        "attacker_action": attacker_action,
        "why_important": why_important,
        "cwe_explanation": cwe_explanation,
        "exploit_explanation": exploit_explanation,
        "poc_explanation": poc_explanation,
        "description": description or (
            "NVD description unavailable."
        ),
        "affected": affected,
    }


# ============================================================
# AUTOMATIC SCAN SCHEDULER CALLBACKS
# ============================================================

def auto_scan_toggle_changed():
    """Start/stop the automatic scan schedule when the toggle changes."""

    if st.session_state.auto_scan_enabled:
        interval_seconds = (
            st.session_state.auto_scan_interval * 60
        )

        st.session_state.next_auto_scan = (
            datetime.fromtimestamp(
                time.time() + interval_seconds
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        st.session_state.auto_scan_status = "Waiting"

    else:
        st.session_state.next_auto_scan = None
        st.session_state.auto_scan_running = False
        st.session_state.auto_scan_status = "Waiting"


def auto_scan_interval_changed():
    """Reset the next scheduled run when the interval changes."""

    if st.session_state.auto_scan_enabled:
        interval_seconds = (
            st.session_state.auto_scan_interval * 60
        )

        st.session_state.next_auto_scan = (
            datetime.fromtimestamp(
                time.time() + interval_seconds
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ Scanner Control")

    st.caption(
        "Configure endpoint vulnerability discovery "
        "and automatic scanning."
    )

    st.divider()

    # IMPORTANT:
    # Do not assign the result back to session_state.
    # The widget owns the key.

    st.toggle(
        "Enable automatic scanning",
        key="auto_scan_enabled",
        on_change=auto_scan_toggle_changed,
        help=(
            "Automatically scan installed software "
            "at the selected interval."
        ),
    )

    st.slider(
        "Scan interval",
        min_value=5,
        max_value=240,
        step=5,
        key="auto_scan_interval",
        on_change=auto_scan_interval_changed,
        help="Automatic scan interval in minutes.",
    )

    if st.session_state.auto_scan_enabled:

        st.success(
            "🟢 AUTO SCANNER ON"
        )

        if st.session_state.next_auto_scan:

            st.caption(
                "Next scheduled scan:"
            )

            st.code(
                st.session_state.next_auto_scan
            )

    else:

        st.info(
            "⚪ AUTO SCANNER OFF"
        )

    st.divider()

    st.subheader(
        "Manual Scanner"
    )

    # --------------------------------------------------------
    # Scan Installed Software
    # --------------------------------------------------------

    if st.button(
        "🔍 Scan Installed Software",
        use_container_width=True,
    ):

        st.session_state.scan_log = []

        st.session_state.auto_scan_status = (
            "Running"
        )

        log(
            "[dashboard] Starting installed-software scan."
        )

        with st.spinner(
            "Scanning installed software..."
        ):

            try:

                results = run_scan_once(
                    log=log
                )

                st.session_state.last_auto_scan = (
                    current_time_string()
                )

                st.session_state.last_auto_scan_count = (
                    len(results)
                )

                st.session_state.auto_scan_status = (
                    "Completed"
                )

                log(
                    "[dashboard] Manual scan completed: "
                    f"{len(results)} new CVE(s) triaged."
                )

                st.success(
                    f"Scan complete — "
                    f"{len(results)} new CVE(s)."
                )

            except Exception as exc:

                st.session_state.auto_scan_status = (
                    "Failed"
                )

                log(
                    f"[dashboard] Manual scan failed: {exc}"
                )

                st.error(
                    f"Manual scan failed: {exc}"
                )

    # --------------------------------------------------------
    # Run Auto Scan Now
    # --------------------------------------------------------

    if st.button(
        "⚡ Run Auto-Scan Now",
        use_container_width=True,
    ):

        st.session_state.scan_log = []

        st.session_state.auto_scan_status = (
            "Running"
        )

        log(
            "[dashboard] Manual auto-scan trigger started."
        )

        with st.spinner(
            "Running automatic endpoint scan..."
        ):

            try:

                results = run_scan_once(
                    log=log
                )

                scan_time = (
                    current_time_string()
                )

                st.session_state.last_auto_scan = (
                    scan_time
                )

                interval_seconds = (
                    st.session_state.auto_scan_interval
                    * 60
                )

                next_timestamp = (
                    time.time()
                    + interval_seconds
                )

                st.session_state.next_auto_scan = (
                    datetime.fromtimestamp(
                        next_timestamp
                    ).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                st.session_state.last_auto_scan_count = (
                    len(results)
                )

                st.session_state.auto_scan_status = (
                    "Completed"
                )

                log(
                    "[dashboard] Auto-scan completed: "
                    f"{len(results)} new CVE(s) triaged."
                )

                st.success(
                    f"Auto-scan complete — "
                    f"{len(results)} new CVE(s)."
                )

            except Exception as exc:

                st.session_state.auto_scan_status = (
                    "Failed"
                )

                log(
                    f"[dashboard] Auto-scan failed: {exc}"
                )

                st.error(
                    f"Auto-scan failed: {exc}"
                )

    st.divider()

    st.write(
        "**Scanner status:** "
        f"`{st.session_state.auto_scan_status}`"
    )

    if st.session_state.last_auto_scan:

        st.caption(
            "Last scan: "
            + st.session_state.last_auto_scan
        )

    st.caption(
        "Configured interval: "
        f"{st.session_state.auto_scan_interval} minutes"
    )


# ============================================================
# AUTOMATIC SCANNER
# ============================================================

# Streamlit itself controls the automatic scan frequency.
# When automatic scanning is enabled, this fragment reruns at
# the selected interval. When disabled, run_every becomes None.

auto_scan_run_every = (
    st.session_state.auto_scan_interval * 60
    if st.session_state.auto_scan_enabled
    else None
)


@st.fragment(run_every=auto_scan_run_every)
def automatic_scanner():

    if not st.session_state.auto_scan_enabled:
        return

    # Prevent overlapping scans if a previous scan is still running.
    if st.session_state.auto_scan_running:
        return

    st.session_state.auto_scan_running = True
    st.session_state.auto_scan_status = "Running"

    log(
        "[dashboard] Scheduled auto-scan started."
    )

    try:

        results = run_scan_once(
            log=log
        )

        scan_time = current_time_string()

        st.session_state.last_auto_scan = scan_time
        st.session_state.last_auto_scan_count = len(results)
        st.session_state.auto_scan_status = "Completed"

        # Calculate the next expected scan time for display only.
        # The actual scheduling is controlled by Streamlit's
        # fragment run_every interval above.
        interval_seconds = (
            st.session_state.auto_scan_interval * 60
        )

        next_timestamp = time.time() + interval_seconds

        st.session_state.next_auto_scan = (
            datetime.fromtimestamp(
                next_timestamp
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        log(
            "[dashboard] Scheduled auto-scan completed: "
            f"{len(results)} new CVE(s) triaged."
        )

    except Exception as exc:

        st.session_state.auto_scan_status = "Failed"

        log(
            f"[dashboard] Scheduled auto-scan failed: {exc}"
        )

        # Keep the displayed next-scan time moving forward even
        # if one scan fails. The fragment itself will continue
        # according to run_every.
        interval_seconds = (
            st.session_state.auto_scan_interval * 60
        )

        st.session_state.next_auto_scan = (
            datetime.fromtimestamp(
                time.time() + interval_seconds
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    finally:

        st.session_state.auto_scan_running = False


automatic_scanner()



# ============================================================
# MAIN HEADER
# ============================================================

st.title(
    "🛡️ Cyber Threat Triage Center"
)

st.caption(
    "Multi-Agent Cybersecurity Intelligence & "
    "Dynamic Threat Triage System"
)

st.write(
    "Security operations dashboard for endpoint "
    "vulnerability discovery, CVE intelligence, "
    "exploit evidence and dynamic risk prioritization."
)

st.divider()


# ============================================================
# DATABASE STATISTICS
# ============================================================

try:

    scans = db.get_all_scans()

except Exception as exc:

    scans = []

    st.error(
        f"Database error: {exc}"
    )


counts = count_priorities(
    scans
)


m1, m2, m3, m4 = st.columns(4)

with m1:

    st.metric(
        "Total CVE Analyses",
        len(scans),
    )

with m2:

    st.metric(
        "P0 Critical",
        counts["P0"],
    )

with m3:

    st.metric(
        "P1 High",
        counts["P1"],
    )

with m4:

    st.metric(
        "Auto Scanner",
        (
            "ON"
            if st.session_state.auto_scan_enabled
            else "OFF"
        ),
    )


high_count = (
    counts["P0"]
    + counts["P1"]
)

if high_count:

    st.warning(
        f"⚠️ {high_count} high-priority finding(s) "
        "are currently stored."
    )


# ============================================================
# SCANNER ACTIVITY
# ============================================================

st.divider()

st.header(
    "📡 Scanner Activity"
)

st.caption(
    "Installed-software discovery and vulnerability "
    "matching activity."
)

# Wide center column.
# This keeps the scanner log visually centered.

log_left, log_center, log_right = st.columns(
    [1, 4, 1]
)

with log_center:

    if st.session_state.scan_log:

        st.code(
            "\n".join(
                reversed(
                    st.session_state.scan_log[-35:]
                )
            ),
            language="text",
        )

    else:

        st.info(
            "No scanner activity yet. "
            "Run an endpoint scan to see the scanner activity here."
        )


# ============================================================
# MANUAL CVE ANALYSIS
# ============================================================

st.divider()

st.header(
    "🔎 Manual CVE Analysis"
)

st.caption(
    "Investigate a specific vulnerability using "
    "the multi-agent threat-intelligence pipeline."
)

manual_left, manual_right = st.columns(
    [2, 1]
)

with manual_left:

    manual_cve = st.text_input(
        "CVE ID",
        placeholder="Example: CVE-2021-44228",
    )

    analyze_button = st.button(
        "🧠 Analyze CVE",
        use_container_width=True,
    )

with manual_right:

    st.info(
        "**Important distinction**\n\n"
        "Manual CVE analysis tells you how dangerous "
        "a CVE is. It does not prove that your computer "
        "is vulnerable.\n\n"
        "The automatic scanner performs that endpoint "
        "version check."
    )


if analyze_button:

    cve_id = (
        manual_cve
        .strip()
        .upper()
    )

    if not cve_id:

        st.warning(
            "Please enter a CVE ID."
        )

    elif not re.fullmatch(
        r"CVE-\d{4}-\d{4,}",
        cve_id,
    ):

        st.warning(
            "Invalid CVE format. "
            "Example: CVE-2021-44228"
        )

    else:

        with st.spinner(
            f"Running multi-agent analysis on {cve_id}..."
        ):

            try:

                result = analyze_cve(
                    cve_id
                )

                db.save_scan(
                    result,
                    source="manual",
                )

                st.success(
                    f"{cve_id} analysis completed "
                    "and saved."
                )

            except Exception as exc:

                st.error(
                    f"CVE analysis failed: {exc}"
                )


# ============================================================
# ARCHITECTURE
# ============================================================

st.divider()

st.header(
    "🏗️ How the System Works"
)

st.caption(
    "The platform has two complementary workflows."
)

auto_tab, manual_tab = st.tabs(
    [
        "🔍 Automatic Endpoint Scan",
        "🧠 Manual CVE Analysis",
    ]
)


with auto_tab:

    st.subheader(
        "Automatic Endpoint Vulnerability Discovery"
    )

    st.write(
        "The automatic scanner starts with the software "
        "installed on the computer."
    )

    steps = [
        (
            "1",
            "Inventory",
            "Detect installed Windows software."
        ),
        (
            "2",
            "Normalize",
            "Map software names to vendor/product identifiers."
        ),
        (
            "3",
            "Version Matching",
            "Compare the installed version with NVD affected ranges."
        ),
        (
            "4",
            "CVE Filtering",
            "Keep only vulnerabilities that actually affect the installed version."
        ),
        (
            "5",
            "Threat Intelligence",
            "Investigate exploit evidence, PoCs and active exploitation."
        ),
        (
            "6",
            "Risk Fusion",
            "Combine CVSS and dynamic exploitation evidence."
        ),
        (
            "7",
            "Triage",
            "Assign P0–P3 remediation priority."
        ),
    ]

    for number, title, description in steps:

        with st.container(
            border=True
        ):

            st.markdown(
                f"**{number}. {title}**"
            )

            st.caption(
                description
            )

    st.success(
        "Key principle: a CVE is not considered an "
        "endpoint vulnerability simply because the CVE exists. "
        "The installed software version must match the "
        "affected version range."
    )


with manual_tab:

    st.subheader(
        "Manual CVE Threat Analysis"
    )

    st.write(
        "Manual mode starts with a CVE identifier rather "
        "than installed software."
    )

    manual_steps = [
        "Retrieve NVD vulnerability information.",
        "Extract CVSS, severity and CWE information.",
        "Collect threat-intelligence evidence.",
        "Look for proof-of-concept information.",
        "Check active exploitation evidence.",
        "Check CISA KEV evidence.",
        "Calculate exploit maturity and fused risk.",
        "Generate remediation guidance.",
        "Store the final analysis.",
    ]

    for number, step in enumerate(
        manual_steps,
        start=1,
    ):

        st.write(
            f"**{number}.** {step}"
        )

    st.warning(
        "Manual analysis answers: "
        "\"How dangerous is this CVE?\""
    )

    st.info(
        "Automatic scanning answers: "
        "\"Does this CVE affect software actually installed "
        "on this endpoint?\""
    )


# ============================================================
# THREE AGENTS
# ============================================================

st.divider()

st.header(
    "🤖 Multi-Agent Intelligence Engine"
)

st.caption(
    "Three specialized reasoning roles work together "
    "to produce the final triage result."
)

agent1, agent2, agent3 = st.columns(3)

with agent1:

    with st.container(border=True):

        st.markdown(
            "### 🔎 Agent 1"
        )

        st.subheader(
            "Threat Intelligence Analyst"
        )

        st.caption(
            "Evidence collection"
        )

        st.write(
            "This agent investigates the vulnerability "
            "and gathers the technical and threat context."
        )

        st.markdown(
            "**It looks at:**"
        )

        st.write(
            "• NVD description\n"
            "• CVSS\n"
            "• CWE\n"
            "• Proof of concept\n"
            "• Exploitation evidence\n"
            "• Threat intelligence"
        )

        st.info(
            "Main question: "
            "\"What do we actually know about this vulnerability?\""
        )


with agent2:

    with st.container(border=True):

        st.markdown(
            "### ⚠️ Agent 2"
        )

        st.subheader(
            "Risk Assessment Agent"
        )

        st.caption(
            "Dynamic risk calculation"
        )

        st.write(
            "This agent determines how urgently "
            "the vulnerability should be addressed."
        )

        st.markdown(
            "**It considers:**"
        )

        st.write(
            "• CVSS severity\n"
            "• Exploit maturity\n"
            "• Active exploitation\n"
            "• Evidence freshness\n"
            "• Dynamic risk score"
        )

        st.warning(
            "Main question: "
            "\"How urgently should we respond?\""
        )


with agent3:

    with st.container(border=True):

        st.markdown(
            "### 🧠 Agent 3"
        )

        st.subheader(
            "Reflection Agent"
        )

        st.caption(
            "Quality and consistency review"
        )

        st.write(
            "This agent reviews the assessment to "
            "identify missing evidence or inconsistent reasoning."
        )

        st.markdown(
            "**It checks:**"
        )

        st.write(
            "• Reasoning consistency\n"
            "• Missing evidence\n"
            "• Contradictions\n"
            "• Quality of final assessment"
        )

        st.success(
            "Main question: "
            "\"Does the final assessment make sense?\""
        )


# ============================================================
# FINDINGS
# ============================================================

st.divider()

st.header(
    "🚨 Vulnerability Intelligence"
)

st.caption(
    "Every stored CVE is presented with both "
    "technical evidence and a plain-English explanation."
)


@st.fragment(run_every=30)
def render_scan_results():

    try:

        current_scans = db.get_all_scans()

    except Exception as exc:

        st.error(
            f"Could not load findings: {exc}"
        )

        return

    if not current_scans:

        with st.container(
            border=True
        ):

            st.success(
                "✓ No vulnerability findings stored."
            )

            st.write(
                "Run an endpoint scan or manually analyze "
                "a CVE to populate this section."
            )

        return

    for index, scan in enumerate(
        current_scans
    ):

        cve_id = scan.get(
            "cve_id",
            "Unknown CVE",
        )

        priority = get_priority(
            scan
        )

        risk = safe_float(
            scan.get(
                "fused_score",
                scan.get(
                    "risk_score",
                    0,
                ),
            )
        )

        raw = _raw_result(
            scan
        )

        description = extract_nvd_description(
            raw
        )

        cvss = extract_cvss_details(
            raw
        )

        cwe = extract_cwe(
            raw
        )

        affected = extract_affected(
            raw
        )

        active_exploit = extract_exploit_status(
            raw
        )

        poc = extract_poc_status(
            raw
        )

        explanation = build_vulnerability_explanation(
            cve_id=cve_id,
            description=description,
            cwe=cwe,
            affected=affected,
            active_exploit=active_exploit,
            poc=poc,
        )

        software_name = (
            scan.get(
                "software_name"
            )
            or "Manual CVE analysis"
        )

        installed_version = (
            scan.get(
                "installed_version"
            )
        )

        if installed_version:

            software_display = (
                f"{software_name} · "
                f"Version {installed_version}"
            )

        else:

            software_display = software_name

        # ----------------------------------------------------
        # Finding card
        # ----------------------------------------------------

        with st.container(
            border=True
        ):

            header_left, header_right = st.columns(
                [4, 1]
            )

            with header_left:

                st.markdown(
                    f"## {priority_icon(priority)} {cve_id}"
                )

                st.caption(
                    software_display
                )

            with header_right:

                st.metric(
                    "Fused Risk",
                    f"{risk:.2f}",
                )

            # ------------------------------------------------
            # Metrics
            # ------------------------------------------------

            c1, c2, c3, c4, c5 = st.columns(5)

            with c1:

                st.metric(
                    "Priority",
                    priority_code(priority),
                )

            with c2:

                st.metric(
                    "Risk Level",
                    priority_level(priority),
                )

            with c3:

                st.metric(
                    "CVSS",
                    cvss["score"],
                )

            with c4:

                st.metric(
                    "Severity",
                    cvss["severity"],
                )

            with c5:

                st.metric(
                    "Active Exploit",
                    active_exploit,
                )

            # ------------------------------------------------
            # Plain English explanation
            # ------------------------------------------------

            st.markdown(
                "### 🗣️ What vulnerability is this?"
            )

            st.info(
                explanation["what_is_it"]
            )

            st.markdown(
                "### 🎯 What could an attacker do?"
            )

            st.warning(
                explanation["attacker_action"]
            )

            st.markdown(
                "### 🚨 Why is this important?"
            )

            if active_exploit == "YES":

                st.error(
                    explanation["why_important"]
                    + " "
                    + explanation["exploit_explanation"]
                )

            else:

                st.info(
                    explanation["why_important"]
                    + " "
                    + explanation["exploit_explanation"]
                )

            # ------------------------------------------------
            # Quick evidence
            # ------------------------------------------------

            e1, e2, e3 = st.columns(3)

            with e1:

                if active_exploit == "YES":

                    st.error(
                        "🔴 Active exploitation indicated"
                    )

                elif active_exploit == "NO":

                    st.success(
                        "🟢 No active exploitation indicated"
                    )

                else:

                    st.info(
                        "ℹ️ Exploitation status unknown"
                    )

            with e2:

                if poc == "YES":

                    st.warning(
                        "⚠️ Proof-of-concept evidence found"
                    )

                elif poc == "NO":

                    st.success(
                        "No PoC evidence found"
                    )

                else:

                    st.info(
                        "PoC status unknown"
                    )

            with e3:

                st.info(
                    f"**CWE:** {cwe}"
                )

            # ------------------------------------------------
            # Technical details
            # ------------------------------------------------

            with st.expander(
                "🔬 Technical CVE Details"
            ):

                st.markdown(
                    f"**CVE:** `{cve_id}`"
                )

                st.markdown(
                    f"**Affected component:** "
                    f"{affected}"
                )

                st.markdown(
                    f"**CVSS score:** "
                    f"`{cvss['score']}`"
                )

                st.markdown(
                    f"**Severity:** "
                    f"`{cvss['severity']}`"
                )

                st.markdown(
                    f"**CWE:** "
                    f"`{cwe}`"
                )

                st.markdown(
                    f"**CWE explanation:** "
                    f"{explanation['cwe_explanation']}"
                )

                st.markdown(
                    f"**CVSS vector:** "
                    f"`{cvss['vector']}`"
                )

                st.markdown(
                    f"**Proof of Concept:** "
                    f"`{poc}`"
                )

                st.markdown(
                    f"**Active Exploitation:** "
                    f"`{active_exploit}`"
                )

                st.markdown(
                    "#### Original NVD Description"
                )

                st.write(
                    description
                    or "No NVD description stored."
                )

            # ------------------------------------------------
            # Full agent report
            # ------------------------------------------------

            with st.expander(
                "🧠 View Full Multi-Agent Report"
            ):

                report = scan.get(
                    "report_markdown"
                )

                if not report:

                    report = raw.get(
                        "report_markdown",
                        "No report available.",
                    )

                st.markdown(
                    report
                )

            # ------------------------------------------------
            # Evidence
            # ------------------------------------------------

            with st.expander(
                "📡 View Threat Intelligence Evidence"
            ):

                nvd_result = raw.get(
                    "nvd_result",
                    "No NVD result available.",
                )

                exa_result = raw.get(
                    "exa_result",
                    "No Exa threat-intelligence result available.",
                )

                kev_result = raw.get(
                    "kev_result",
                    "No CISA KEV result available.",
                )

                intelligence_result = raw.get(
                    "intelligence_result",
                    "No agent intelligence result available.",
                )

                evidence_nvd, evidence_exa, evidence_kev, evidence_agent = (
                    st.tabs(
                        [
                            "NVD",
                            "Threat Intelligence",
                            "CISA KEV",
                            "Agent Intelligence",
                        ]
                    )
                )

                with evidence_nvd:

                    st.code(
                        nvd_result,
                        language="text",
                    )

                with evidence_exa:

                    st.code(
                        exa_result,
                        language="text",
                    )

                with evidence_kev:

                    st.code(
                        kev_result,
                        language="text",
                    )

                with evidence_agent:

                    st.code(
                        intelligence_result,
                        language="text",
                    )

            # ------------------------------------------------
            # Scan metadata
            # ------------------------------------------------

            with st.expander(
                "📋 Scan Metadata"
            ):

                meta1, meta2, meta3, meta4 = st.columns(4)

                with meta1:

                    st.caption("Source")

                    st.write(
                        scan.get(
                            "source",
                            "Unknown",
                        )
                    )

                with meta2:

                    st.caption("Timestamp")

                    st.write(
                        scan.get(
                            "timestamp",
                            "Unknown",
                        )
                    )

                with meta3:

                    st.caption("Installed Version")

                    st.write(
                        installed_version
                        or "N/A"
                    )

                with meta4:

                    st.caption("Priority")

                    st.write(
                        priority
                    )

            # ------------------------------------------------
            # PDF report
            # ------------------------------------------------

            st.markdown(
                "### 📄 Advisory Report"
            )

            pdf_col, download_col = st.columns(2)

            pdf_state_key = (
                f"pdf_path_{cve_id}_{index}"
            )

            with pdf_col:

                if st.button(
                    "Generate PDF Advisory",
                    key=f"pdf_{cve_id}_{index}",
                    use_container_width=True,
                ):

                    try:

                        pdf_path = (
                            Path(
                                tempfile.gettempdir()
                            )
                            / f"{cve_id}_advisory.pdf"
                        )

                        generate_pdf(
                            raw,
                            str(pdf_path),
                        )

                        st.session_state[
                            pdf_state_key
                        ] = str(pdf_path)

                        st.success(
                            "PDF advisory generated."
                        )

                    except Exception as exc:

                        st.error(
                            f"PDF generation failed: {exc}"
                        )

            pdf_path = (
                st.session_state.get(
                    pdf_state_key
                )
            )

            if (
                pdf_path
                and Path(pdf_path).exists()
            ):

                with download_col:

                    with open(
                        pdf_path,
                        "rb",
                    ) as pdf_file:

                        st.download_button(
                            "⬇️ Download PDF",
                            data=pdf_file.read(),
                            file_name=(
                                f"{cve_id}_advisory.pdf"
                            ),
                            mime="application/pdf",
                            key=(
                                f"download_{cve_id}_{index}"
                            ),
                            use_container_width=True,
                        )

        if index < len(current_scans) - 1:

            st.divider()


render_scan_results()


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Multi-Agent Cybersecurity Intelligence & Dynamic "
    "Threat Triage System · Local NVD · Exa Threat "
    "Intelligence · CISA KEV"
)
