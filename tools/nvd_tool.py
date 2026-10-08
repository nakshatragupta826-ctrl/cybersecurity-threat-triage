import time
import requests
from crewai.tools import tool

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@tool("NVD CVE Lookup")
def nvd_lookup(cve_id: str) -> str:
    """
    Fetches static vulnerability data for a given CVE ID from the National
    Vulnerability Database (NVD). Returns CVSS base score, severity, CWE
    weakness type, and the official description as a formatted string.
    Input should be a CVE ID like 'CVE-2021-44228'.
    """
    from config import NVD_API_KEY

    headers = (
        {"apiKey": NVD_API_KEY}
        if NVD_API_KEY
        and NVD_API_KEY != "your_nvd_api_key_here_optional"
        else {}
    )

    params = {
        "cveId": cve_id.strip().upper()
    }

    # Retry when NVD rate-limits the request.
    resp = None

    for attempt in range(5):
        resp = requests.get(
            NVD_BASE_URL,
            headers=headers,
            params=params,
            timeout=20,
        )

        if resp.status_code != 429:
            break

        wait_seconds = 6 * (attempt + 1)

        print(
            f"  NVD rate limit hit. "
            f"Waiting {wait_seconds}s before retry..."
        )

        time.sleep(wait_seconds)

    if resp is None:
        return f"NVD request failed for {cve_id}."

    if resp.status_code == 404:
        return f"No NVD record found for {cve_id}."

    resp.raise_for_status()

    data = resp.json()

    vulns = data.get("vulnerabilities", [])

    if not vulns:
        return f"No NVD record found for {cve_id}."

    cve = vulns[0]["cve"]

    # Extract English description.
    description = next(
        (
            d["value"]
            for d in cve.get("descriptions", [])
            if d["lang"] == "en"
        ),
        "No description available.",
    )

    # Extract CVSS information.
    metrics = cve.get("metrics", {})

    cvss_info = "No CVSS score available."

    for key in (
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        if key in metrics:
            entry = metrics[key][0]
            m = entry["cvssData"]

            cvss_info = (
                f"CVSS Version: {m.get('version')}, "
                f"Base Score: {m.get('baseScore')}, "
                f"Severity: "
                f"{entry.get('baseSeverity', m.get('baseSeverity', 'N/A'))}, "
                f"Vector: {m.get('vectorString')}"
            )

            break

    # Extract CWE information.
    weaknesses = cve.get("weaknesses", [])

    cwe_list = []

    for weakness in weaknesses:
        for d in weakness.get("description", []):
            if d["lang"] == "en":
                cwe_list.append(d["value"])

    cwe_str = (
        ", ".join(cwe_list)
        if cwe_list
        else "Not classified"
    )

    published = cve.get(
        "published",
        "Unknown",
    )

    last_modified = cve.get(
        "lastModified",
        "Unknown",
    )

    return (
        f"CVE ID: {cve_id.upper()}\n"
        f"Published: {published}\n"
        f"Last Modified: {last_modified}\n"
        f"Description: {description}\n"
        f"{cvss_info}\n"
        f"CWE: {cwe_str}"
    )


def get_nvd_cves_by_date(
    start_date,
    end_date,
    count=100,
):
    """
    Retrieve real CVE IDs published by NVD within a specified date range.
    """
    from config import NVD_API_KEY

    headers = (
        {"apiKey": NVD_API_KEY}
        if NVD_API_KEY
        and NVD_API_KEY != "your_nvd_api_key_here_optional"
        else {}
    )

    params = {
        "pubStartDate": (
            f"{start_date}T00:00:00.000"
        ),
        "pubEndDate": (
            f"{end_date}T23:59:59.999"
        ),
        "resultsPerPage": min(count, 2000),
    }

    # Retry handling for date-based NVD requests as well.
    resp = None

    for attempt in range(5):
        resp = requests.get(
            NVD_BASE_URL,
            headers=headers,
            params=params,
            timeout=30,
        )

        if resp.status_code != 429:
            break

        wait_seconds = 6 * (attempt + 1)

        print(
            f"NVD rate limit hit while retrieving CVEs. "
            f"Waiting {wait_seconds}s before retry..."
        )

        time.sleep(wait_seconds)

    if resp is None:
        raise RuntimeError(
            "NVD request failed."
        )

    resp.raise_for_status()

    data = resp.json()

    return [
        item["cve"]["id"]
        for item in data.get(
            "vulnerabilities",
            [],
        )
        if item.get("cve", {}).get("id")
    ][:count]