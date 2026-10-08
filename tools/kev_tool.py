import requests
from crewai.tools import tool

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache = {"data": None}


def _load_kev():
    if _kev_cache["data"] is None:
        resp = requests.get(KEV_URL, timeout=20)
        resp.raise_for_status()
        _kev_cache["data"] = resp.json().get("vulnerabilities", [])
    return _kev_cache["data"]


def get_kev_record(cve_id: str):
    """
    Returns structured CISA KEV information for a CVE.
    Returns is_kev=False when the CVE is not in the catalog.
    """
    cve_id = cve_id.strip().upper()

    try:
        vulns = _load_kev()
    except Exception:
        return None

    for v in vulns:
        if v.get("cveID", "").upper() == cve_id:
            return {
                "cve_id": cve_id,
                "is_kev": True,
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "known_ransomware": v.get(
                    "knownRansomwareCampaignUse"
                ),
                "required_action": v.get(
                    "requiredAction"
                ),
            }

    return {
        "cve_id": cve_id,
        "is_kev": False,
        "vendor": None,
        "product": None,
        "date_added": None,
        "due_date": None,
        "known_ransomware": None,
        "required_action": None,
    }


@tool("CISA KEV Ground Truth Check")
def kev_check(cve_id: str) -> str:
    """
    Checks whether a CVE ID appears in CISA's Known Exploited Vulnerabilities
    (KEV) catalog - the authoritative U.S. government list of vulnerabilities
    confirmed to be actively exploited in the wild. Returns ground-truth
    confirmation plus the required remediation due date if listed.
    Input should be a CVE ID.
    """
    cve_id = cve_id.strip().upper()

    try:
        vulns = _load_kev()
    except Exception as e:
        return f"Could not reach CISA KEV feed: {e}"

    for v in vulns:
        if v.get("cveID", "").upper() == cve_id:
            return (
                f"GROUND TRUTH: {cve_id} IS in the CISA KEV catalog "
                f"(confirmed actively exploited).\n"
                f"Vendor/Product: {v.get('vendorProject')} / {v.get('product')}\n"
                f"Date Added: {v.get('dateAdded')}\n"
                f"Required Action: {v.get('requiredAction')}\n"
                f"Due Date: {v.get('dueDate')}"
            )

    return f"GROUND TRUTH: {cve_id} is NOT currently in the CISA KEV catalog."