import requests

from tools.version_matcher import version_in_range

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cpe_matches_product(cpe, vendor, product):
    parts = cpe.split(":")

    if len(parts) < 6:
        return False

    return (
        parts[2].lower() == "a"
        and parts[3].lower() == vendor.lower()
        and parts[4].lower() == product.lower()
    )


def cpe_match_applies(match, vendor, product, installed_version):
    if not match.get("vulnerable", False):
        return False

    criteria = match.get("criteria", "")

    if not cpe_matches_product(criteria, vendor, product):
        return False

    parts = criteria.split(":")

    if len(parts) > 5:
        cpe_version = parts[5]

        if cpe_version not in ("*", "-"):
            return cpe_version == installed_version

    has_range = any(
        match.get(field)
        for field in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )

    if has_range:
        return version_in_range(
            installed_version,
            start_including=match.get("versionStartIncluding"),
            start_excluding=match.get("versionStartExcluding"),
            end_including=match.get("versionEndIncluding"),
            end_excluding=match.get("versionEndExcluding"),
        )

    return True


def evaluate_node(node, vendor, product, installed_version):
    """
    Evaluate an NVD configuration node.

    We only need to determine whether the installed
    product/version satisfies a vulnerable CPE condition.

    Non-vulnerable CPE entries for other platforms should
    not cause an otherwise matching vulnerable product
    CPE to become false.
    """

    vulnerable_matches = []

    for match in node.get("cpeMatch", []):
        if cpe_match_applies(
            match,
            vendor,
            product,
            installed_version,
        ):
            vulnerable_matches.append(True)

    for child in node.get("children", []):
        if evaluate_node(
           child,
           vendor,
           product,
           installed_version,
    ):
           vulnerable_matches.append(True)

    for child in node.get("nodes", []):
        if evaluate_node(
          child,
          vendor,
          product,
          installed_version,
    ):
          vulnerable_matches.append(True)

    if not vulnerable_matches:
        result = False
    elif node.get("operator", "OR").upper() == "AND":
        result = all(vulnerable_matches)
    else:
        result = any(vulnerable_matches)

    if node.get("negate", False):
        result = not result

    return result


def _cve_object_affects_version(
    cve,
    vendor,
    product,
    installed_version,
):
    for configuration in cve.get("configurations", []):
        if evaluate_node(
            configuration,
            vendor,
            product,
            installed_version,
        ):
            return True

    return False


def check_cve_affects_version(
    cve_id,
    vendor,
    product,
    installed_version,
):
    response = requests.get(
        NVD_CVE_URL,
        params={"cveId": cve_id},
        timeout=30,
    )

    response.raise_for_status()

    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return False

    return _cve_object_affects_version(
        vulnerabilities[0]["cve"],
        vendor,
        product,
        installed_version,
    )


def check_cve_object_affects_version(
    cve,
    vendor,
    product,
    installed_version,
):
    return _cve_object_affects_version(
        cve,
        vendor,
        product,
        installed_version,
    )


if __name__ == "__main__":
    result = check_cve_affects_version(
        "CVE-2021-44228",
        "apache",
        "log4j",
        "2.14.1",
    )

    print(
        "CVE-2021-44228 affects Log4j 2.14.1:",
        result,
    )