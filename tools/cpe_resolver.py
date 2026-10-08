import requests
import time

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def find_cpes(vendor, product, limit=20):
    """
    Find candidate NVD application CPEs for a vendor/product pair.

    Only returns CPEs where:
    - CPE part is 'a' (application)
    - vendor matches exactly
    - product matches exactly
    """

    keyword = f"{vendor} {product}"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(limit, 2000),
    }

    response = None

    for attempt in range(5):
        response = requests.get(
            NVD_CPE_URL,
            params=params,
            timeout=30,
        )

        if response.status_code != 429:
            break

        wait_seconds = 6 * (attempt + 1)

        print(
            f"NVD rate limit hit. "
            f"Waiting {wait_seconds}s..."
        )

        time.sleep(wait_seconds)

    if response is None:
        raise RuntimeError("NVD CPE request failed.")

    response.raise_for_status()

    data = response.json()

    cpes = []

    for item in data.get("products", []):

        cpe_names = item.get("cpe", {}).get("cpeName", [])

        if isinstance(cpe_names, str):
            cpe_names = [cpe_names]

        for cpe in cpe_names:

            parts = cpe.split(":")

            if len(parts) < 6:
                continue

            cpe_part = parts[2].lower()
            cpe_vendor = parts[3].lower()
            cpe_product = parts[4].lower()

            # Only applications
            if cpe_part != "a":
                continue

            # Exact vendor/product match
            if cpe_vendor != vendor.lower():
                continue

            if cpe_product != product.lower():
                continue

            cpes.append(cpe)

    return cpes


if __name__ == "__main__":

    print("--- GIT ---")

    git_results = find_cpes(
        "git",
        "git",
        limit=20,
    )

    for cpe in git_results:
        print(cpe)

    print()
    print("--- CHROME ---")

    chrome_results = find_cpes(
        "google",
        "chrome",
        limit=20,
    )

    for cpe in chrome_results:
        print(cpe)