"""
Background self-scanning service.

1. Enumerates installed Windows software.
2. Identifies products supported by PRODUCT_MAP.
3. Handles installed product/version entries.
4. Checks local NVD feeds for CVEs affecting the installed version.
5. Runs newly found CVEs through the 3-agent triage pipeline.
6. Saves results to triage.db.
7. Raises P0/P1 alerts.
"""

import argparse
import threading
import time
import traceback
from datetime import datetime, timezone

import db
from pipeline import analyze_cve

from tools.product_normalizer import (
    PRODUCT_MAP,
    normalize_product,
    normalize_version,
)

from tools.software_inventory import get_installed_software

from tools.vulnerability_discovery import (
    discover_vulnerabilities,
)


# Kept for compatibility with dashboard.py and existing code.
# The scanner itself now discovers installed software automatically.
DEFAULT_TARGETS = [
    key.title() for key in PRODUCT_MAP.keys() if key != "git"
] + ["Git"]


def _beep_alert():
    try:
        import winsound

        winsound.Beep(1000, 400)
        winsound.Beep(1300, 400)

    except Exception:
        pass


def _print_alert_banner(cve_id, risk_data, software_name):
    print("\n" + "!" * 70)
    print(f"! HIGH-RISK VULNERABILITY DETECTED: {cve_id}")
    print(f"! Software: {software_name}")
    print(
        f"! Fused Risk Score: {risk_data['FUSED_SCORE']:.2f}"
        f"   Priority: {risk_data['PRIORITY']}"
    )
    print("!" * 70 + "\n")

    _beep_alert()


def _get_supported_installed_software(log=print):
    """
    Enumerate installed Windows software and return only products
    supported by PRODUCT_MAP.

    Multiple registry entries belonging to the same software are
    de-duplicated by vendor/product/version.

    Python is special because Windows registers many Python components.
    Only the Core Interpreter entry is used.
    """

    inventory = get_installed_software()

    discovered = []
    seen = set()

    for item in inventory:
        name = (item.get("name") or "").strip()
        raw_version = (item.get("version") or "").strip()

        if not name or not raw_version:
            continue

        # Python has many component entries. We only want the
        # actual interpreter entry.
        if name.lower().startswith("python "):
            if "core interpreter" not in name.lower():
                continue

        normalized = normalize_product(name)

        if normalized is None:
            continue

        version = normalize_version(raw_version)

        if not version:
            continue

        vendor = normalized["vendor"]
        product = normalized["product"]

        identity = (vendor, product, version)

        if identity in seen:
            continue

        seen.add(identity)

        discovered.append(
            {
                "software": name,
                "version": version,
                "vendor": vendor,
                "product": product,
            }
        )

    log(
        f"[scanner] Inventory contains {len(inventory)} "
        f"software entries."
    )

    log(
        f"[scanner] {len(discovered)} supported "
        f"software/version entries selected for scanning."
    )

    return discovered


def run_scan_once(targets=None, log=print):
    """
    Run one complete endpoint vulnerability scan.

    The scanner discovers supported software directly from the
    Windows inventory rather than requiring every product to have
    an exact hard-coded target name.

    'targets' is retained for dashboard compatibility. If supplied,
    only matching normalized product names are scanned.
    """

    db.init_db()

    new_results = []

    installed_software = _get_supported_installed_software(log=log)

    # Optional filtering for callers such as the dashboard.
    if targets:
        target_names = {
            str(target).lower().strip()
            for target in targets
        }

        filtered = []

        for item in installed_software:
            software_name = item["software"].lower().strip()
            product_name = item["product"].lower().strip()

            matched = False

            for target in target_names:
                if target in software_name:
                    matched = True
                    break

            if not matched:
                # Also allow normalized product names such as
                # "chrome", "git", "python", etc.
                for target in target_names:
                    if target == product_name:
                        matched = True
                        break

            if matched:
                filtered.append(item)

        installed_software = filtered

    for item in installed_software:

        software_name = item["software"]
        version = item["version"]
        vendor = item["vendor"]
        product = item["product"]

        log(
            f"[scanner] Checking {software_name} "
            f"{version} → {vendor}/{product}"
        )

        try:
            candidates = discover_vulnerabilities(
                vendor,
                product,
                version,
            )

        except Exception as e:
            log(
                f"[scanner] Failed to check "
                f"{software_name} {version}: {e}"
            )
            continue

        log(
            f"[scanner] {software_name} {version}: "
            f"{len(candidates)} candidate CVE(s) "
            f"in local feed"
        )

        if not candidates:
            log(
                f"[scanner] {software_name} {version}: "
                f"No matching vulnerabilities detected."
            )

            continue

        for candidate in candidates:

            cve_id = candidate["id"]

            if db.already_scanned(cve_id):
                log(
                    f"[scanner] {cve_id} already exists "
                    f"in database — skipping."
                )
                continue

            log(
                f"[scanner] New CVE found: {cve_id} — "
                f"running full triage pipeline..."
            )

            try:
                result = analyze_cve(cve_id)

            except Exception:
                log(
                    f"[scanner] Failed to analyze "
                    f"{cve_id}:\n"
                    f"{traceback.format_exc()}"
                )
                continue

            db.save_scan(
                result,
                source="auto-scan",
                software_name=software_name,
                installed_version=version,
            )

            new_results.append(result)

            risk = result["risk_data"]

            priority_code = str(
                risk["PRIORITY"]
            ).split(" ")[0]

            if priority_code in ("P0", "P1"):

                _print_alert_banner(
                    cve_id,
                    risk,
                    software_name,
                )

            else:

                log(
                    f"[scanner] {cve_id} triaged: "
                    f"score={risk['FUSED_SCORE']:.2f} "
                    f"priority={priority_code}"
                )

    log(
        f"[scanner] Scan pass complete. "
        f"{len(new_results)} new CVE(s) triaged."
    )

    return new_results


class BackgroundScanner:
    """Runs run_scan_once() repeatedly in a daemon thread."""

    def __init__(
        self,
        targets=None,
        interval_seconds=3600,
        log=print,
    ):
        self.targets = targets
        self.interval_seconds = interval_seconds
        self.log = log

        self._stop_event = threading.Event()
        self._thread = None

    def _loop(self):

        while not self._stop_event.is_set():

            self.log(
                "[scanner] Starting scan pass at "
                f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}"
            )

            try:
                run_scan_once(
                    self.targets,
                    log=self.log,
                )

            except Exception:
                self.log(
                    "[scanner] Scan pass failed:\n"
                    f"{traceback.format_exc()}"
                )

            self._stop_event.wait(
                self.interval_seconds
            )

    def start(self):

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
        )

        self._thread.start()

    def stop(self):
        self._stop_event.set()

    @property
    def running(self):
        return bool(
            self._thread
            and self._thread.is_alive()
        )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Background vulnerability self-scanner"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Seconds between scan passes (default 3600)",
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan pass and exit",
    )

    args = parser.parse_args()

    if args.once:

        run_scan_once()

    else:

        scanner = BackgroundScanner(
            interval_seconds=args.interval
        )

        scanner.start()

        print(
            f"[scanner] Running in background every "
            f"{args.interval}s. Press Ctrl+C to stop."
        )

        try:

            while True:
                time.sleep(1)

        except KeyboardInterrupt:

            scanner.stop()
            print("[scanner] Stopped.")