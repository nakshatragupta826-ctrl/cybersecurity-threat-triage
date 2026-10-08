"""
Lightweight SQLite storage for scan results and alerts. One file
(triage.db) next to the project, so the dashboard, the background
scanner, and any CLI script all see the same history.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "triage.db"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                cve_id TEXT PRIMARY KEY,
                timestamp TEXT,
                source TEXT,
                software_name TEXT,
                installed_version TEXT,
                cvss REAL,
                fused_score REAL,
                priority TEXT,
                exploit_maturity REAL,
                days_since_evidence INTEGER,
                report_markdown TEXT,
                raw_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                timestamp TEXT,
                priority TEXT,
                fused_score REAL,
                message TEXT
            )
            """
        )


def already_scanned(cve_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM scans WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
        return row is not None


def save_scan(result: dict, source: str = "manual", software_name: str = None, installed_version: str = None):
    risk = result["risk_data"]
    priority_code = str(risk["PRIORITY"]).split(" ")[0]

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scans (
                cve_id, timestamp, source, software_name, installed_version,
                cvss, fused_score, priority, exploit_maturity,
                days_since_evidence, report_markdown, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                timestamp=excluded.timestamp,
                source=excluded.source,
                software_name=excluded.software_name,
                installed_version=excluded.installed_version,
                cvss=excluded.cvss,
                fused_score=excluded.fused_score,
                priority=excluded.priority,
                exploit_maturity=excluded.exploit_maturity,
                days_since_evidence=excluded.days_since_evidence,
                report_markdown=excluded.report_markdown,
                raw_json=excluded.raw_json
            """,
            (
                result["cve_id"], result["timestamp"], source, software_name, installed_version,
                risk["CVSS"], risk["FUSED_SCORE"], priority_code, risk["EXPLOIT_MATURITY"],
                risk["DAYS"], result["report_markdown"], json.dumps(result),
            ),
        )

    if priority_code in ("P0", "P1"):
        add_alert(result["cve_id"], priority_code, risk["FUSED_SCORE"])


def add_alert(cve_id: str, priority: str, fused_score: float):
    message = f"{cve_id} scored {fused_score:.2f} ({priority}) - immediate attention required"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (cve_id, timestamp, priority, fused_score, message) VALUES (?, ?, ?, ?, ?)",
            (cve_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), priority, fused_score, message),
        )


def get_all_scans():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY fused_score DESC, timestamp DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(cve_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
        return dict(row) if row else None


def get_alerts(limit: int = 50):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
