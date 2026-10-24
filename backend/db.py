"""SQLite database management for VulnExplain scans and vulnerability findings.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "vulnexplain.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes SQLite database schema if not present."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        repo_url TEXT NOT NULL,
        status TEXT NOT NULL,         -- queued, running, done, failed
        progress INTEGER DEFAULT 0,  -- 0 to 100 percent
        summary_json TEXT,           -- counts by severity, language, total
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        file TEXT NOT NULL,
        func_name TEXT NOT NULL,
        start_line INTEGER NOT NULL,
        end_line INTEGER NOT NULL,
        prob REAL NOT NULL,
        cwe TEXT NOT NULL,
        severity TEXT NOT NULL,
        code TEXT NOT NULL,
        suspicious_lines_json TEXT,
        flow_mermaid TEXT,
        explanation_json TEXT,
        fix_diff TEXT,
        validation_json TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );
    """)
    columns = {row[1] for row in cur.execute("PRAGMA table_info(findings)")}
    for name in ("language", "prediction_source"):
        if name not in columns:
            cur.execute(f"ALTER TABLE findings ADD COLUMN {name} TEXT DEFAULT ''")

    conn.commit()
    conn.close()


def create_scan(scan_id: str, repo_url: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (id, repo_url, status, progress, summary_json) VALUES (?, ?, ?, ?, ?)",
        (scan_id, repo_url, "queued", 0, json.dumps({})),
    )
    conn.commit()
    conn.close()


def update_scan_progress(scan_id: str, progress: int, status: str = "running", summary: dict | None = None, error: str | None = None):
    conn = get_connection()
    cur = conn.cursor()
    if summary is not None:
        cur.execute(
            "UPDATE scans SET progress = ?, status = ?, summary_json = ?, error_message = ? WHERE id = ?",
            (progress, status, json.dumps(summary), error, scan_id),
        )
    else:
        cur.execute(
            "UPDATE scans SET progress = ?, status = ?, error_message = ? WHERE id = ?",
            (progress, status, error, scan_id),
        )
    conn.commit()
    conn.close()


def get_scan(scan_id: str) -> dict[str, Any] | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    res["summary"] = json.loads(res["summary_json"]) if res["summary_json"] else {}
    return res


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    scans = []
    for r in rows:
        d = dict(r)
        d["summary"] = json.loads(d["summary_json"]) if d["summary_json"] else {}
        scans.append(d)
    return scans


def insert_findings(findings: list[dict[str, Any]]):
    conn = get_connection()
    cur = conn.cursor()
    for f in findings:
        cur.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, scan_id, file, func_name, start_line, end_line,
                prob, cwe, severity, code, suspicious_lines_json,
                flow_mermaid, explanation_json, fix_diff, validation_json, language, prediction_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f["id"],
                f["scan_id"],
                f["file"],
                f["func_name"],
                f["start_line"],
                f["end_line"],
                f["prob"],
                f["cwe"],
                f["severity"],
                f["code"],
                json.dumps(f.get("suspicious_lines", [])),
                f.get("flow_mermaid", ""),
                json.dumps(f.get("explanation", {})),
                f.get("fix_diff", ""),
                json.dumps(f.get("validation", {})),
                f.get("language", ""),
                f.get("prediction_source", ""),
            ),
        )
    conn.commit()
    conn.close()


def get_findings_for_scan(scan_id: str) -> list[dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["suspicious_lines"] = json.loads(d["suspicious_lines_json"]) if d["suspicious_lines_json"] else []
        d["explanation"] = json.loads(d["explanation_json"]) if d["explanation_json"] else {}
        d["validation"] = json.loads(d["validation_json"]) if d["validation_json"] else {}
        results.append(d)
    return results


def get_finding(finding_id: str) -> dict[str, Any] | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["suspicious_lines"] = json.loads(d["suspicious_lines_json"]) if d["suspicious_lines_json"] else []
    d["explanation"] = json.loads(d["explanation_json"]) if d["explanation_json"] else {}
    d["validation"] = json.loads(d["validation_json"]) if d["validation_json"] else {}
    return d


def update_finding_fix(finding_id: str, fix_diff: str, validation: dict):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE findings SET fix_diff = ?, validation_json = ? WHERE id = ?",
        (fix_diff, json.dumps(validation), finding_id),
    )
    conn.commit()
    conn.close()


def update_finding_explanation(finding_id: str, explanation: dict):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE findings SET explanation_json = ? WHERE id = ?",
        (json.dumps(explanation), finding_id),
    )
    conn.commit()
    conn.close()


# Ensure DB schema is ready on import
init_db()
