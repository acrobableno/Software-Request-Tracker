"""SQLite storage for software requests."""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "requests.db"

STATUSES = ["Pending Review", "Approved", "Approved with Conditions", "Rejected"]


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                requester_name TEXT NOT NULL,
                requester_email TEXT,
                department TEXT,
                software_name TEXT NOT NULL,
                requested_version TEXT,
                platform TEXT,
                purpose TEXT,
                status TEXT NOT NULL DEFAULT 'Pending Review',
                reviewer_notes TEXT,
                latest_version TEXT,
                risk_level TEXT,
                check_json TEXT,
                checked_at TEXT,
                submitted_by TEXT
            )"""
        )
        columns = [row[1] for row in conn.execute("PRAGMA table_info(requests)")]
        if "submitted_by" not in columns:  # databases created before login accounts existed
            conn.execute("ALTER TABLE requests ADD COLUMN submitted_by TEXT")


def add_request(requester_name, requester_email, department, software_name,
                requested_version, platform, purpose, submitted_by=None):
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO requests (created_at, requester_name, requester_email, department,
               software_name, requested_version, platform, purpose, submitted_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(timespec="seconds"), requester_name, requester_email,
             department, software_name, requested_version, platform, purpose, submitted_by),
        )
        return cur.lastrowid


def get_request(request_id):
    with _connect() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    return dict(row) if row else None


def list_requests(submitted_by=None):
    with _connect() as conn:
        if submitted_by:
            rows = conn.execute("SELECT * FROM requests WHERE submitted_by = ? ORDER BY id DESC",
                                (submitted_by,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM requests ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def save_check(request_id, findings):
    with _connect() as conn:
        conn.execute(
            """UPDATE requests SET latest_version = ?, risk_level = ?, check_json = ?, checked_at = ?
               WHERE id = ?""",
            ((findings.get("latest") or {}).get("version"), findings["risk"]["level"],
             json.dumps(findings), findings["checked_at"], request_id),
        )


def update_status(request_id, status, reviewer_notes):
    with _connect() as conn:
        conn.execute("UPDATE requests SET status = ?, reviewer_notes = ? WHERE id = ?",
                     (status, reviewer_notes, request_id))
