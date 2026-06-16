"""
db.py — SQLite-backed persistence for scan jobs.

Replaces the old in-memory dict job store so jobs survive a server restart,
and gives us a place to track Stripe payment status and scan history per
domain. set_job()/get_job() mirror the old dict.update()/dict.get() semantics
so callers in app.py don't need to change.
"""
import os
import json
import sqlite3
import threading

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "rapidvuln.db"))

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id            TEXT PRIMARY KEY,
    host              TEXT,
    target            TEXT,
    business_name     TEXT,
    scan_type         TEXT,
    status            TEXT,
    step              TEXT,
    progress          INTEGER DEFAULT 0,
    error             TEXT,
    risk_score        INTEGER,
    risk_label        TEXT,
    high_count        INTEGER,
    medium_count      INTEGER,
    low_count         INTEGER,
    report_json       TEXT,
    pdf               BLOB,
    paid              INTEGER DEFAULT 0,
    stripe_session_id TEXT,
    started_at        TEXT,
    finished_at       TEXT,
    created_at        TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_jobs_host ON jobs(host);
CREATE INDEX IF NOT EXISTS idx_jobs_stripe_session ON jobs(stripe_session_id);
"""

# Columns sent back to app.py as-is (no JSON/blob handling needed)
_PLAIN_COLUMNS = [
    "job_id", "host", "target", "business_name", "scan_type", "status", "step",
    "progress", "error", "stripe_session_id", "started_at", "finished_at",
]

_HISTORY_COLUMNS = [
    "job_id", "host", "target", "business_name", "status", "risk_score",
    "risk_label", "high_count", "medium_count", "low_count", "paid", "finished_at",
]


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _connect() as conn:
        conn.executescript(_SCHEMA)


def _row_to_job(row: sqlite3.Row) -> dict:
    job = {col: row[col] for col in _PLAIN_COLUMNS}
    job["report"] = json.loads(row["report_json"]) if row["report_json"] else None
    job["pdf"] = row["pdf"]
    job["paid"] = bool(row["paid"])
    return job


def set_job(job_id: str, update: dict):
    """Merge `update` onto the stored job, creating it if it doesn't exist yet."""
    with _lock:
        conn = _connect()
        try:
            existing = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            job = _row_to_job(existing) if existing else {"job_id": job_id}
            job.update(update)

            report = job.get("report") or {}
            findings = report.get("findings", []) if isinstance(report, dict) else []

            row = {
                "job_id":            job_id,
                "host":              job.get("host"),
                "target":            job.get("target"),
                "business_name":     job.get("business_name"),
                "scan_type":         job.get("scan_type"),
                "status":            job.get("status"),
                "step":              job.get("step"),
                "progress":          job.get("progress", 0),
                "error":             job.get("error"),
                "risk_score":        report.get("risk_score"),
                "risk_label":        report.get("risk_label"),
                "high_count":        sum(1 for f in findings if f.get("severity") == "HIGH"),
                "medium_count":      sum(1 for f in findings if f.get("severity") == "MEDIUM"),
                "low_count":         sum(1 for f in findings if f.get("severity") in ("LOW", "INFO")),
                "report_json":       json.dumps(report) if report else None,
                "pdf":               job.get("pdf"),
                "paid":              1 if job.get("paid") else 0,
                "stripe_session_id": job.get("stripe_session_id"),
                "started_at":        job.get("started_at"),
                "finished_at":       job.get("finished_at"),
            }

            conn.execute("""
                INSERT INTO jobs (job_id, host, target, business_name, scan_type, status, step,
                                   progress, error, risk_score, risk_label, high_count, medium_count,
                                   low_count, report_json, pdf, paid, stripe_session_id, started_at, finished_at)
                VALUES (:job_id, :host, :target, :business_name, :scan_type, :status, :step,
                        :progress, :error, :risk_score, :risk_label, :high_count, :medium_count,
                        :low_count, :report_json, :pdf, :paid, :stripe_session_id, :started_at, :finished_at)
                ON CONFLICT(job_id) DO UPDATE SET
                    host=:host, target=:target, business_name=:business_name, scan_type=:scan_type,
                    status=:status, step=:step, progress=:progress, error=:error,
                    risk_score=:risk_score, risk_label=:risk_label, high_count=:high_count,
                    medium_count=:medium_count, low_count=:low_count, report_json=:report_json,
                    pdf=:pdf, paid=:paid, stripe_session_id=:stripe_session_id,
                    started_at=:started_at, finished_at=:finished_at
            """, row)
            conn.commit()
        finally:
            conn.close()


def get_job(job_id: str) -> dict:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return _row_to_job(row) if row else {}
        finally:
            conn.close()


def get_job_by_stripe_session(session_id: str) -> dict:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM jobs WHERE stripe_session_id = ?", (session_id,)
            ).fetchone()
            return _row_to_job(row) if row else {}
        finally:
            conn.close()


def list_history(host: str = None, limit: int = 100) -> list[dict]:
    """Summary rows only (no report/pdf blobs) — cheap enough for a history page."""
    cols = ", ".join(_HISTORY_COLUMNS)
    with _lock:
        conn = _connect()
        try:
            if host:
                rows = conn.execute(
                    f"SELECT {cols} FROM jobs WHERE status='done' AND host = ? "
                    f"ORDER BY finished_at DESC LIMIT ?",
                    (host, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT {cols} FROM jobs WHERE status='done' "
                    f"ORDER BY finished_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [{**dict(r), "paid": bool(r["paid"])} for r in rows]
        finally:
            conn.close()
