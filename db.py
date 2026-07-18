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
import datetime

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "rapidvuln.db"))

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    email              TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash      TEXT NOT NULL,
    stripe_customer_id TEXT,
    created_at         TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

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
    created_at        TEXT DEFAULT CURRENT_TIMESTAMP,
    user_id           INTEGER
);
CREATE INDEX IF NOT EXISTS idx_jobs_host ON jobs(host);
CREATE INDEX IF NOT EXISTS idx_jobs_stripe_session ON jobs(stripe_session_id);
-- idx_jobs_user is created in _migrate(), not here: on a pre-accounts-feature
-- database, jobs.user_id doesn't exist yet at this point in the script (the
-- CREATE TABLE above is a no-op against an already-existing table), so an
-- index on it here would fail before the ALTER TABLE below ever runs.

CREATE TABLE IF NOT EXISTS monitors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host            TEXT NOT NULL,
    target          TEXT,
    business_name   TEXT,
    scan_type       TEXT DEFAULT 'standard',
    email           TEXT NOT NULL,
    frequency_days  INTEGER DEFAULT 7,
    active          INTEGER DEFAULT 1,
    last_job_id     TEXT,
    last_score      INTEGER,
    last_run_at     TEXT,
    next_run_at     TEXT,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    user_id         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors(active, next_run_at);
CREATE INDEX IF NOT EXISTS idx_monitors_host ON monitors(host);
-- idx_monitors_user is created in _migrate(), same reason as idx_jobs_user above.
"""

# Columns sent back to app.py as-is (no JSON/blob handling needed)
_PLAIN_COLUMNS = [
    "job_id", "host", "target", "business_name", "scan_type", "status", "step",
    "progress", "error", "stripe_session_id", "started_at", "finished_at", "user_id",
]

_HISTORY_COLUMNS = [
    "job_id", "host", "target", "business_name", "status", "risk_score",
    "risk_label", "high_count", "medium_count", "low_count", "paid", "finished_at",
    "user_id",
]

# Tables that predate the accounts feature — existing production databases
# already have these tables without a user_id column, and "CREATE TABLE IF NOT
# EXISTS" in _SCHEMA does nothing for a table that already exists, so the new
# column has to be added explicitly via a one-time ALTER TABLE. Safe to run on
# every startup: _migrate() checks PRAGMA table_info first and only alters a
# table that's actually missing the column.
_MIGRATIONS = {
    "jobs":     ("ALTER TABLE jobs ADD COLUMN user_id INTEGER",
                 "CREATE INDEX IF NOT EXISTS idx_jobs_user ON jobs(user_id)"),
    "monitors": ("ALTER TABLE monitors ADD COLUMN user_id INTEGER",
                 "CREATE INDEX IF NOT EXISTS idx_monitors_user ON monitors(user_id)"),
}


def _migrate(conn: sqlite3.Connection):
    for table, (alter_sql, index_sql) in _MIGRATIONS.items():
        cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if "user_id" not in cols:
            conn.execute(alter_sql)
        # Index creation runs unconditionally (IF NOT EXISTS) — cheap, and
        # covers both the fresh-install case (column already existed via
        # _SCHEMA's CREATE TABLE) and the just-migrated case above.
        conn.execute(index_sql)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _connect() as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)
        conn.commit()


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
                "user_id":           job.get("user_id"),
            }

            conn.execute("""
                INSERT INTO jobs (job_id, host, target, business_name, scan_type, status, step,
                                   progress, error, risk_score, risk_label, high_count, medium_count,
                                   low_count, report_json, pdf, paid, stripe_session_id, started_at,
                                   finished_at, user_id)
                VALUES (:job_id, :host, :target, :business_name, :scan_type, :status, :step,
                        :progress, :error, :risk_score, :risk_label, :high_count, :medium_count,
                        :low_count, :report_json, :pdf, :paid, :stripe_session_id, :started_at,
                        :finished_at, :user_id)
                ON CONFLICT(job_id) DO UPDATE SET
                    host=:host, target=:target, business_name=:business_name, scan_type=:scan_type,
                    status=:status, step=:step, progress=:progress, error=:error,
                    risk_score=:risk_score, risk_label=:risk_label, high_count=:high_count,
                    medium_count=:medium_count, low_count=:low_count, report_json=:report_json,
                    pdf=:pdf, paid=:paid, stripe_session_id=:stripe_session_id,
                    started_at=:started_at, finished_at=:finished_at,
                    user_id=COALESCE(:user_id, user_id)
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


def list_history(host: str = None, limit: int = 100, user_id: int = None) -> list[dict]:
    """Summary rows only (no report/pdf blobs) — cheap enough for a history page.
    Pass user_id to scope results to one account's dashboard (accounts feature) —
    left optional so the existing host-only /history page keeps working unchanged."""
    cols = ", ".join(_HISTORY_COLUMNS)
    with _lock:
        conn = _connect()
        try:
            query = f"SELECT {cols} FROM jobs WHERE status='done'"
            params = []
            if host:
                query += " AND host = ?"
                params.append(host)
            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)
            query += " ORDER BY finished_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [{**dict(r), "paid": bool(r["paid"])} for r in rows]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Users — accounts for the dashboard (scan history / monitor management /
# billing). Passwords are never stored in plain text — only a werkzeug hash,
# generated/verified in app.py.
# ---------------------------------------------------------------------------

def _row_to_user(row: sqlite3.Row) -> dict:
    return dict(row) if row else {}


def create_user(email: str, password_hash: str) -> int:
    """Raises sqlite3.IntegrityError if the email is already registered (the
    UNIQUE COLLATE NOCASE constraint on users.email) — app.py catches this to
    return a friendly "email already in use" error instead of a 500."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, password_hash),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def get_user_by_email(email: str) -> dict:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()
            return _row_to_user(row)
        finally:
            conn.close()


def get_user_by_id(user_id: int) -> dict:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return _row_to_user(row)
        finally:
            conn.close()


def set_user_stripe_customer_id(user_id: int, stripe_customer_id: str):
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE users SET stripe_customer_id = ? WHERE id = ?",
                (stripe_customer_id, user_id),
            )
            conn.commit()
        finally:
            conn.close()


def list_users() -> list:
    """Admin-only listing of every registered account. Deliberately excludes
    password_hash from the returned rows — callers (the admin dashboard) never
    need it and there's no reason to let it leave this module."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, email, stripe_customer_id, created_at FROM users ORDER BY created_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Monitors — recurring scheduled re-scans with score-over-time tracking.
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def _row_to_monitor(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["active"] = bool(d["active"])
    return d


def create_monitor(host: str, target: str, business_name: str, scan_type: str,
                    email: str, frequency_days: int = 7, user_id: int = None) -> int:
    """Register a new recurring monitor. First run is scheduled immediately.
    user_id is optional for backward compatibility with the pre-accounts flow,
    but the dashboard's create-monitor path always passes the logged-in
    account's id (and its own email) — see app.py's ownership-check routes."""
    now = _now_iso()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("""
                INSERT INTO monitors (host, target, business_name, scan_type, email,
                                       frequency_days, active, next_run_at, created_at, user_id)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """, (host, target, business_name, scan_type, email, frequency_days, now, now, user_id))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def list_monitors(email: str = None, host: str = None, user_id: int = None) -> list[dict]:
    with _lock:
        conn = _connect()
        try:
            query = "SELECT * FROM monitors WHERE 1=1"
            params = []
            if email:
                query += " AND email = ?"
                params.append(email)
            if host:
                query += " AND host = ?"
                params.append(host)
            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)
            query += " ORDER BY created_at DESC"
            rows = conn.execute(query, params).fetchall()
            return [_row_to_monitor(r) for r in rows]
        finally:
            conn.close()


def get_monitor(monitor_id: int) -> dict:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM monitors WHERE id = ?", (monitor_id,)).fetchone()
            return _row_to_monitor(row) if row else {}
        finally:
            conn.close()


def due_monitors() -> list[dict]:
    """Active monitors whose next_run_at has already passed."""
    now = _now_iso()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT * FROM monitors WHERE active = 1 AND next_run_at <= ?",
                (now,),
            ).fetchall()
            return [_row_to_monitor(r) for r in rows]
        finally:
            conn.close()


def record_monitor_run(monitor_id: int, job_id: str = None, score: int = None):
    """Called after a monitor's re-scan finishes: stamps the run and schedules the next one.
    Pass job_id=None/score=None when the scan failed — COALESCE keeps the previous
    last_job_id/last_score (a transient failure shouldn't erase score-trend history),
    while last_run_at/next_run_at still advance so a permanently broken target doesn't
    retry in a hot loop."""
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT frequency_days FROM monitors WHERE id = ?", (monitor_id,)).fetchone()
            freq = row["frequency_days"] if row else 7
            now = datetime.datetime.utcnow()
            next_run = (now + datetime.timedelta(days=freq)).isoformat()
            conn.execute("""
                UPDATE monitors
                SET last_job_id = COALESCE(?, last_job_id),
                    last_score  = COALESCE(?, last_score),
                    last_run_at = ?,
                    next_run_at = ?
                WHERE id = ?
            """, (job_id, score, now.isoformat(), next_run, monitor_id))
            conn.commit()
        finally:
            conn.close()


def set_monitor_active(monitor_id: int, active: bool):
    with _lock:
        conn = _connect()
        try:
            conn.execute("UPDATE monitors SET active = ? WHERE id = ?", (1 if active else 0, monitor_id))
            conn.commit()
        finally:
            conn.close()


def delete_monitor(monitor_id: int):
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
            conn.commit()
        finally:
            conn.close()
