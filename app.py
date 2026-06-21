"""
app.py — Flask web server for the AI Security Report Tool.
Run: python app.py
"""
import os
import uuid
import threading
import time
import json
import base64
import requests as http_requests
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   send_file, abort, redirect)
import io

from scanner import resolve_target, validate_target, run_scan, build_scan_summary
from ai_reporter import generate_report, generate_report_fallback
from pdf_generator import build_pdf
from web_checks import run_web_checks
from vuln_checks import run_vuln_checks
from cve_checks import run_cve_checks
from supply_chain_checks import run_supply_chain_checks
import db

try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False

try:
    import stripe
    HAS_STRIPE = True
except ImportError:
    HAS_STRIPE = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")

# Allow Netlify frontend to call this backend
if HAS_CORS:
    CORS(app, resources={r"/*": {"origins": "*"}})

db.init_db()


# ── Security headers (applied to every response) ──────────────────────────────
@app.after_request
def _set_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self';"
    )
    return response


# ── Stripe (optional — payment gate is skipped entirely if unconfigured) ──────
STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID       = os.environ.get("STRIPE_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

if HAS_STRIPE and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


def _payments_enabled() -> bool:
    return bool(HAS_STRIPE and STRIPE_SECRET_KEY and STRIPE_PRICE_ID)


# ── Monitoring (recurring re-scans) ───────────────────────────────────────────
# Used to build a clickable link in monitor-alert emails, which are sent from a
# background thread with no Flask request context (so request.url_root isn't
# available there). Optional — if unset, alert emails just omit the link.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

# How often (seconds) the scheduler wakes up to check for due monitors.
MONITOR_CHECK_INTERVAL_SECONDS = int(os.environ.get("MONITOR_CHECK_INTERVAL_SECONDS", 300))


# ── Job store (SQLite — see db.py; survives restarts, backs scan history) ─────

def _set_job(job_id: str, update: dict):
    db.set_job(job_id, update)


def _get_job(job_id: str) -> dict:
    return db.get_job(job_id)


# ── Background scan worker ────────────────────────────────────────────────────

def _run_job(job_id: str, host: str, target_display: str,
             business_name: str, scan_type: str):
    try:
        # Step 1: Validate
        _set_job(job_id, {"step": "Validating target…", "progress": 5})
        err = validate_target(host)
        if err:
            _set_job(job_id, {"status": "error", "error": err})
            return

        # Step 2: Run nmap
        _set_job(job_id, {"step": "Running port scan…", "progress": 15})
        scan = run_scan(host, scan_type)

        if scan.get("error"):
            _set_job(job_id, {"status": "error", "error": scan["error"]})
            return

        # Step 2b: Web checks (SSL, HTTP headers, DNS)
        _set_job(job_id, {"step": "Checking SSL & web security…", "progress": 40})
        web_findings = []
        try:
            web_findings = run_web_checks(host)
        except Exception as web_err:
            app.logger.warning(f"Web checks failed ({web_err}), continuing without them")

        # Step 2c: Active vulnerability checks (SQLi, XSS, command injection)
        _set_job(job_id, {"step": "Testing for injection vulnerabilities…", "progress": 48})
        try:
            web_findings.extend(run_vuln_checks(host))
        except Exception as vuln_err:
            app.logger.warning(f"Vuln checks failed ({vuln_err}), continuing without them")

        # Step 2d: Known-CVE lookup for detected software versions
        _set_job(job_id, {"step": "Checking for known vulnerabilities (CVEs)…", "progress": 51})
        try:
            web_findings.extend(run_cve_checks(host))
        except Exception as cve_err:
            app.logger.warning(f"CVE checks failed ({cve_err}), continuing without them")

        # Step 2e: Watering-hole / supply-chain script risk (CSP laxity, missing SRI, mixed content)
        _set_job(job_id, {"step": "Checking for watering-hole risks…", "progress": 53})
        try:
            web_findings.extend(run_supply_chain_checks(host))
        except Exception as supply_chain_err:
            app.logger.warning(f"Supply-chain checks failed ({supply_chain_err}), continuing without them")

        # Step 3: Build summary (merge nmap + web findings)
        _set_job(job_id, {"step": "Analysing all findings…", "progress": 55})
        summary = build_scan_summary(scan, extra_findings=web_findings)

        # Step 4: AI report
        _set_job(job_id, {"step": "Generating AI report…", "progress": 70})
        try:
            report = generate_report(summary, business_name, target_display)
        except Exception as ai_err:
            app.logger.warning(f"AI report failed ({ai_err}), using fallback")
            report = generate_report_fallback(summary, business_name, target_display)

        # Step 5: Build PDF
        _set_job(job_id, {"step": "Building PDF…", "progress": 90})
        pdf_bytes = build_pdf(report)

        # Done
        _set_job(job_id, {
            "status":   "done",
            "step":     "Complete",
            "progress": 100,
            "report":   report,
            "pdf":      pdf_bytes,
            "finished_at": datetime.now().isoformat(),
        })

    except Exception as e:
        app.logger.exception(f"Job {job_id} failed")
        _set_job(job_id, {"status": "error", "error": str(e)})


# ── Monitor worker (scheduled re-scans) ───────────────────────────────────────
# Reuses _run_job exactly as-is — a monitor scan is just a normal scan that gets
# its own job_id (so it shows up in /history like any other scan), but is kicked
# off by the scheduler instead of a user clicking "Scan", and records its result
# against the monitor row + sends an alert email when it finishes.

def _run_monitor_scan(monitor: dict):
    monitor_id     = monitor["id"]
    host           = monitor["host"]
    target_display = monitor.get("target") or host
    business_name  = monitor.get("business_name") or ""
    scan_type      = monitor.get("scan_type") or "standard"
    prev_score     = monitor.get("last_score")

    job_id = str(uuid.uuid4())
    _set_job(job_id, {
        "status":   "running",
        "step":     "Starting scheduled re-scan…",
        "progress": 0,
        "target":   target_display,
        "host":     host,
        "business_name": business_name,
        "scan_type":      scan_type,
        "started_at": datetime.now().isoformat(),
    })

    # Run synchronously here — we're already inside our own background thread
    # (started by the scheduler loop below), so there's no need for _run_job
    # to spawn yet another thread.
    _run_job(job_id, host, target_display, business_name, scan_type)

    job    = _get_job(job_id)
    report = job.get("report") or {}
    succeeded = job.get("status") == "done"
    new_score = report.get("risk_score") if succeeded else None

    # On failure, record neither job_id nor score so the monitor keeps pointing
    # at its last *successful* report instead of a broken/empty one.
    db.record_monitor_run(monitor_id, job_id if succeeded else None, new_score)

    if job.get("status") == "done":
        try:
            _send_monitor_alert(monitor, job_id, report, prev_score)
        except Exception as e:
            app.logger.error(f"Monitor alert email failed for monitor {monitor_id}: {e}")
    else:
        app.logger.warning(f"Monitor {monitor_id} scheduled re-scan failed: {job.get('error')}")


def _send_monitor_alert(monitor: dict, job_id: str, report: dict, prev_score):
    """Emails the monitor's owner the result of a scheduled re-scan, highlighting
    the score change since the previous run. No-ops quietly if Resend isn't
    configured, same as the manual /email/<job_id> route."""
    resend_api_key = os.environ.get("RESEND_API_KEY", "")
    if not resend_api_key:
        app.logger.warning("Monitor alert skipped: RESEND_API_KEY not configured")
        return

    to_email = monitor.get("email")
    if not to_email:
        return

    host      = monitor.get("host", "your site")
    new_score = report.get("risk_score", 0)
    risk      = report.get("risk_label", "UNKNOWN")
    risk_color = '#ef4444' if risk in ('CRITICAL', 'HIGH') else '#f59e0b' if risk == 'MEDIUM' else '#10b981'

    if prev_score is None:
        trend_line  = "This is the first scheduled scan for this monitor — future scans will compare against this baseline."
        trend_color = "#94a3b8"
    else:
        delta = new_score - prev_score
        if delta > 0:
            trend_line  = f"⚠️ Risk score went UP {delta} point(s) since the last scan ({prev_score}/10 → {new_score}/10)."
            trend_color = "#ef4444"
        elif delta < 0:
            trend_line  = f"✅ Risk score improved by {abs(delta)} point(s) since the last scan ({prev_score}/10 → {new_score}/10)."
            trend_color = "#10b981"
        else:
            trend_line  = f"No change in risk score since the last scan (steady at {new_score}/10)."
            trend_color = "#94a3b8"

    report_link = f"{PUBLIC_BASE_URL}/report/{job_id}" if PUBLIC_BASE_URL else None
    link_html = (
        f'<p style="margin-top:20px;"><a href="{report_link}" style="color:#00E5FF;">View the full report →</a></p>'
        if report_link else ""
    )

    html_body = f"""
    <html><body style="font-family:sans-serif;background:#07080f;color:#f0f4ff;padding:32px;">
    <div style="max-width:560px;margin:0 auto;">
      <h1 style="color:#00E5FF;font-size:24px;margin-bottom:4px;">⚡ RapidVuln Monitor</h1>
      <p style="color:#94a3b8;margin-bottom:32px;">Scheduled re-scan complete for {host}</p>
      <div style="background:#10131f;border:1px solid #1a2035;border-radius:12px;padding:20px;margin:24px 0;">
        <div style="font-size:48px;font-weight:900;color:{risk_color}">{new_score}/10</div>
        <div style="font-size:18px;font-weight:700;color:{risk_color};margin-bottom:12px;">{risk} RISK</div>
        <p style="color:{trend_color};font-size:14px;margin:0;">{trend_line}</p>
      </div>
      {link_html}
      <p style="color:#4a5568;font-size:11px;margin-top:32px;border-top:1px solid #1a2035;padding-top:16px;">
        You're receiving this because {host} is registered for automatic monitoring on RapidVuln. Scans run automatically — no action needed.
      </p>
    </div>
    </body></html>
    """

    try:
        resp = http_requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": "RapidVuln <reports@rapidvuln.com>",
                "to": [to_email],
                "subject": f"🔁 Monitor Alert — {host} scanned ({risk} RISK {new_score}/10)",
                "html": html_body,
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            app.logger.info(f"Monitor alert emailed to {to_email} for {host}")
        else:
            app.logger.error(f"Monitor alert email failed ({resp.status_code}): {resp.text}")
    except Exception as e:
        app.logger.error(f"Monitor alert email exception: {e}")


def _monitor_scheduler_loop():
    """Background loop: wakes up every MONITOR_CHECK_INTERVAL_SECONDS, finds any
    monitors that are due for a re-scan, and kicks each one off in its own thread.
    Safe to run as a single in-process loop because this app always runs as a
    single process (see Procfile/Dockerfile — `python app.py`, no gunicorn
    workers), so there's no risk of two loops double-firing the same scan."""
    while True:
        try:
            for monitor in db.due_monitors():
                threading.Thread(target=_run_monitor_scan, args=(monitor,), daemon=True).start()
        except Exception as e:
            app.logger.error(f"Monitor scheduler loop error: {e}")
        time.sleep(MONITOR_CHECK_INTERVAL_SECONDS)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or {}
    target       = (data.get("target") or "").strip()
    business_name= (data.get("business_name") or "").strip()
    scan_type    = data.get("scan_type", "standard")

    if not target:
        return jsonify({"error": "Please enter a URL or IP address"}), 400

    if not data.get("authorized"):
        return jsonify({"error": "You must confirm you own or are authorized to scan this site"}), 400

    # Resolve the target
    resolved = resolve_target(target)
    if resolved["error"]:
        return jsonify({"error": resolved["error"]}), 400

    job_id = str(uuid.uuid4())
    _set_job(job_id, {
        "status":   "running",
        "step":     "Starting…",
        "progress": 0,
        "target":   target,
        "host":     resolved["host"],
        "business_name": business_name,
        "scan_type":      scan_type,
        "started_at": datetime.now().isoformat(),
    })

    thread = threading.Thread(
        target=_run_job,
        args=(job_id, resolved["host"], target, business_name, scan_type),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id, "host": resolved["host"]})


@app.route("/status/<job_id>")
def job_status(job_id: str):
    job = _get_job(job_id)
    if not job:
        abort(404)

    resp = {
        "status":   job.get("status", "running"),
        "step":     job.get("step", ""),
        "progress": job.get("progress", 0),
        "error":    job.get("error"),
    }

    if job.get("status") == "done":
        report = job.get("report", {})
        resp["summary"] = {
            "risk_score":   report.get("risk_score", 0),
            "risk_label":   report.get("risk_label", ""),
            "total_ports":  report.get("meta", {}).get("total_ports", 0),
            "high_findings":sum(1 for f in report.get("findings", []) if f.get("severity") == "HIGH"),
        }

    return jsonify(resp)


@app.route("/report/<job_id>")
def view_report(job_id: str):
    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        abort(404)
    report = job.get("report", {})

    # Look up this host's most recent *other* completed scan (if any) so the
    # template can show a "previous scan was X/10" trend note.
    prev_score = None
    host = job.get("host") or report.get("meta", {}).get("host")
    if host:
        for s in db.list_history(host=host, limit=5):
            if s.get("job_id") != job_id and s.get("risk_score") is not None:
                prev_score = s["risk_score"]
                break

    return render_template("report.html", report=report, job_id=job_id, prev_score=prev_score)


@app.route("/checkout/<job_id>")
def checkout(job_id: str):
    """Send the customer to Stripe Checkout before letting them download the PDF.
    If Stripe isn't configured (no STRIPE_SECRET_KEY/STRIPE_PRICE_ID), or the
    report is already paid for, skip straight to the download."""
    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        abort(404)

    if job.get("paid") or not _payments_enabled():
        return redirect(f"/download/{job_id}")

    report = job.get("report", {})
    target = report.get("meta", {}).get("target", job.get("target", "your site"))
    base_url = request.url_root.rstrip("/")

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        success_url=f"{base_url}/payment-success/{job_id}?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{base_url}/report/{job_id}",
        metadata={"job_id": job_id, "target": target},
    )
    _set_job(job_id, {"stripe_session_id": session.id})
    return redirect(session.url, code=303)


@app.route("/payment-success/<job_id>")
def payment_success(job_id: str):
    """Stripe redirects here right after checkout. We verify the session
    synchronously (rather than waiting on the webhook) so the customer isn't
    stuck — the webhook below is just a robustness backstop."""
    job = _get_job(job_id)
    if not job:
        abort(404)

    session_id = request.args.get("session_id", "")
    if session_id and _payments_enabled():
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            if session.payment_status == "paid":
                _set_job(job_id, {"paid": True, "stripe_session_id": session_id})
        except Exception as e:
            app.logger.error(f"Stripe session verify failed: {e}")

    return redirect(f"/download/{job_id}")


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    if not _payments_enabled():
        abort(404)

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        if STRIPE_WEBHOOK_SECRET:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        else:
            event = json.loads(payload)
    except Exception as e:
        app.logger.error(f"Stripe webhook rejected: {e}")
        return jsonify({"error": "invalid signature"}), 400

    if event.get("type") == "checkout.session.completed":
        session = event["data"]["object"]
        job_id = (session.get("metadata") or {}).get("job_id")
        if job_id:
            _set_job(job_id, {"paid": True})

    return jsonify({"received": True})


@app.route("/history")
def history():
    host = (request.args.get("host") or "").strip() or None
    scans = db.list_history(host=host)
    return render_template("history.html", scans=scans, host=host)


@app.route("/download/<job_id>")
def download_pdf(job_id: str):
    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        abort(404)

    if _payments_enabled() and not job.get("paid"):
        return redirect(f"/checkout/{job_id}")

    pdf_bytes = job.get("pdf")
    if not pdf_bytes:
        abort(404)

    report = job.get("report", {})
    host   = report.get("meta", {}).get("host", "scan").replace(".", "-")
    date   = datetime.now().strftime("%Y%m%d")
    filename = f"security-report-{host}-{date}.pdf"

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})


@app.route("/email/<job_id>", methods=["POST"])
def email_report(job_id: str):
    """Send the PDF report via Resend API."""
    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "Report not ready"}), 404

    if _payments_enabled() and not job.get("paid"):
        return jsonify({
            "error": "Payment required before emailing the report",
            "checkout_url": f"/checkout/{job_id}",
        }), 402

    data           = request.get_json(silent=True) or {}
    to_email       = (data.get("email") or "").strip()
    recipient_name = (data.get("name") or "").strip() or "there"
    business_name  = (data.get("business_name") or "").strip()

    if not to_email or "@" not in to_email:
        return jsonify({"error": "Valid email address required"}), 400

    pdf_bytes = job.get("pdf")
    report    = job.get("report", {})
    if not pdf_bytes:
        return jsonify({"error": "PDF not available"}), 404

    resend_api_key = os.environ.get("RESEND_API_KEY", "")
    if not resend_api_key:
        return jsonify({"error": "Email not configured on this server."}), 503

    target    = report.get("meta", {}).get("target", "your site")
    scan_date = report.get("meta", {}).get("scan_date", "")
    risk      = report.get("risk_label", "UNKNOWN")
    score     = report.get("risk_score", 0)
    host_safe = target.replace(".", "-")
    pdf_name  = f"security-report-{host_safe}-{datetime.now().strftime('%Y%m%d')}.pdf"

    risk_color = '#ef4444' if risk in ('CRITICAL', 'HIGH') else '#f59e0b' if risk == 'MEDIUM' else '#10b981'

    html_body = f"""
    <html><body style="font-family:sans-serif;background:#07080f;color:#f0f4ff;padding:32px;">
    <div style="max-width:560px;margin:0 auto;">
      <h1 style="color:#00E5FF;font-size:24px;margin-bottom:4px;">⚡ RapidVuln</h1>
      <p style="color:#94a3b8;margin-bottom:32px;">Security Report</p>
      <h2 style="font-size:18px;">Hi {recipient_name},</h2>
      <p>Your security report for <strong>{target}</strong> is attached.</p>
      <div style="background:#10131f;border:1px solid #1a2035;border-radius:12px;padding:20px;margin:24px 0;">
        <div style="font-size:48px;font-weight:900;color:{risk_color}">{score}/10</div>
        <div style="font-size:18px;font-weight:700;color:{risk_color};margin-bottom:12px;">{risk} RISK</div>
        <p style="color:#94a3b8;font-size:14px;margin:0;">Scanned on {scan_date}</p>
      </div>
      <p style="color:#94a3b8;font-size:13px;">
        The full PDF report is attached with detailed findings and step-by-step fix instructions.
      </p>
      <p style="color:#4a5568;font-size:11px;margin-top:32px;border-top:1px solid #1a2035;padding-top:16px;">
        This report is for informational purposes only. RapidVuln automated scans are not a substitute for a professional security assessment.
      </p>
    </div>
    </body></html>
    """

    # Encode PDF as base64 for Resend attachment
    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

    payload = {
        "from": "RapidVuln <reports@rapidvuln.com>",
        "to": [to_email],
        "subject": f"Your Security Report — {target} ({risk} RISK {score}/10)",
        "html": html_body,
        "attachments": [
            {
                "filename": pdf_name,
                "content": pdf_b64,
            }
        ],
    }

    try:
        resp = http_requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            app.logger.info(f"Report emailed to {to_email} for job {job_id}")
            return jsonify({"ok": True, "message": f"Report sent to {to_email}"})
        else:
            err = resp.json().get("message", resp.text)
            app.logger.error(f"Resend error: {err}")
            return jsonify({"error": f"Failed to send email: {err}"}), 500
    except Exception as e:
        app.logger.error(f"Email send failed: {e}")
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500


@app.route("/monitor", methods=["POST"])
def create_monitor_route():
    """Register a finished scan's target for recurring automatic re-scans.
    Called from the "Monitor this site" button/modal on report.html."""
    data = request.get_json(silent=True) or {}
    job_id         = (data.get("job_id") or "").strip()
    to_email       = (data.get("email") or "").strip()
    frequency_days = data.get("frequency_days", 7)

    try:
        frequency_days = int(frequency_days)
    except (TypeError, ValueError):
        frequency_days = 7
    if frequency_days not in (1, 7, 30):
        frequency_days = 7

    if not job_id:
        return jsonify({"error": "Missing job_id"}), 400
    if not to_email or "@" not in to_email:
        return jsonify({"error": "Valid email address required"}), 400

    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "Report not ready"}), 404

    report        = job.get("report") or {}
    host          = job.get("host") or report.get("meta", {}).get("host", "")
    target        = job.get("target") or report.get("meta", {}).get("target", host)
    business_name = job.get("business_name", "")
    scan_type     = job.get("scan_type", "standard")

    if not host:
        return jsonify({"error": "Could not determine scan target"}), 400

    monitor_id = db.create_monitor(host, target, business_name, scan_type, to_email, frequency_days)

    label = {1: "day", 7: "week", 30: "month"}.get(frequency_days, f"{frequency_days} days")
    return jsonify({
        "ok": True,
        "monitor_id": monitor_id,
        "message": f"Now monitoring {host} every {label} — alerts go to {to_email}",
    })


@app.route("/monitors")
def monitors_page():
    """Lists active/paused monitors. Pass ?email=... to scope to one customer's
    monitors (the modal links here with the email they just registered)."""
    email = (request.args.get("email") or "").strip() or None
    monitors = db.list_monitors(email=email)
    return render_template("monitors.html", monitors=monitors, email=email)


@app.route("/monitors/<int:monitor_id>/pause", methods=["POST"])
def pause_monitor_route(monitor_id: int):
    db.set_monitor_active(monitor_id, False)
    return jsonify({"ok": True})


@app.route("/monitors/<int:monitor_id>/resume", methods=["POST"])
def resume_monitor_route(monitor_id: int):
    db.set_monitor_active(monitor_id, True)
    return jsonify({"ok": True})


@app.route("/monitors/<int:monitor_id>/delete", methods=["POST"])
def delete_monitor_route(monitor_id: int):
    db.delete_monitor(monitor_id)
    return jsonify({"ok": True})


# ── Run ───────────────────────────────────────────────────────────────────────

# Start the recurring-scan scheduler once, at process startup. Module-level (not
# inside `if __name__ == "__main__"`) so it starts the same way db.init_db() does
# above, regardless of how the process is launched.
threading.Thread(target=_monitor_scheduler_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    print(f"\n  🔒 AI Security Report Tool")
    print(f"  Running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
