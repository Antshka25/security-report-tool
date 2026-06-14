"""
app.py — Flask web server for the AI Security Report Tool.
Run: python app.py
"""
import os
import uuid
import threading
import json
import smtplib
import ssl as ssl_lib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   send_file, abort)
import io

from scanner import resolve_target, validate_target, run_scan, build_scan_summary
from ai_reporter import generate_report, generate_report_fallback
from pdf_generator import build_pdf
from web_checks import run_web_checks

try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")

# Allow Netlify frontend to call this backend
if HAS_CORS:
    CORS(app, resources={r"/*": {"origins": "*"}})

# ── Job store (in-memory — use Redis for production) ──────────────────────────
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _set_job(job_id: str, update: dict):
    with _jobs_lock:
        if job_id not in _jobs:
            _jobs[job_id] = {}
        _jobs[job_id].update(update)


def _get_job(job_id: str) -> dict:
    with _jobs_lock:
        return dict(_jobs.get(job_id, {}))


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
    return render_template("report.html", report=report, job_id=job_id)


@app.route("/download/<job_id>")
def download_pdf(job_id: str):
    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        abort(404)

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
    """Send the PDF report to an email address."""
    job = _get_job(job_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "Report not ready"}), 404

    data          = request.get_json(silent=True) or {}
    to_email      = (data.get("email") or "").strip()
    recipient_name= (data.get("name") or "").strip() or "there"
    business_name = (data.get("business_name") or "").strip()

    if not to_email or "@" not in to_email:
        return jsonify({"error": "Valid email address required"}), 400

    pdf_bytes = job.get("pdf")
    report    = job.get("report", {})
    if not pdf_bytes:
        return jsonify({"error": "PDF not available"}), 404

    # SMTP config from environment
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    from_addr = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_pass:
        return jsonify({"error": "Email not configured on this server. Set SMTP_USER and SMTP_PASS environment variables."}), 503

    target    = report.get("meta", {}).get("target", "your site")
    scan_date = report.get("meta", {}).get("scan_date", "")
    risk      = report.get("risk_label", "")
    score     = report.get("risk_score", 0)
    host_safe = target.replace(".", "-")
    pdf_name  = f"security-report-{host_safe}-{datetime.now().strftime('%Y%m%d')}.pdf"

    # Build email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your Security Report — {target} ({risk} RISK {score}/10)"
    msg["From"]    = from_addr
    msg["To"]      = to_email

    html_body = f"""
    <html><body style="font-family:sans-serif;background:#07080f;color:#f0f4ff;padding:32px;">
    <div style="max-width:560px;margin:0 auto;">
      <h1 style="color:#7c3aed;font-size:24px;margin-bottom:4px;">⬡ SecureCheck</h1>
      <p style="color:#94a3b8;margin-bottom:32px;">AI Security Report</p>
      <h2 style="font-size:18px;">Hi {recipient_name},</h2>
      <p>Your security report for <strong>{target}</strong> is attached.</p>
      <div style="background:#10131f;border:1px solid #1a2035;border-radius:12px;padding:20px;margin:24px 0;">
        <div style="font-size:48px;font-weight:900;color:{'#ef4444' if risk in ('CRITICAL','HIGH') else '#f59e0b' if risk=='MEDIUM' else '#10b981'}">
          {score}/10
        </div>
        <div style="font-size:18px;font-weight:700;color:{'#ef4444' if risk in ('CRITICAL','HIGH') else '#f59e0b' if risk=='MEDIUM' else '#10b981'};margin-bottom:12px;">
          {risk} RISK
        </div>
        <p style="color:#94a3b8;font-size:14px;margin:0;">Scanned on {scan_date}</p>
      </div>
      <p style="color:#94a3b8;font-size:13px;">
        The full PDF report is attached with detailed findings and step-by-step fix instructions for each issue.
      </p>
      <p style="color:#4a5568;font-size:11px;margin-top:32px;border-top:1px solid #1a2035;padding-top:16px;">
        This report is for informational purposes only. SecureCheck automated scans are not a substitute for a professional security assessment.
      </p>
    </div>
    </body></html>
    """

    msg.attach(MIMEText(html_body, "html"))

    # Attach PDF
    pdf_part = MIMEBase("application", "pdf")
    pdf_part.set_payload(pdf_bytes)
    encoders.encode_base64(pdf_part)
    pdf_part.add_header("Content-Disposition", f'attachment; filename="{pdf_name}"')
    msg.attach(pdf_part)

    try:
        ctx = ssl_lib.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, to_email, msg.as_string())
        app.logger.info(f"Report emailed to {to_email} for job {job_id}")
        return jsonify({"ok": True, "message": f"Report sent to {to_email}"})
    except smtplib.SMTPAuthenticationError:
        return jsonify({"error": "Email authentication failed. Check SMTP_USER and SMTP_PASS."}), 500
    except Exception as e:
        app.logger.error(f"Email send failed: {e}")
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    print(f"\n  🔒 AI Security Report Tool")
    print(f"  Running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
