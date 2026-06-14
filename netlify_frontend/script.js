/**
 * SecureScan — connects Netlify frontend to Flask backend
 * Set BACKEND_URL to your deployed Railway/Render URL.
 * For local testing: "http://localhost:5000"
 */
const BACKEND_URL = "https://web-production-dc0f8.up.railway.app";

// ── State ──────────────────────────────────────────────────────────────────
let currentJobId  = null;
let pollInterval  = null;
let currentTarget = "";

const RISK_COLORS = {
  CRITICAL: "#ef4444", HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#10b981"
};

// ── Boot ───────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  wireUpScanForm();
  wireUpEmailForm();
});

// ── Find elements loosely (works across different HTML structures) ──────────
function $id(id)       { return document.getElementById(id); }
function $sel(sel)     { return document.querySelector(sel); }
function $all(sel)     { return document.querySelectorAll(sel); }

function getScanInput() {
  return $id("scan-input") || $id("url-input") || $id("target") ||
         $sel('input[type="text"][placeholder*="website"]') ||
         $sel('input[type="text"][placeholder*="URL"]') ||
         $sel('input[placeholder*="business"]') ||
         $sel('.scan-input input') || $sel('input[type="text"]');
}

function getScanBtn() {
  return $id("scan-btn") || $id("btn-scan") ||
         $sel('[id*="scan"]') ||
         $sel('button[onclick*="scan"]') ||
         Array.from($all("button")).find(b => /scan|check|run/i.test(b.textContent));
}

function getResultsSection() {
  return $id("results") || $id("scan-results") || $id("result-section") ||
         $sel(".scan-complete") || $sel('[class*="result"]') ||
         $sel('[class*="complete"]');
}

function getEmailBtn() {
  return $id("email-btn") || $id("btn-email") ||
         Array.from($all("button")).find(b => /email/i.test(b.textContent));
}

// ── Wire scan form ─────────────────────────────────────────────────────────
function wireUpScanForm() {
  const input  = getScanInput();
  const btn    = getScanBtn();

  if (!btn) return;

  btn.addEventListener("click", startScan);
  if (input) {
    input.addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
  }
}

async function startScan() {
  const input = getScanInput();
  const target = (input ? input.value : "").trim();

  if (!target) {
    showInlineError("Please enter a website URL or IP address");
    return;
  }

  currentTarget = target;
  showScanningUI(target);

  try {
    const res  = await fetch(`${BACKEND_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, scan_type: "standard" })
    });
    const data = await res.json();

    if (data.error) { showScanError(data.error); return; }

    currentJobId = data.job_id;
    startPolling();

  } catch (err) {
    showScanError("Could not reach scan server. Make sure the backend is running.");
  }
}

// ── Progress polling ───────────────────────────────────────────────────────
function startPolling() {
  pollInterval = setInterval(async () => {
    try {
      const res  = await fetch(`${BACKEND_URL}/status/${currentJobId}`);
      const data = await res.json();

      updateProgress(data.step || "", data.progress || 0);

      if (data.status === "done") {
        clearInterval(pollInterval);
        showResults(data.summary, currentJobId, currentTarget);
      } else if (data.status === "error") {
        clearInterval(pollInterval);
        showScanError(data.error || "Scan failed — please try again");
      }
    } catch (_) { /* keep polling on network hiccup */ }
  }, 1500);
}

// ── UI: scanning state ─────────────────────────────────────────────────────
function showScanningUI(target) {
  // Look for a progress/scanning section and show it
  const scanningSection = $id("scanning-section") || $id("progress-section") ||
                          $sel('[class*="scanning"]') || $sel('[class*="progress"]');

  // Terminal log — try to find or create it
  let terminal = $id("terminal") || $id("scan-log") || $sel('[class*="terminal"]');

  const resultsSection = getResultsSection();
  if (resultsSection) resultsSection.style.display = "none";

  if (scanningSection) {
    scanningSection.style.display = "block";
  }

  if (terminal) {
    terminal.innerHTML = "";
    addTerminalLine(terminal, `> Starting scan of ${target}...`);
    addTerminalLine(terminal, `> Running port scan...`);
  }

  const btn = getScanBtn();
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
}

function updateProgress(step, pct) {
  const bar = $id("progress-bar") || $sel('[class*="progress-bar"]');
  if (bar) bar.style.width = pct + "%";

  const stepEl = $id("progress-step") || $sel('[class*="step"]');
  if (stepEl) stepEl.textContent = step;

  // Push step to terminal
  const terminal = $id("terminal") || $id("scan-log") || $sel('[class*="terminal"]');
  if (terminal && step) addTerminalLine(terminal, `> ${step}`);
}

function addTerminalLine(terminal, text, color) {
  const line = document.createElement("div");
  line.textContent = text;
  if (color) line.style.color = color;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// ── UI: results ────────────────────────────────────────────────────────────
function showResults(summary, jobId, target) {
  const btn = getScanBtn();
  if (btn) { btn.disabled = false; btn.textContent = "Scan Again →"; }

  const score = summary.risk_score || 0;
  const label = summary.risk_label || "LOW";
  const color = RISK_COLORS[label] || "#10b981";

  const terminal = $id("terminal") || $sel('[class*="terminal"]');
  if (terminal) {
    addTerminalLine(terminal, `✓ Scan complete — ${summary.total_ports} open ports found`, "#10b981");
    if (summary.high_findings > 0) {
      addTerminalLine(terminal, `✗ ${summary.high_findings} HIGH risk issue(s) found`, "#ef4444");
    }
  }

  // Try to update existing result elements
  const scoreEl = $id("result-score") || $sel('[class*="score"]');
  if (scoreEl) { scoreEl.textContent = score + "/10"; scoreEl.style.color = color; }

  const labelEl = $id("result-label") || $sel('[class*="risk-label"]');
  if (labelEl) { labelEl.textContent = label + " RISK"; labelEl.style.color = color; }

  const portsEl = $id("stat-ports") || $sel('[class*="ports"]');
  if (portsEl) portsEl.textContent = summary.total_ports;

  const highEl = $id("stat-high") || $sel('[class*="high"]');
  if (highEl) highEl.textContent = summary.high_findings;

  // Update CTA links
  const viewBtn = $id("btn-view") || Array.from($all("a,button")).find(b => /view|report/i.test(b.textContent));
  if (viewBtn) viewBtn.href = `${BACKEND_URL}/report/${jobId}`;

  const dlBtn = $id("btn-download") || Array.from($all("a,button")).find(b => /download|pdf/i.test(b.textContent));
  if (dlBtn) dlBtn.href = `${BACKEND_URL}/download/${jobId}`;

  // Show email button with job context
  const emailBtn = getEmailBtn();
  if (emailBtn) {
    emailBtn.onclick = () => openEmailModal(jobId);
    emailBtn.style.display = "";
  }

  // Inject a results block if the site has a placeholder
  injectResultsBlock(summary, jobId, target, color, label, score);

  const resultsSection = getResultsSection();
  if (resultsSection) resultsSection.style.display = "block";

  const scanningSection = $id("scanning-section") || $id("progress-section") ||
                          $sel('[class*="scanning"]');
  if (scanningSection) scanningSection.style.display = "none";
}

function injectResultsBlock(summary, jobId, target, color, label, score) {
  // Find the placeholder results container in the existing HTML
  const container = $id("results-inject") || $sel('[data-results]') ||
                    $sel('.scan-result-container') || $sel('#result-section') ||
                    $sel('.result-card');

  if (!container) return;

  container.innerHTML = `
    <div style="text-align:center; margin-bottom:20px;">
      <div style="font-size:56px; font-weight:900; color:${color}; line-height:1;">${score}/10</div>
      <div style="font-size:18px; font-weight:700; color:${color}; margin:4px 0 16px;">${label} RISK</div>
      <div style="font-size:13px; color:#94a3b8;">${target} · ${summary.total_ports} open port(s) · ${summary.high_findings || 0} high risk</div>
    </div>
    <div style="display:flex; gap:10px; justify-content:center; flex-wrap:wrap;">
      <a href="${BACKEND_URL}/report/${jobId}" target="_blank"
         style="background:#7c3aed; color:white; padding:12px 24px; border-radius:8px; font-weight:700; text-decoration:none; font-size:14px;">
        📋 View Full Report
      </a>
      <a href="${BACKEND_URL}/download/${jobId}"
         style="background:transparent; color:#f0f4ff; border:1px solid #1a2035; padding:12px 24px; border-radius:8px; font-weight:700; text-decoration:none; font-size:14px;">
        ⬇️ Download PDF
      </a>
      <button onclick="openEmailModal('${jobId}')"
         style="background:transparent; color:#f0f4ff; border:1px solid #1a2035; padding:12px 24px; border-radius:8px; font-weight:700; font-size:14px; cursor:pointer;">
        📧 Email Report
      </button>
    </div>
  `;
}

// ── Email modal ────────────────────────────────────────────────────────────
function openEmailModal(jobId) {
  currentJobId = jobId || currentJobId;

  let modal = $id("securescan-email-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "securescan-email-modal";
    modal.innerHTML = `
      <div style="position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;">
        <div style="background:#10131f;border:1px solid #1a2035;border-radius:16px;padding:32px;max-width:420px;width:100%;">
          <h2 style="font-size:18px;margin-bottom:6px;">📧 Email This Report</h2>
          <p style="color:#94a3b8;font-size:14px;margin-bottom:24px;">We'll send the full PDF to your inbox.</p>
          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:11px;font-weight:700;color:#94a3b8;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:5px;">Your Name</label>
            <input id="em-name" type="text" placeholder="Anton"
              style="width:100%;background:#090b16;border:1px solid #1a2035;border-radius:8px;color:#f0f4ff;font-size:14px;padding:10px 12px;outline:none;box-sizing:border-box;">
          </div>
          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:11px;font-weight:700;color:#94a3b8;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:5px;">Email Address</label>
            <input id="em-email" type="email" placeholder="you@company.com"
              style="width:100%;background:#090b16;border:1px solid #1a2035;border-radius:8px;color:#f0f4ff;font-size:14px;padding:10px 12px;outline:none;box-sizing:border-box;">
          </div>
          <div style="margin-bottom:20px;">
            <label style="display:block;font-size:11px;font-weight:700;color:#94a3b8;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:5px;">Business Name</label>
            <input id="em-biz" type="text" placeholder="Acme Co."
              style="width:100%;background:#090b16;border:1px solid #1a2035;border-radius:8px;color:#f0f4ff;font-size:14px;padding:10px 12px;outline:none;box-sizing:border-box;">
          </div>
          <div id="em-status" style="display:none;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:12px;"></div>
          <div style="display:flex;gap:10px;">
            <button id="em-send"
              style="flex:1;background:#7c3aed;color:white;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:700;cursor:pointer;">
              Send Report
            </button>
            <button onclick="document.getElementById('securescan-email-modal').remove()"
              style="background:transparent;color:#94a3b8;border:1px solid #1a2035;border-radius:8px;padding:12px 16px;font-size:14px;cursor:pointer;">
              Cancel
            </button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    $id("em-send").addEventListener("click", sendEmail);
  }
  modal.style.display = "";
}

async function sendEmail() {
  const email = ($id("em-email") || {}).value?.trim();
  const name  = ($id("em-name")  || {}).value?.trim() || "";
  const biz   = ($id("em-biz")   || {}).value?.trim() || "";
  const status = $id("em-status");
  const btn    = $id("em-send");

  if (!email || !email.includes("@")) {
    showEmailStatus("Please enter a valid email address", "error");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Sending…";
  if (status) status.style.display = "none";

  try {
    const res  = await fetch(`${BACKEND_URL}/email/${currentJobId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, name, business_name: biz })
    });
    const data = await res.json();
    if (data.ok) {
      showEmailStatus(`✅ Report sent to ${email}`, "ok");
      btn.textContent = "✓ Sent!";
    } else {
      showEmailStatus("⚠️ " + (data.error || "Failed to send."), "error");
      btn.disabled = false;
      btn.textContent = "Try Again";
    }
  } catch (_) {
    showEmailStatus("⚠️ Network error — please try again.", "error");
    btn.disabled = false;
    btn.textContent = "Try Again";
  }
}

function showEmailStatus(msg, type) {
  const el = $id("em-status");
  if (!el) return;
  el.textContent = msg;
  el.style.display = "block";
  el.style.background = type === "ok" ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)";
  el.style.color       = type === "ok" ? "#34d399" : "#f87171";
  el.style.border      = type === "ok" ? "1px solid rgba(16,185,129,0.3)" : "1px solid rgba(239,68,68,0.3)";
}

// ── Error helpers ──────────────────────────────────────────────────────────
function showInlineError(msg) {
  const err = $id("scan-error") || $sel('[class*="error"]');
  if (err) { err.textContent = msg; err.style.display = "block"; return; }
  alert(msg);
}

function showScanError(msg) {
  const btn = getScanBtn();
  if (btn) { btn.disabled = false; btn.textContent = "Scan Again →"; }
  showInlineError("Scan failed: " + msg);
}
