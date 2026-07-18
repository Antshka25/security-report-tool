"""
ai_reporter.py — GPT-4o powered security report generator.
Takes raw scan summary and produces a structured plain-English report
designed for small business owners with zero technical knowledge.
"""
import json
import os
from datetime import datetime
from typing import Optional
from openai import OpenAI

from cwe_reference import annotate_findings


# ── OpenAI client ─────────────────────────────────────────────────────────────

def _get_client() -> OpenAI:
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        raise RuntimeError("OPENAI_API_KEY not set in environment")
    return OpenAI(api_key=key)


# ── Prompt builder ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity expert writing a professional security report for a small business owner.
The business owner is NOT technical. They need plain English explanations, not jargon.
You must return ONLY valid JSON — no markdown fences, no explanation outside the JSON.

Your tone is:
- Professional but friendly
- Clear and direct, like a doctor explaining test results
- Never condescending
- Urgent about real risks, calm about minor ones

Every finding must explain:
1. What it is (1 sentence, no jargon)
2. What could go wrong (real-world consequences: data theft, ransomware, downtime)
3. How to fix it (specific, actionable, simple)"""


def _build_prompt(summary: dict, business_name: str = "") -> str:
    biz = f" for {business_name}" if business_name else ""
    def _label(p):
        port = str(p.get("port", ""))
        cat  = p.get("category", "")
        if port.isdigit():
            return f"Port {port}"
        if cat == "dns":
            return "DNS"
        return port  # SSL, HTTPS, HTTP, etc.

    ports_text = "\n".join(
        f"  - {_label(p)} ({p['service']}) — Risk: {p['risk']} — {p['reason']}"
        f"{' — Version: ' + p['version'] if p.get('version') else ''}"
        f"{' — CWE: ' + p['cwe'] if p.get('cwe') else ''}"
        f"{' — Real-World Example: ' + p['real_world_example'] if p.get('real_world_example') else ''}"
        for p in summary["ports"]
    ) or "  - No issues detected"

    return f"""Generate a security report{biz} based on this comprehensive security scan:

TARGET: {summary['host']}
OPEN NETWORK PORTS: {summary['total_ports']}
TOTAL FINDINGS (ports + SSL + headers + DNS): {summary.get('total_findings', summary['total_ports'])}
HIGH RISK: {summary['high_count']}
MEDIUM RISK: {summary['medium_count']}
LOW RISK / INFO: {summary['low_count']}
OVERALL RISK SCORE: {summary['risk_score']}/10 ({summary['risk_label']})

PORT DETAILS:
{ports_text}

Return ONLY this JSON structure (no markdown, no extra text):
{{
  "executive_summary": "2-3 sentence plain English summary of the overall security posture. What is the business's biggest risk right now?",
  "risk_score": {summary['risk_score']},
  "risk_label": "{summary['risk_label']}",
  "risk_explanation": "1-2 sentences explaining what the risk score means in business terms (potential impact: ransomware, data breach, downtime, fines)",
  "findings": [
    {{
      "title": "Short finding title (e.g. 'Remote Desktop Exposed to Internet')",
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "port": "port number",
      "service": "service name",
      "what_it_is": "Plain English: what is this port/service? Max 1 sentence.",
      "business_risk": "What could actually happen to the business? Real consequences: ransomware, data stolen, website down, fines. Max 2 sentences.",
      "how_to_fix": "Specific action to take. Simple steps. Max 3 sentences.",
      "urgency": "Fix immediately|Fix within 1 week|Fix within 1 month|Monitor",
      "cwe": "Copy the exact CWE reference (e.g. 'CWE-319') from the PORT DETAILS above for this finding if one is listed there. Use an empty string if none was listed. NEVER invent or guess a CWE ID.",
      "real_world_example": "Copy the exact Real-World Example text from the PORT DETAILS above for this finding, verbatim, if one is listed there. Use an empty string if none was listed. NEVER invent a new example."
    }}
  ],
  "top_recommendations": [
    "Most important action item (specific and actionable)",
    "Second most important action",
    "Third most important action"
  ],
  "positive_findings": "1-2 sentences about what they're doing right (or note if nothing positive was found)",
  "next_steps": "What should the business owner do first thing tomorrow morning? 2-3 sentences, very specific.",
  "disclaimer": "Standard security report disclaimer"
}}

Generate findings for ALL open ports listed above. Order findings by severity (HIGH first).
Make the executive_summary and business_risk sections genuinely useful for a non-technical business owner.
For the "cwe" field on each finding, copy it verbatim from PORT DETAILS if one is listed there — never invent, guess, or reuse a CWE ID from a different finding.
For the "real_world_example" field, copy it verbatim from PORT DETAILS if one is listed there — never invent a new example or reuse one from a different finding."""


# ── Main report generator ─────────────────────────────────────────────────────

def generate_report(summary: dict, business_name: str = "",
                    target_url: str = "") -> dict:
    """
    Generate a complete security report from scan summary.
    Returns the report dict (parsed from GPT-4o JSON output).
    """
    client = _get_client()
    prompt = _build_prompt(summary, business_name)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        temperature=0.3,
        max_tokens=4000,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()

    try:
        report = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"AI returned invalid JSON: {e}\n\nRaw: {raw[:500]}")

    # Attach metadata
    report["meta"] = {
        "target":        target_url or summary.get("host", ""),
        "host":          summary.get("host", ""),
        "ip":            summary.get("ip", ""),
        "business_name": business_name or "Your Business",
        "scan_date":     datetime.now().strftime("%B %d, %Y"),
        "scan_time":     datetime.now().strftime("%I:%M %p"),
        "total_ports":   summary.get("total_ports", 0),
        "model":         "GPT-4o",
        "report_version":"1.0",
    }

    # Ensure findings list exists
    if "findings" not in report:
        report["findings"] = []

    # Normalise severity capitalization
    for f in report["findings"]:
        f["severity"] = f.get("severity", "INFO").upper()

    # Defense-in-depth: even though the prompt instructs the model to copy CWE
    # IDs verbatim and never invent one, strip any "cwe" value that doesn't
    # match a real CWE we actually supplied in PORT DETAILS — a security report
    # must never present a fabricated reference ID as fact.
    real_cwes = {p["cwe"] for p in summary.get("ports", []) if p.get("cwe")}
    for f in report["findings"]:
        if f.get("cwe") and f["cwe"] not in real_cwes:
            f["cwe"] = ""

    # Same defense-in-depth for real_world_example: strip anything the model
    # didn't copy verbatim from a finding we actually supplied, so a report
    # never presents an AI-invented scenario as one of our vetted examples.
    real_examples = {p["real_world_example"] for p in summary.get("ports", []) if p.get("real_world_example")}
    for f in report["findings"]:
        if f.get("real_world_example") and f["real_world_example"] not in real_examples:
            f["real_world_example"] = ""

    # Tag content_discovery findings so report.html can split them into their
    # own tab. The JSON schema the model returns has no "category" field (it
    # was never asked for one), so this can't just trust something the model
    # wrote — instead it keys off "port"/"service", which the model DOES
    # reliably copy from PORT DETAILS for every other purpose already:
    # content_discovery_checks.py's _finding() always sets port="PATH" and
    # service="Content Discovery" (see that module), and _build_prompt's
    # _label() passes "PATH" through to the model verbatim (it isn't a digit
    # and isn't the "dns" category, so it falls through unchanged). Every
    # other category (web/dns/vuln/cve/supply_chain/port) doesn't need this
    # tag — report.html only ever checks for "content_discovery" specifically.
    for f in report["findings"]:
        if str(f.get("port", "")).upper() == "PATH" or f.get("service") == "Content Discovery":
            f["category"] = "content_discovery"

    # Attach human-readable name/explanation for any recognized CWE id.
    annotate_findings(report["findings"])

    return report


# ── Per-port specific fix instructions ───────────────────────────────────────

_PORT_FIX = {
    "21":    ("FTP transfers files without encryption. Usernames and passwords are visible to anyone on the network.",
              "Disable FTP completely and switch to SFTP (port 22) or FTPS. In your firewall/router, block inbound port 21. "
              "On Linux: 'sudo systemctl stop vsftpd && sudo systemctl disable vsftpd'. "
              "If you must use file transfer, use SFTP via an SSH client like FileZilla with SFTP mode."),
    "22":    ("SSH allows encrypted remote access to your server.",
              "SSH is generally safe if configured correctly. Harden it: disable root login ('PermitRootLogin no' in /etc/ssh/sshd_config), "
              "use SSH key authentication instead of passwords ('PasswordAuthentication no'), "
              "and restrict access to known IP addresses in your firewall."),
    "23":    ("Telnet sends all data including passwords in plain text — completely unencrypted.",
              "Disable Telnet immediately. On Linux: 'sudo systemctl stop telnet && sudo apt remove telnetd'. "
              "Block port 23 in your firewall. Replace with SSH (port 22) for all remote access."),
    "25":    ("SMTP handles outgoing email. Open to the internet it can be exploited for spam relay.",
              "Block port 25 inbound from the internet unless this is a mail server. "
              "In your firewall/router, restrict port 25 to only known mail servers. "
              "If you don't run a mail server, disable the service: 'sudo systemctl stop postfix'."),
    "80":    ("Port 80 serves unencrypted HTTP web traffic.",
              "Redirect all HTTP traffic to HTTPS. In Nginx: add 'return 301 https://$host$request_uri;' in your port 80 server block. "
              "In Apache: add redirect in .htaccess. Cloudflare: enable 'Always Use HTTPS'."),
    "135":   ("Windows RPC (Remote Procedure Call) is used for Windows services communication — historically targeted by worms.",
              "Block port 135 at your firewall/router for all external access. "
              "This port should NEVER be accessible from the internet. "
              "In Windows Firewall: Control Panel > Windows Firewall > Advanced Settings > Inbound Rules > block port 135. "
              "In your router: block TCP/UDP port 135 in the firewall settings."),
    "139":   ("NetBIOS is Windows file sharing — used by ransomware like WannaCry for lateral movement.",
              "Block port 139 at your router/firewall immediately — it should never be internet-facing. "
              "Router admin panel > Firewall > block inbound TCP port 139. "
              "If you don't need Windows file sharing, disable it: Control Panel > Network > right-click adapter > Properties > uncheck 'File and Printer Sharing'."),
    "443":   ("HTTPS serves encrypted web traffic — this is expected for websites.",
              "Port 443 being open is normal for a website. Ensure your SSL certificate is valid and up to date, "
              "and that you're using TLS 1.2 or higher. Test your SSL at https://www.ssllabs.com/ssltest/"),
    "445":   ("SMB (Server Message Block) is Windows file sharing — the primary target for WannaCry, NotPetya, and most ransomware.",
              "Block port 445 at your router/firewall IMMEDIATELY — this is the #1 ransomware entry point. "
              "Router: firewall settings > block inbound TCP port 445. "
              "Windows: netsh advfirewall firewall add rule name='Block SMB' dir=in action=block protocol=TCP localport=445. "
              "If you need file sharing inside your office, it should only work on your local network, never from the internet."),
    "1433":  ("Microsoft SQL Server database port — direct internet exposure risks your entire database.",
              "Block port 1433 at your firewall immediately. Databases should NEVER be publicly accessible. "
              "Access SQL Server through your application only (never directly from the internet). "
              "Windows Firewall: block inbound TCP 1433. In SQL Server: disable the TCP/IP protocol if remote access isn't needed."),
    "3306":  ("MySQL database — exposed to the internet means anyone can attempt to log into your database.",
              "Block port 3306 at your firewall immediately. In MySQL: bind to localhost only by adding 'bind-address = 127.0.0.1' to /etc/mysql/mysql.conf.d/mysqld.cnf, then restart: 'sudo systemctl restart mysql'. "
              "Access your database only through your application or via SSH tunnel."),
    "3389":  ("Remote Desktop Protocol (RDP) — the #1 way ransomware gets in. Attackers constantly scan for open RDP.",
              "Either disable RDP or put it behind a VPN immediately. "
              "To disable: Control Panel > System > Remote Settings > uncheck 'Allow Remote Desktop'. "
              "Better option: keep RDP but only allow it through a VPN (install OpenVPN or WireGuard), then block port 3389 in your firewall for all non-VPN traffic. "
              "At minimum, change RDP to a non-standard port and enable Network Level Authentication."),
    "5432":  ("PostgreSQL database exposed to the internet.",
              "Block port 5432 at your firewall. In PostgreSQL: edit postgresql.conf and set 'listen_addresses = localhost', "
              "restart: 'sudo systemctl restart postgresql'. Access only via your application or SSH tunnel."),
    "5900":  ("VNC remote desktop — often has weak or no encryption and authentication.",
              "Block port 5900 at your firewall. Use SSH tunnel for VNC access instead: "
              "'ssh -L 5900:localhost:5900 user@yourserver' then connect VNC to localhost:5900. "
              "Never expose VNC directly to the internet."),
    "6379":  ("Redis database — frequently configured with no authentication by default.",
              "Block port 6379 at your firewall immediately. In Redis: edit /etc/redis/redis.conf, "
              "set 'bind 127.0.0.1' and add 'requirepass YourStrongPassword'. "
              "Restart: 'sudo systemctl restart redis'. Redis with no auth and public access is a critical breach risk."),
    "8080":  ("Alternative HTTP port — often used for admin panels, development servers, or control panels.",
              "Identify what service runs on 8080 and restrict access. Block port 8080 at your firewall "
              "unless this is intentionally public. If it's an admin panel, put it behind a VPN or IP whitelist."),
    "9200":  ("Elasticsearch — many major data breaches have come from public Elasticsearch instances with no authentication.",
              "Block port 9200 immediately. In elasticsearch.yml: set 'network.host: 127.0.0.1'. "
              "Restart Elasticsearch. This database should NEVER be publicly accessible."),
    "27017": ("MongoDB — like Elasticsearch, many breaches come from default no-auth MongoDB instances.",
              "Block port 27017 at your firewall. In mongod.conf: set 'bindIp: 127.0.0.1' under net:. "
              "Enable authentication: add '--auth' flag or set 'security.authorization: enabled' in mongod.conf. "
              "Restart MongoDB. Never expose databases to the internet."),
}

_DEFAULT_FIX = (
    "Block this port in your firewall/router for all external internet access. "
    "In your router admin panel, go to Firewall settings and add a rule to block inbound access to this port. "
    "If you use a cloud provider (AWS, Azure, GCP), update your Security Group or Network Security Group to remove this rule."
)


def generate_report_fallback(summary: dict, business_name: str = "",
                              target_url: str = "") -> dict:
    """
    Rule-based fallback report generator — used when OpenAI is unavailable.
    Includes specific, actionable how-to-fix steps per finding type.
    """
    ports = summary.get("ports", [])
    host  = summary.get("host", "")

    findings = []
    for p in ports:
        port_str = str(p.get("port", ""))
        svc      = p.get("service", port_str)
        risk     = p.get("risk", "INFO")
        cat      = p.get("category", "port")

        # Use how_to_fix if already set (web checks set their own)
        existing_fix = p.get("how_to_fix", "")
        what_it_is   = p.get("what_it_is", "")
        biz_risk     = p.get("business_risk", p.get("reason", ""))

        if cat in ("web", "dns", "vuln", "cve", "supply_chain", "content_discovery", "fingerprint", "breach"):
            # web_checks / vuln_checks / cve_checks / supply_chain_checks /
            # content_discovery_checks / breach_checks findings already have
            # rich data — these are every non-raw-port category the scan
            # engine produces (checked against every _finding() category=
            # default in the codebase, not just the ones that happened to be
            # covered here before). "fingerprint" is the tech-stack finding
            # and "breach" is the email-breach-exposure finding — both would
            # otherwise fall into the raw-port-lookup else-branch below and
            # lose their real what_it_is text to a generic "Port X is
            # running Y" placeholder.
            title    = p.get("title", f"{svc} Issue")
            fix      = existing_fix or _DEFAULT_FIX
            what     = what_it_is or p.get("reason", "")
            biz      = biz_risk
            urgency  = p.get("urgency", "Fix within 1 week")
        else:
            # nmap port findings — use lookup table
            port_info = _PORT_FIX.get(port_str, (None, None))
            what  = port_info[0] if port_info[0] else f"Port {port_str} is running {svc}."
            fix   = existing_fix or (port_info[1] if port_info[1] else _DEFAULT_FIX)
            biz   = biz_risk or p.get("reason", "")
            title = p.get("title", f"{svc} Exposed (Port {port_str})")
            urgency = "Fix immediately" if risk == "HIGH" else "Fix within 1 week" if risk == "MEDIUM" else "Monitor"

        findings.append({
            "title":        title,
            "severity":     risk,
            "port":         port_str,
            "service":      svc,
            "what_it_is":   what,
            "business_risk": biz,
            "how_to_fix":   fix,
            "urgency":      urgency,
            "cwe":          p.get("cwe", ""),
            "real_world_example": p.get("real_world_example", ""),
            # Preserved so report.html can split content_discovery findings into
            # their own tab (see the tab-row logic there) — this was missing
            # entirely before, which would have made that split silently find
            # nothing, since every finding here previously carried no category.
            "category":     cat,
        })

    # Attach human-readable name/explanation for any recognized CWE id.
    annotate_findings(findings)

    score = summary.get("risk_score", 0)
    label = summary.get("risk_label", "LOW")

    # Build smart top recommendations from actual findings
    high_findings  = [f for f in findings if f["severity"] == "HIGH"]
    med_findings   = [f for f in findings if f["severity"] == "MEDIUM"]
    recs = []
    for f in (high_findings + med_findings)[:3]:
        recs.append(f"{f['title']}: {f['how_to_fix'].split('.')[0]}.")
    if not recs:
        recs = ["Keep software and systems updated", "Review firewall rules regularly", "Enable automatic security patches"]

    # Next steps based on findings
    if high_findings:
        next_steps = (
            f"Start with the {len(high_findings)} HIGH risk finding(s) today — these are your most urgent risks. "
            f"First, address '{high_findings[0]['title']}': {high_findings[0]['how_to_fix'].split('.')[0]}. "
            f"Then work through the remaining findings in order of severity."
        )
    elif med_findings:
        next_steps = (
            f"Address the {len(med_findings)} MEDIUM risk finding(s) this week. "
            f"Start with '{med_findings[0]['title']}': {med_findings[0]['how_to_fix'].split('.')[0]}."
        )
    else:
        next_steps = "Your security posture looks good. Continue monitoring monthly and keep all software updated."

    # Executive summary
    total_findings = summary.get("total_findings", summary.get("total_ports", 0))
    if summary.get("high_count", 0) > 0:
        exec_summary = (
            f"The security scan of {host} found {total_findings} issues including "
            f"{summary['high_count']} high-risk and {summary.get('medium_count', 0)} medium-risk findings. "
            f"The most critical issue is '{high_findings[0]['title']}' which requires immediate attention. "
            f"Full remediation steps are provided for each finding below."
        )
    elif summary.get("medium_count", 0) > 0:
        exec_summary = (
            f"The security scan of {host} found {total_findings} medium and low severity issues. "
            f"No critical vulnerabilities were detected, but {summary['medium_count']} issues should be addressed this week "
            f"to harden your security posture. Detailed fix instructions are included for each finding."
        )
    else:
        exec_summary = (
            f"The security scan of {host} found no critical or high-risk issues. "
            f"Your internet-facing exposure appears well-controlled. "
            f"Review the low-severity findings below for additional hardening opportunities."
        )

    return {
        "executive_summary": exec_summary,
        "risk_score":       score,
        "risk_label":       label,
        "risk_explanation": (
            f"A score of {score}/10 ({label}) means your internet-facing exposure is well-controlled — no critical services are publicly accessible."
            if score == 0 else
            f"A risk score of {score}/10 ({label}) indicates your business has security issues that need attention. "
            f"The higher the score, the greater the chance of a breach, ransomware, or data theft."
        ),
        "findings":         findings,
        "top_recommendations": recs,
        "positive_findings": (
            "No high-risk open ports were detected from the internet — your firewall appears to be blocking dangerous services."
            if not high_findings else
            "Your server is reachable, which means the web checks and SSL analysis were able to run successfully."
        ),
        "next_steps":       next_steps,
        "disclaimer":       "This report is for informational purposes only and represents a point-in-time automated scan. It is not a substitute for a professional penetration test.",
        "meta": {
            "target":        target_url or host,
            "host":          host,
            "ip":            summary.get("ip", ""),
            "business_name": business_name or "Your Business",
            "scan_date":     datetime.now().strftime("%B %d, %Y"),
            "scan_time":     datetime.now().strftime("%I:%M %p"),
            "total_ports":   summary.get("total_ports", 0),
            "model":         "Rule-based (AI unavailable)",
            "report_version":"1.0",
        },
    }