"""
vuln_checks.py — Active checks for SQL injection, reflected XSS, and OS
command injection. Discovers forms/URL parameters on the target's homepage
and sends small, non-destructive probe payloads, then looks for tell-tale
signs (DB error text, unescaped reflection, abnormal response delay).
Every finding includes a specific how_to_fix instruction.
"""
import time
import re
import uuid
from urllib.parse import urlsplit, urlunsplit, urljoin, urlencode, parse_qsl

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

MAX_TARGETS     = 4   # cap how many forms/params we probe per scan
REQUEST_TIMEOUT = 6
CMDI_DELAY      = 4   # seconds the sleep payload asks the shell to pause

_XSS_MARKER  = "rvxss1337"
_XSS_PAYLOAD = f"<{_XSS_MARKER}>"

_SQLI_PAYLOAD = "'\""

_SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated", "sqlstate[",
    "pg_query():", "postgresql query failed", "sqlite3.operationalerror",
    "ora-00933", "ora-01756", "microsoft sql server", "odbc sql server driver",
    "syntax error at or near", "mysql_fetch_array()", "valid mysql result",
    "npgsql.", "system.data.sqlclient",
]

_CMDI_PAYLOADS = [f"; sleep {CMDI_DELAY}", f"`sleep {CMDI_DELAY}`"]

_FORM_RE  = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b([^>]*)>", re.I)
_ATTR_RE  = re.compile(r"""(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*'([^']*)'""", re.I)
_LINK_RE  = re.compile(r'<a\b[^>]*href\s*=\s*["\']([^"\']+\?[^"\']+)["\']', re.I)

_SKIP_INPUT_TYPES = {"submit", "button", "hidden", "checkbox", "radio", "file", "image", "reset"}

_REDIRECT_FIELD_HINTS = ("url", "redirect", "next", "return", "dest", "continue", "target", "out", "to")

MAX_SCRIPTS = 6   # cap how many same-origin <script src> files we pull and scan for leaked secrets

_SENSITIVE_FILES = [
    ("/.env", "HIGH", "Exposed .env File",
     "the application's environment file is publicly accessible, which typically contains database passwords, API keys, and other secrets",
     "Anyone can download this file and get direct access to your database, payment processor, email service, or "
     "other connected accounts using the credentials inside it.",
     "Move the .env file outside the publicly served folder, or add a server rule to block it. "
     "Nginx: 'location ~ /\\.env { deny all; }' inside your server block. Apache: add a .htaccess rule "
     "'<Files \".env\"> Require all denied </Files>'. Then rotate every credential that was in the file, since it may already be compromised."),
    ("/.git/config", "HIGH", "Exposed .git Directory",
     "the site's .git folder is publicly accessible, which can let someone reconstruct your entire source code and commit history",
     "Anyone can use a free tool to rebuild your full source code and commit history from this folder, which "
     "often reveals secrets, internal logic, or vulnerabilities that were since 'fixed' but never rotated.",
     "Block access to the .git folder. Nginx: 'location ~ /\\.git { deny all; }'. Apache: '<DirectoryMatch \"\\.git\"> Require all denied </DirectoryMatch>'. "
     "Better yet, don't deploy the .git folder to your live server at all."),
    ("/wp-config.php.bak", "HIGH", "WordPress Config Backup Exposed",
     "a backup copy of wp-config.php is publicly downloadable, which contains your WordPress database credentials in plain text",
     "Anyone can download this file and get direct read/write access to your entire WordPress database, including "
     "customer data, orders, and admin password hashes.",
     "Delete this backup file from the server immediately (via FTP/file manager), or move it outside the public web folder. "
     "Never leave .bak, .old, or ~ copies of config files in a publicly accessible location."),
    ("/backup.sql", "HIGH", "Database Backup File Exposed",
     "a SQL database backup file is publicly downloadable",
     "Anyone can download your entire database — customer records, orders, password hashes — in one file.",
     "Delete or move this file outside the public web folder immediately. Store backups somewhere not served by the web server, such as private cloud storage."),
    ("/database.sql", "HIGH", "Database Backup File Exposed",
     "a SQL database file is publicly downloadable",
     "Anyone can download your entire database — customer records, orders, password hashes — in one file.",
     "Delete or move this file outside the public web folder immediately. Store backups somewhere not served by the web server, such as private cloud storage."),
    ("/.htpasswd", "HIGH", "Exposed .htpasswd File",
     "the .htpasswd password file is publicly downloadable",
     "This file contains hashed passwords protecting restricted areas of your site — once downloaded, an attacker "
     "can attempt to crack them offline at their leisure.",
     "Block access to .htpasswd in your server config (it should never be servable), and change the passwords it protects."),
    ("/phpinfo.php", "MEDIUM", "phpinfo() Page Exposed",
     "a phpinfo() debug page is publicly accessible, revealing detailed server configuration",
     "This page reveals your exact PHP version, installed modules, internal file paths, and sometimes other "
     "environment secrets — all useful information for planning a targeted attack.",
     "Delete this file from the server. It should never be left on a production site."),
    ("/info.php", "MEDIUM", "phpinfo() Page Exposed",
     "a phpinfo() debug page is publicly accessible, revealing detailed server configuration",
     "This page reveals your exact PHP version, installed modules, internal file paths, and sometimes other "
     "environment secrets — all useful information for planning a targeted attack.",
     "Delete this file from the server. It should never be left on a production site."),
    ("/.DS_Store", "LOW", "Exposed .DS_Store File",
     "a macOS .DS_Store file is publicly accessible, which can reveal the names of other files in the same folder",
     "This file can list the names of other files on the server in the same folder, sometimes giving an attacker "
     "hints about other things to probe for.",
     "Delete the file and add a server rule to block it. Nginx: 'location ~ /\\.DS_Store$ { deny all; }'."),
    ("/web.config.bak", "HIGH", "IIS Config Backup Exposed",
     "a backup of web.config is publicly downloadable, which can contain connection strings and other secrets",
     "Connection strings and other secrets in this file can give direct access to your database or internal services.",
     "Delete this backup file from the server immediately, and rotate any credentials it contained."),
]

_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{20,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
]

_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.I)


# ── Public entry point ────────────────────────────────────────────────────────

def run_vuln_checks(host: str) -> list[dict]:
    if not HAS_HTTPX:
        return []

    base_url, html = _fetch_homepage(host)
    if not base_url:
        return []

    findings = []

    try:
        findings.extend(_check_exposed_files(base_url))
    except Exception:
        pass
    try:
        findings.extend(_check_leaked_secrets(base_url, html))
    except Exception:
        pass
    try:
        findings.extend(_check_cors(base_url))
    except Exception:
        pass

    targets = _discover_targets(base_url, html)[:MAX_TARGETS]
    for target in targets:
        baseline = _send(target, "rv1")
        try:
            findings.extend(_check_xss(target))
        except Exception:
            pass
        try:
            findings.extend(_check_sqli(target, baseline))
        except Exception:
            pass
        try:
            findings.extend(_check_cmdi(target, baseline))
        except Exception:
            pass
        try:
            findings.extend(_check_open_redirect(target))
        except Exception:
            pass

    findings.sort(key=lambda f: RISK_ORDER.get(f.get("risk", "INFO"), 99))
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(port, service, risk, reason, title="", version="",
             category="vuln", how_to_fix="", urgency="", business_risk=""):
    return {
        "port":       port,
        "proto":      "tcp",
        "state":      "checked",
        "service":    service,
        "version":    version,
        "risk":       risk,
        "reason":     reason,
        "what_it_is": reason,
        "business_risk": business_risk or reason,
        "dangerous":  risk in ("HIGH", "MEDIUM"),
        "title":      title or f"{service} Issue",
        "category":   category,
        "how_to_fix": how_to_fix,
        "urgency":    urgency or (
            "Fix immediately" if risk == "HIGH" else
            "Fix within 1 week" if risk == "MEDIUM" else
            "Fix within 1 month"
        ),
    }


def _fetch_homepage(host: str):
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=REQUEST_TIMEOUT,
                          follow_redirects=True, verify=False)
            return str(r.url), r.text
        except Exception:
            continue
    return "", ""


def _attrs(tag_text: str) -> dict:
    out = {}
    for m in _ATTR_RE.finditer(tag_text):
        k = (m.group(1) or m.group(3) or "").lower()
        v = m.group(2) if m.group(2) is not None else m.group(4)
        out[k] = v
    return out


def _discover_targets(base_url: str, html: str) -> list[dict]:
    """Find form fields and query-string parameters worth probing."""
    targets = []

    for form_match in _FORM_RE.finditer(html):
        form_attrs = _attrs(form_match.group(1))
        action = form_attrs.get("action", "")
        method = form_attrs.get("method", "get").lower()
        url = urljoin(base_url, action) if action else base_url

        field_names = []
        for input_match in _INPUT_RE.finditer(form_match.group(2)):
            field_attrs = _attrs(input_match.group(1))
            if field_attrs.get("type", "text").lower() in _SKIP_INPUT_TYPES:
                continue
            name = field_attrs.get("name")
            if name:
                field_names.append(name)

        for name in field_names:
            targets.append({
                "kind": "form", "url": url, "method": method,
                "field": name, "fields": field_names,
                "label": f"the '{name}' field in a form on {url}",
            })

    seen_params = set()
    for link_match in _LINK_RE.finditer(html):
        url = urljoin(base_url, link_match.group(1))
        split = urlsplit(url)
        params = parse_qsl(split.query, keep_blank_values=True)
        param_names = [n for n, _ in params]
        for name in param_names:
            key = (split.scheme, split.netloc, split.path, name)
            if key in seen_params:
                continue
            seen_params.add(key)
            targets.append({
                "kind": "param", "url": url, "method": "get",
                "field": name, "fields": param_names,
                "label": f"the '{name}' URL parameter on {split.path or '/'}",
            })

    return targets


def _send(target: dict, payload: str, timeout: float = REQUEST_TIMEOUT):
    try:
        data = {f: (payload if f == target["field"] else "rv1") for f in target["fields"]}
        if target["method"] == "post":
            return httpx.post(target["url"], data=data, timeout=timeout, verify=False)
        split = urlsplit(target["url"])
        params = dict(parse_qsl(split.query, keep_blank_values=True))
        params.update(data)
        url = urlunsplit((split.scheme, split.netloc, split.path, urlencode(params), ""))
        return httpx.get(url, timeout=timeout, verify=False)
    except Exception:
        return None


# ── Reflected XSS ────────────────────────────────────────────────────────────

def _check_xss(target: dict) -> list[dict]:
    resp = _send(target, _XSS_PAYLOAD)
    if resp is None or _XSS_PAYLOAD not in resp.text:
        return []
    return [_finding(
        "XSS", "Reflected XSS", "HIGH",
        f"{target['label']} reflects user input back into the page without escaping it, "
        f"a real attacker could inject a script that runs in visitors' browsers",
        "Reflected Cross-Site Scripting (XSS)",
        business_risk=(
            "An attacker can craft a link that, when a customer clicks it, runs malicious code in their "
            "browser while they're on your site, stealing login sessions, showing fake login forms, or "
            "redirecting them to a scam page. This can also get your site blacklisted by Google Safe Browsing."
        ),
        how_to_fix=(
            f"Escape/encode all user input before rendering it in HTML (e.g. htmlspecialchars() in PHP, or "
            f"the auto-escaping built into Flask/Django/Rails templates). Check {target['label']}. "
            f"Adding a strict Content-Security-Policy header also limits the damage if escaping is ever missed."
        ),
    )]


# ── SQL injection ─────────────────────────────────────────────────────────────

def _check_sqli(target: dict, baseline) -> list[dict]:
    probe = _send(target, _SQLI_PAYLOAD)
    if probe is None:
        return []
    body = probe.text.lower()
    baseline_body = baseline.text.lower() if baseline is not None else ""
    for sig in _SQL_ERROR_SIGNATURES:
        if sig in body and sig not in baseline_body:
            return [_finding(
                "SQLi", "SQL Injection", "HIGH",
                f"{target['label']} returned a database error message after being sent a quote character, "
                f"a strong sign the input reaches a SQL query without being sanitized",
                "Possible SQL Injection",
                business_risk=(
                    "An attacker could potentially read your entire database (customer records, passwords, "
                    "orders) or modify/delete data by sending crafted input to this field instead of normal "
                    "text. This is one of the most damaging and common website vulnerabilities."
                ),
                how_to_fix=(
                    f"Never build SQL queries by concatenating user input. Use parameterized queries / "
                    f"prepared statements (e.g. cursor.execute('...WHERE id=%s', (value,))) instead of string "
                    f"formatting. Check {target['label']}. Also disable detailed database error messages in production."
                ),
            )]
    return []


# ── Command injection ─────────────────────────────────────────────────────────

def _check_cmdi(target: dict, baseline) -> list[dict]:
    baseline_elapsed = 0.0
    if baseline is not None:
        baseline_elapsed = baseline.elapsed.total_seconds()

    for payload in _CMDI_PAYLOADS:
        start = time.monotonic()
        resp = _send(target, payload, timeout=REQUEST_TIMEOUT + CMDI_DELAY + 2)
        elapsed = time.monotonic() - start
        if resp is None:
            continue
        if elapsed - baseline_elapsed >= CMDI_DELAY - 1:
            return [_finding(
                "CMDi", "Command Injection", "HIGH",
                f"{target['label']} took {elapsed:.1f}s to respond to a harmless 'sleep {CMDI_DELAY}' payload "
                f"(normal response: {baseline_elapsed:.1f}s), a strong sign the input reaches a system shell",
                "Possible OS Command Injection",
                business_risk=(
                    "An attacker could potentially run arbitrary commands on your server, reading files, "
                    "installing malware, or taking the server over completely. This is one of the most "
                    "severe vulnerabilities a website can have."
                ),
                how_to_fix=(
                    f"Never pass user input directly to a shell command. Use your language's built-in library "
                    f"functions instead of shell calls, or strictly allow-list expected input. Check {target['label']}."
                ),
            )]
    return []


# ── Exposed sensitive files ───────────────────────────────────────────────────

def _looks_like_fallback_page(text: str, *references: str) -> bool:
    """True if `text` looks like the same soft-404/catch-all page as one of
    the reference pages, rather than a genuinely distinct file."""
    if not text:
        return True
    for ref in references:
        if ref and abs(len(text) - len(ref)) < 30 and text[:200] == ref[:200]:
            return True
    return False


def _check_exposed_files(base_url: str) -> list[dict]:
    home_text = ""
    try:
        home_text = httpx.get(base_url, timeout=REQUEST_TIMEOUT, verify=False).text
    except Exception:
        pass

    baseline_text = ""
    try:
        control_path = f"/rv-control-{uuid.uuid4().hex[:10]}"
        baseline_text = httpx.get(urljoin(base_url, control_path), timeout=REQUEST_TIMEOUT, verify=False).text
    except Exception:
        pass

    findings = []
    for path, risk, title, reason, business_risk, how_to_fix in _SENSITIVE_FILES:
        try:
            r = httpx.get(urljoin(base_url, path), timeout=REQUEST_TIMEOUT, verify=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        if _looks_like_fallback_page(r.text, baseline_text, home_text):
            continue
        findings.append(_finding(
            "FILE", "Information Disclosure", risk, reason, title,
            business_risk=business_risk, how_to_fix=how_to_fix,
        ))
    return findings


# ── Leaked secrets in page/JS source ──────────────────────────────────────────

def _scan_for_secrets(text: str, source_label: str, seen_types: set, findings: list):
    for name, pattern in _SECRET_PATTERNS:
        if name in seen_types:
            continue
        m = pattern.search(text)
        if not m:
            continue
        seen_types.add(name)
        match = m.group(0)
        masked = match[:6] + "…" + match[-4:] if len(match) > 10 else "…"
        findings.append(_finding(
            "SECRET", "Exposed Credential", "HIGH",
            f"A {name} was found exposed in {source_label} ({masked}) — visible to anyone who views the page source",
            f"Exposed {name} in Page Source",
            business_risk=(
                "Anyone who views your page source or downloaded JavaScript can copy this credential and use it "
                "directly — potentially running up charges on your account, sending data through your services, "
                "or accessing whatever this key controls."
            ),
            how_to_fix=(
                f"Revoke/rotate this key immediately in the relevant provider's dashboard, then remove it from "
                f"{source_label}. Secret keys must only ever be used in backend/server code, never embedded in "
                f"HTML or JavaScript sent to the browser. Use environment variables on the server instead."
            ),
        ))


def _check_leaked_secrets(base_url: str, html: str) -> list[dict]:
    findings = []
    seen_types = set()

    _scan_for_secrets(html, "the homepage HTML", seen_types, findings)

    script_urls = []
    base_netloc = urlsplit(base_url).netloc
    for m in _SCRIPT_SRC_RE.finditer(html):
        full = urljoin(base_url, m.group(1))
        if urlsplit(full).netloc == base_netloc:
            script_urls.append(full)

    for url in script_urls[:MAX_SCRIPTS]:
        try:
            r = httpx.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        except Exception:
            continue
        _scan_for_secrets(r.text, f"a loaded script ({urlsplit(url).path})", seen_types, findings)

    return findings


# ── Open redirect ──────────────────────────────────────────────────────────────

def _check_open_redirect(target: dict) -> list[dict]:
    if target["kind"] != "param":
        return []
    if not any(hint in target["field"].lower() for hint in _REDIRECT_FIELD_HINTS):
        return []

    evil_host = "rv-redirect-test-evil.example"
    resp = _send(target, f"https://{evil_host}/")
    if resp is None:
        return []
    location = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and evil_host in location:
        return [_finding(
            "REDIR", "Open Redirect", "MEDIUM",
            f"{target['label']} redirects to an attacker-controlled external URL when given one, without validating it stays on this domain",
            "Open Redirect Vulnerability",
            business_risk=(
                "Scammers can craft a link that starts with your real, trusted domain but redirects victims to a "
                "phishing or malware site — making the scam far more convincing since the link itself looks legitimate."
            ),
            how_to_fix=(
                f"Validate redirect destinations against an allow-list of your own domain/paths before redirecting. "
                f"Reject or ignore any redirect target that isn't a relative path or doesn't match your domain. Check {target['label']}."
            ),
        )]
    return []


# ── CORS misconfiguration ────────────────────────────────────────────────────

def _check_cors(base_url: str) -> list[dict]:
    evil_origin = "https://rv-cors-test-evil.example"
    try:
        r = httpx.get(base_url, headers={"Origin": evil_origin}, timeout=REQUEST_TIMEOUT, verify=False)
    except Exception:
        return []

    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    if acao == evil_origin and acac == "true":
        return [_finding(
            "CORS", "CORS Misconfiguration", "HIGH",
            "the site reflects any Origin header back in Access-Control-Allow-Origin while also allowing "
            "credentials, letting any other website read logged-in users' data through their browser",
            "CORS Misconfiguration (Reflected Origin + Credentials)",
            business_risk=(
                "A malicious website a logged-in customer visits can silently make authenticated requests to "
                "your site from their browser and read the response — potentially stealing account data, "
                "orders, or session details without the customer ever noticing."
            ),
            how_to_fix=(
                "Stop reflecting the request's Origin header back unconditionally. Use an explicit allow-list of "
                "trusted origins for Access-Control-Allow-Origin instead of echoing the request's own Origin, "
                "and only set Access-Control-Allow-Credentials: true for origins on that list."
            ),
        )]
    return []
