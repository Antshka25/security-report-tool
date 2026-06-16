"""
vuln_checks.py — Active checks for SQL injection, reflected XSS, and OS
command injection. Discovers forms/URL parameters on the target's homepage
and sends small, non-destructive probe payloads, then looks for tell-tale
signs (DB error text, unescaped reflection, abnormal response delay).
Every finding includes a specific how_to_fix instruction.
"""
import time
import re
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


# ── Public entry point ────────────────────────────────────────────────────────

def run_vuln_checks(host: str) -> list[dict]:
    if not HAS_HTTPX:
        return []

    base_url, html = _fetch_homepage(host)
    if not base_url:
        return []

    targets = _discover_targets(base_url, html)[:MAX_TARGETS]
    if not targets:
        return []

    findings = []
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
