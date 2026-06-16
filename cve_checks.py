"""
cve_checks.py — Fingerprints the scanned site's detected software/versions
(server software, CMS, common JS libraries) and checks the NVD CVE database
for publicly disclosed vulnerabilities affecting that exact version.
Every finding includes a specific how_to_fix instruction.
"""
import os
import re
import time
from datetime import datetime, timedelta, timezone

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

REQUEST_TIMEOUT     = 8
NVD_API_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY          = os.environ.get("NVD_API_KEY", "")
CVE_LOOKBACK_DAYS    = 365   # only surface CVEs published in roughly the last year
MAX_CVES_PER_PRODUCT = 3     # cap noise — most relevant/most recent only
MAX_PRODUCTS         = 4     # cap how many detected products we look up per scan
# NVD's public rate limit is 5 requests/30s unauthenticated (50/30s with NVD_API_KEY).
# Space requests out when no key is configured so we don't get throttled mid-scan.
REQUEST_DELAY        = 0 if NVD_API_KEY else 6

_SERVER_VERSION_RE     = re.compile(r'(apache|nginx|iis|php|openssl|lighttpd|tomcat)[/\s]([\d.]+)', re.I)
_GENERATOR_RE          = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_GENERATOR_VERSION_RE  = re.compile(r'([A-Za-z][A-Za-z .]*?)\s+([\d]+(?:\.[\d]+){1,3})')
_JS_LIB_RE             = re.compile(r'(jquery|bootstrap|angular|vue|react|lodash)[.-]([\d]+(?:\.[\d]+){1,3})(?:\.min)?\.js', re.I)


# ── Public entry point ────────────────────────────────────────────────────────

def run_cve_checks(host: str) -> list[dict]:
    if not HAS_HTTPX:
        return []

    products = _fingerprint(host)
    if not products:
        return []

    findings = []
    for i, (name, version) in enumerate(products[:MAX_PRODUCTS]):
        if i > 0 and REQUEST_DELAY:
            time.sleep(REQUEST_DELAY)
        try:
            findings.extend(_lookup_cves(name, version))
        except Exception:
            pass

    findings.sort(key=lambda f: RISK_ORDER.get(f.get("risk", "INFO"), 99))
    return findings


# ── Fingerprinting ───────────────────────────────────────────────────────────

def _fingerprint(host: str) -> list[tuple]:
    """Detects (product_name, version) pairs from the homepage's headers and HTML."""
    headers, html = {}, ""
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=REQUEST_TIMEOUT,
                          follow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in r.headers.items()}
            html = r.text
            break
        except Exception:
            continue
    if not headers and not html:
        return []

    products = []

    m = _SERVER_VERSION_RE.search(headers.get("server", ""))
    if m:
        products.append((m.group(1).lower(), m.group(2)))

    m = _SERVER_VERSION_RE.search(headers.get("x-powered-by", ""))
    if m:
        products.append((m.group(1).lower(), m.group(2)))

    gen = _GENERATOR_RE.search(html)
    if gen:
        gm = _GENERATOR_VERSION_RE.search(gen.group(1))
        if gm:
            products.append((gm.group(1).strip().lower(), gm.group(2)))

    for jm in _JS_LIB_RE.finditer(html):
        products.append((jm.group(1).lower(), jm.group(2)))

    # de-dupe while preserving detection order
    seen = set()
    unique = []
    for pair in products:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


# ── NVD lookup ───────────────────────────────────────────────────────────────

def _lookup_cves(product: str, version: str) -> list[dict]:
    """Queries NVD for product+version, published within the lookback window,
    and only keeps results that mention the exact version string in their
    description — a keyword search alone is too noisy to report on its own."""
    now = datetime.now(timezone.utc)
    params = {
        "keywordSearch":  f"{product} {version}",
        "resultsPerPage": 20,
        "pubStartDate":   (now - timedelta(days=CVE_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     now.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        r = httpx.get(NVD_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []

    findings = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        if not cve_id or version not in desc:
            continue  # require the exact version string — cuts down false positives

        severity, score = _extract_severity(cve.get("metrics", {}))
        risk = _severity_to_risk(severity)
        desc_snippet = desc if len(desc) <= 200 else desc[:200].rsplit(" ", 1)[0] + "…"

        findings.append(_finding(
            "HTTPS", f"{product.title()} {version}", risk,
            f"{cve_id} — publicly disclosed vulnerability affecting {product} {version}: {desc_snippet}",
            f"Known Vulnerability: {cve_id} ({product.title()} {version})",
            version=version,
            business_risk=(
                f"This is a publicly documented vulnerability (CVSS {score if score else 'unrated'}) — attackers "
                "routinely scan for sites still running the affected version, since the exploit details are "
                "already public."
            ),
            how_to_fix=(
                f"Update {product} past version {version} to a patched release — check the vendor's changelog "
                f"or security advisories. Details: https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
        ))
        if len(findings) >= MAX_CVES_PER_PRODUCT:
            break

    return findings


def _extract_severity(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            # CVSS v3.x carries baseSeverity inside cvssData; NVD attaches it
            # as a sibling field instead for CVSS v2 entries.
            severity = data.get("baseSeverity") or entry.get("baseSeverity", "")
            return severity, data.get("baseScore", "")
    return "", ""


def _severity_to_risk(severity: str) -> str:
    severity = (severity or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return "HIGH"
    if severity == "MEDIUM":
        return "MEDIUM"
    if severity == "LOW":
        return "LOW"
    return "INFO"


def _finding(port, service, risk, reason, title="", version="",
             category="cve", how_to_fix="", urgency="", business_risk=""):
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
