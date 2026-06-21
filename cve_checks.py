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
# Widened from the original 1-year window: most real-world vulnerable deployments
# are running outdated software with CVEs disclosed well over a year ago, not just
# recent ones — limiting to 365 days excluded the single most common real case.
CVE_LOOKBACK_DAYS    = 1825  # ~5 years
MAX_CVES_PER_PRODUCT = 3     # cap noise — most relevant/most recent only
MAX_PRODUCTS         = 6     # cap how many detected products we look up per scan
# NVD's public rate limit is 5 requests/30s unauthenticated (50/30s with NVD_API_KEY).
# Space requests out when no key is configured so we don't get throttled mid-scan.
REQUEST_DELAY        = 0 if NVD_API_KEY else 6

_SERVER_VERSION_RE     = re.compile(r'(apache|nginx|iis|php|openssl|lighttpd|tomcat|werkzeug|caddy|litespeed|openresty|varnish)[/\s]([\d.]+)', re.I)
_ASPNET_VERSION_RE     = re.compile(r'([\d.]+)')
_GENERATOR_RE          = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_GENERATOR_VERSION_RE  = re.compile(r'([A-Za-z][A-Za-z .]*?)\s+([\d]+(?:\.[\d]+){1,3})')
# Negative lookbehind avoids misattributing e.g. "flowchart-1.2.js" to "chart" —
# only matches when the library name isn't itself glued onto a preceding word.
_JS_LIB_RE             = re.compile(
    r'(?<![A-Za-z0-9])(jquery-ui|jquery-migrate|jquery|bootstrap|angularjs|angular|vue|react|'
    r'lodash|underscore|moment|handlebars|knockout|backbone|ember|ckeditor|tinymce|d3|chart|'
    r'axios|select2)[.-]([\d]+(?:\.[\d]+){1,3})(?:\.min)?\.js', re.I)
# WordPress's bundled readme.html exposes the core version even when sites strip
# the <meta name="generator"> tag to hide it — see _fingerprint_wordpress().
_WP_VERSION_RE         = re.compile(r'Version\s+([\d]+(?:\.[\d]+){1,3})', re.I)


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

    # ASP.NET discloses its version via dedicated headers rather than Server/X-Powered-By
    m = _ASPNET_VERSION_RE.search(headers.get("x-aspnet-version", ""))
    if m:
        products.append(("asp.net", m.group(1)))
    m = _ASPNET_VERSION_RE.search(headers.get("x-aspnetmvc-version", ""))
    if m:
        products.append(("asp.net mvc", m.group(1)))

    gen = _GENERATOR_RE.search(html)
    if gen:
        gm = _GENERATOR_VERSION_RE.search(gen.group(1))
        if gm:
            products.append((gm.group(1).strip().lower(), gm.group(2)))

    for jm in _JS_LIB_RE.finditer(html):
        products.append((jm.group(1).lower(), jm.group(2)))

    # WordPress core version via readme.html — only probe if the generator tag
    # didn't already reveal it (saves a request; also catches hardened sites
    # that strip the tag but leave readme.html in place).
    if not any(name == "wordpress" for name, _ in products):
        products.extend(_fingerprint_wordpress(host))

    # de-dupe while preserving detection order
    seen = set()
    unique = []
    for pair in products:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


def _fingerprint_wordpress(host: str) -> list[tuple]:
    """WordPress core version disclosure via the default /readme.html file —
    a long-standing, widely-documented fingerprinting technique (used by tools
    like WPScan) that often still works even when the homepage's generator
    meta tag has been deliberately stripped to hide the version."""
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}/readme.html", timeout=REQUEST_TIMEOUT,
                          follow_redirects=True, verify=False)
            if r.status_code == 200 and "wordpress" in r.text.lower():
                m = _WP_VERSION_RE.search(r.text)
                if m:
                    return [("wordpress", m.group(1))]
            break
        except Exception:
            continue
    return []


# ── NVD lookup ───────────────────────────────────────────────────────────────

def _lookup_cves(product: str, version: str) -> list[dict]:
    """Queries NVD for product+version, published within the lookback window,
    and only keeps results that mention the exact version string in their
    description — a keyword search alone is too noisy to report on its own."""
    now = datetime.now(timezone.utc)
    params = {
        "keywordSearch":  f"{product} {version}",
        "resultsPerPage": 50,
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
        if not cve_id:
            continue
        # Prefer NVD's own structured affected-version ranges (configurations/cpeMatch)
        # over a literal substring check — catches real matches the description text
        # doesn't spell out (e.g. "before 2.4.51" won't contain "2.4.49" literally).
        # Falls back to the substring check when NVD has no usable range data for
        # this CVE, so existing matches aren't lost.
        if not (_cpe_confirms_version(cve, product, version) or version in desc):
            continue

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


def _cpe_confirms_version(cve: dict, product: str, version: str) -> bool:
    """Checks NVD's structured CPE match ranges (configurations/nodes/cpeMatch)
    to see if the detected version actually falls within the affected range —
    more accurate than a literal substring-in-description check, and still
    100% derived from NVD's own data, never guessed."""
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                cpe_parts = match.get("criteria", "").split(":")
                if len(cpe_parts) < 6:
                    continue
                # CPE 2.3 puts the vendor at index 3 and product at index 4 — for
                # software like Apache HTTP Server, the colloquial name we detect
                # ("apache") is the *vendor* field; the product field is "http_server".
                # Checking both avoids silently never matching well-known software.
                cpe_vendor  = cpe_parts[3].replace("_", " ").lower()
                cpe_product = cpe_parts[4].replace("_", " ").lower()
                cpe_name = f"{cpe_vendor} {cpe_product}".strip()
                if (product.lower() not in cpe_name
                        and cpe_product not in product.lower()
                        and cpe_vendor not in product.lower()):
                    continue  # this cpeMatch entry is for a different product
                cpe_version = cpe_parts[5]
                if cpe_version not in ("*", "-"):
                    if cpe_version == version:
                        return True
                    continue
                bounds = (
                    match.get("versionStartIncluding"), match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"), match.get("versionEndExcluding"),
                )
                if any(bounds) and _version_satisfies(version, *bounds):
                    return True
    return False


def _version_key(v: str):
    """Parses a dotted version string into a tuple for comparison, e.g.
    '2.4.49' -> (2, 4, 49). Non-numeric segments are kept as strings so odd
    version formats degrade gracefully instead of raising."""
    return tuple(int(p) if p.isdigit() else p for p in re.split(r'[.\-]', v))


def _version_satisfies(version: str, start_inc=None, start_exc=None, end_inc=None, end_exc=None) -> bool:
    try:
        v = _version_key(version)
        if start_inc is not None and v < _version_key(start_inc):
            return False
        if start_exc is not None and v <= _version_key(start_exc):
            return False
        if end_inc is not None and v > _version_key(end_inc):
            return False
        if end_exc is not None and v >= _version_key(end_exc):
            return False
        return True
    except TypeError:
        # Mixed int/str segments aren't orderable (e.g. 49 vs "x") — too
        # unreliable to base a security finding on, so don't claim a match.
        return False


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
