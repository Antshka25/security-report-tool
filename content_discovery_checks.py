"""
content_discovery_checks.py — Authorized hidden-directory and sensitive-file
discovery. Probes a small, configurable list of commonly forgotten/admin/
backup/config paths on the target's own origin, using only normal HTTP GET
requests (no auth bypass, no exploitation, no destructive testing).

Every finding includes a specific how_to_fix instruction, matching the shape
used by web_checks.py / vuln_checks.py / cve_checks.py / supply_chain_checks.py
so it flows through build_scan_summary() and ai_reporter.py unchanged.

Authorization: this module assumes the caller has already gated the scan
behind the same "I own this site / am authorized" checkbox used everywhere
else in the app (see app.py's start_scan()) — it does not re-implement that
check, it just does normal, low-impact GET requests once invoked.
"""
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urljoin

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

REQUEST_TIMEOUT = 6
MAX_REDIRECTS   = 3
BASELINE_PROBES = 2      # randomized nonexistent paths sampled before scanning
RATE_LIMIT_STREAK_STOP = 3   # consecutive 429/503 responses that pause the scan


# ── Scan profiles ──────────────────────────────────────────────────────────────
# Each profile controls how much of _DEFAULT_PATHS / _BACKUP_COMBOS gets probed,
# how many requests run at once, and how long to pause between batches. Kept
# conservative by default since this hits a real, possibly-third-party-adjacent
# server — see the "Scan depth" note in the UI.

_PROFILES = {
    "quick":    {"max_paths": 25,  "concurrency": 5,  "delay_between_batches": 0.0},
    "standard": {"max_paths": 100, "concurrency": 5,  "delay_between_batches": 0.15},
    "thorough": {"max_paths": 300, "concurrency": 10, "delay_between_batches": 0.25},
}
DEFAULT_PROFILE = "standard"


# ── Path list ──────────────────────────────────────────────────────────────────
# Deliberately a plain Python list, ordered highest-value-first (profiles just
# slice into it), so a larger external wordlist can be dropped in later without
# touching any other logic: swap _DEFAULT_PATHS for e.g. a file-loaded list,
# or extend it, and everything downstream (probing, classification, profiles)
# keeps working unchanged.

_DEFAULT_PATHS = [
    # Highest-value / most sensitive first — these are what "quick" covers.
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/config.php",
    "/wp-config.php.bak",
    "/.svn/entries",
    "/backup.sql",
    "/database.sql",
    "/db.sql",
    "/.htpasswd",
    "/id_rsa",
    "/server-status",
    "/phpinfo.php",
    "/admin/",
    "/administrator/",
    "/login/",
    "/dashboard/",
    "/backup/",
    "/backups/",
    "/config/",
    "/debug/",
    "/swagger-ui/",
    "/swagger.json",
    "/openapi.json",
    "/api/",
    "/.aws/credentials",

    # Broader / dev / staging / misc — "standard" and "thorough" extend into these.
    "/old/",
    "/test/",
    "/staging/",
    "/dev/",
    "/tmp/",
    "/uploads/",
    "/private/",
    "/secret/",
    "/hidden/",
    "/internal/",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/.well-known/security.txt",
    "/composer.json",
    "/package.json",
    "/web.config",
    "/web.config.bak",
    "/wp-admin/",
    "/phpmyadmin/",
    "/adminer.php",
    "/info.php",
    "/status",
    "/metrics",
    "/.DS_Store",
    "/.idea/workspace.xml",
    "/.vscode/settings.json",
    "/error_log",
    "/debug.log",
    "/robots.txt",
    "/sitemap.xml",
]

# Base names + backup-style extensions get combined at scan time (only for
# "standard"/"thorough" profiles, since this multiplies the list quickly).
_BACKUP_BASE_NAMES = ["backup", "site", "www", "database", "db", "config", "app", "old"]
_BACKUP_EXTENSIONS = [".bak", ".old", ".backup", ".zip", ".tar.gz"]

_LOGIN_LIKE_PATHS = {"/login/", "/admin/", "/administrator/", "/dashboard/", "/wp-admin/"}


def _backup_combo_paths() -> list:
    return [f"/{name}{ext}" for name in _BACKUP_BASE_NAMES for ext in _BACKUP_EXTENSIONS]


def _build_path_list(profile: str, extra_paths: list) -> list:
    """Combine the built-in list + robots/sitemap-discovered paths + backup
    combos, dedupe while preserving priority order, then cap per profile."""
    cfg = _PROFILES.get(profile, _PROFILES[DEFAULT_PROFILE])
    ordered = list(_DEFAULT_PATHS)
    if profile in ("standard", "thorough"):
        ordered += _backup_combo_paths()
    # robots.txt / sitemap.xml derived paths are appended (deduped) rather than
    # prioritized above the curated list, since they're arbitrary in number and
    # we don't want a huge sitemap silently starving out the high-value paths.
    ordered += extra_paths

    seen, unique = set(), []
    for p in ordered:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique[: cfg["max_paths"]]


# ── Target/URL helpers ───────────────────────────────────────────────────────

def _resolve_base_url(host: str):
    """Same pattern as vuln_checks.py's _fetch_homepage — try https then http,
    follow redirects to land on the real scheme/host, and never leave that
    origin afterward (see _is_same_origin)."""
    if not HAS_HTTPX:
        return "", ""
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=REQUEST_TIMEOUT,
                          follow_redirects=True, verify=False)
            return str(r.url).rstrip("/"), urlsplit(str(r.url)).netloc.lower()
        except Exception:
            continue
    return "", ""


def _is_same_origin(base_netloc: str, url: str) -> bool:
    try:
        return urlsplit(url).netloc.lower() == base_netloc
    except Exception:
        return False


# ── Soft-404 baseline ────────────────────────────────────────────────────────

def _title_of(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return (m.group(1).strip() if m else "")[:120]


def _fingerprint(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")[:400]).strip()


def _build_baseline(client, base_url: str) -> list:
    """Fetch a couple of definitely-nonexistent paths and record their status,
    length, title, and a body fingerprint — everything discovered later gets
    checked against this before being treated as a real finding, so a site's
    custom 404/soft-404 page never gets reported as N different exposures."""
    baseline = []
    for _ in range(BASELINE_PROBES):
        control = f"/rv-cd-control-{uuid.uuid4().hex[:12]}"
        try:
            r = client.get(urljoin(base_url + "/", control.lstrip("/")),
                           timeout=REQUEST_TIMEOUT, follow_redirects=True)
            baseline.append({
                "status": r.status_code,
                "length": len(r.text or ""),
                "title": _title_of(r.text),
                "fingerprint": _fingerprint(r.text),
            })
        except Exception:
            continue
    return baseline


def _matches_baseline(baseline: list, status: int, text: str) -> bool:
    """True if this response looks like the same soft-404/catch-all page as
    one of the baseline samples, rather than genuinely distinct content."""
    length = len(text or "")
    title = _title_of(text)
    fp = _fingerprint(text)
    for b in baseline:
        if b["status"] != status:
            continue
        if abs(b["length"] - length) > 40:
            continue
        if b["title"] and title and b["title"] != title:
            continue
        if b["fingerprint"] and fp and b["fingerprint"][:150] != fp[:150]:
            continue
        return True
    return False


# ── robots.txt / sitemap.xml same-origin path extraction ────────────────────

_ROBOTS_PATH_RE  = re.compile(r"^\s*(?:Disallow|Allow)\s*:\s*(\S+)", re.I | re.M)
_SITEMAP_LOC_RE  = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def _extract_from_robots(text: str) -> list:
    paths = []
    for m in _ROBOTS_PATH_RE.finditer(text or ""):
        p = m.group(1).strip()
        if p and p != "/" and p.startswith("/"):
            paths.append(p)
    return paths


def _extract_from_sitemap(text: str, base_netloc: str) -> list:
    paths = []
    for m in _SITEMAP_LOC_RE.finditer(text or ""):
        url = m.group(1).strip()
        split = urlsplit(url)
        if split.netloc and split.netloc.lower() != base_netloc:
            continue  # cross-origin sitemap entry — not our target, skip
        if split.path:
            paths.append(split.path)
    return paths


def _discover_seed_paths(client, base_url: str, base_netloc: str) -> list:
    seeds = []
    try:
        r = client.get(urljoin(base_url + "/", "robots.txt"), timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            seeds += _extract_from_robots(r.text)
    except Exception:
        pass
    try:
        r = client.get(urljoin(base_url + "/", "sitemap.xml"), timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            seeds += _extract_from_sitemap(r.text, base_netloc)
    except Exception:
        pass
    return seeds


# ── Sensitive-content detection (redacted) ───────────────────────────────────
# Detects that a response *contains* secret-shaped content without ever
# keeping the full value — only a short redacted proof survives into a finding.

_ENV_KEY_RE = re.compile(
    r"(?im)^\s*([A-Z0-9_]{2,60}(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*)\s*=\s*(\S+)"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
_DB_CONN_RE = re.compile(r"(?i)\b(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s\"'<>]{6,}")
_KNOWN_TOKEN_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
]
_GIT_HEAD_RE   = re.compile(r"ref:\s*refs/heads/")
_GIT_CONFIG_RE = re.compile(r"\[core\]|repositoryformatversion")


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) > 10:
        return value[:3] + "…[REDACTED]…" + value[-2:]
    return "[REDACTED]"


def _detect_sensitive_content(path: str, text: str, headers) -> list:
    """Returns a list of (label, redacted_evidence) tuples for whatever
    secret-shaped content was found — never the raw matched value."""
    hits = []
    if not text:
        return hits

    for m in _ENV_KEY_RE.finditer(text):
        key, val = m.group(1), m.group(2)
        hits.append((f"Environment variable ({key})", f"{key}={_redact(val)}"))
        if len(hits) >= 3:
            break

    if _PRIVATE_KEY_RE.search(text):
        hits.append(("Private key block", "-----BEGIN [...] PRIVATE KEY-----[REDACTED]"))

    m = _DB_CONN_RE.search(text)
    if m:
        scheme = m.group(1)
        hits.append((f"{scheme} database connection string", f"{scheme}://[REDACTED]"))

    for name, pattern in _KNOWN_TOKEN_PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append((name, _redact(m.group(0))))

    if path.endswith(("/.git/HEAD",)) and _GIT_HEAD_RE.search(text):
        hits.append(("Git HEAD metadata", "ref: refs/heads/[REDACTED]"))
    if path.endswith((".git/config",)) and _GIT_CONFIG_RE.search(text):
        hits.append(("Git config metadata", "[core] repositoryformatversion=[present]"))

    return hits


def _looks_like_archive_or_db(path: str, headers, content_bytes: bytes) -> bool:
    ctype = (headers.get("content-type") or "").lower()
    if any(t in ctype for t in ("zip", "gzip", "x-tar", "octet-stream", "sql")):
        if path.endswith((".zip", ".tar.gz", ".bak", ".old", ".backup", ".sql")):
            return True
    if content_bytes[:2] == b"PK":       # zip magic
        return True
    if content_bytes[:2] == b"\x1f\x8b":  # gzip magic
        return True
    return False


# ── Classification ───────────────────────────────────────────────────────────

_HIGH_VALUE_SENSITIVE_SUFFIXES = (
    ".env", ".git/config", ".git/head", ".htpasswd", "id_rsa", "credentials",
)
_MEDIUM_VALUE_SUFFIXES = (
    ".bak", ".old", ".backup", ".zip", ".tar.gz", ".sql", "phpinfo.php",
    "server-status", "adminer.php", "info.php", "web.config", "config.php",
)
_API_DOC_SUFFIXES = ("swagger", "openapi.json", "graphql")


def _finding(path, url, http_status, risk, confidence, title, reason,
             evidence="", how_to_fix="", business_risk="", cwe="",
             real_world_example="", urgency=""):
    return {
        "port":       "PATH",
        "proto":      "tcp",
        "state":      "checked",
        "service":    "Content Discovery",
        "version":    "",
        "risk":       risk,
        "reason":     reason,
        "what_it_is": reason,
        "business_risk": business_risk or reason,
        "dangerous":  risk in ("HIGH", "MEDIUM"),
        "title":      title,
        "category":   "content_discovery",
        "cwe":        cwe,
        "real_world_example": real_world_example,
        "how_to_fix": how_to_fix,
        "urgency":    urgency or (
            "Fix immediately" if risk == "HIGH" else
            "Fix within 1 week" if risk == "MEDIUM" else
            "Fix within 1 month"
        ),
        # Extra fields specific to this module — additive, doesn't break the
        # shared finding shape the rest of the pipeline already expects.
        "path":        path,
        "url":         url,
        "http_status": http_status,
        "confidence":  confidence,   # "confirmed" | "probable" | "informational" — aligned with
                                     # web_checks.py's confidence vocabulary so scanner.py's
                                     # confidence-aware risk-score weighting applies consistently
                                     # across both modules.
        "evidence":    evidence,
    }


def _classify(path: str, url: str, status: int, headers, text: str,
              content_bytes: bytes, redirect_location: str, base_netloc: str) -> dict:
    """Turns one raw response into a finding dict, or None if it's nothing
    worth reporting (404/soft-404/etc). Deliberately conservative — existence
    of a path alone is never enough for a HIGH/MEDIUM finding; content or an
    auth-restricted status code is required."""
    lower_path = path.lower()

    if status in (404, 410):
        return None

    if status in (301, 302, 307, 308):
        if redirect_location and not _is_same_origin(base_netloc, redirect_location):
            return None  # cross-origin redirect — never followed, nothing to report
        dest_note = f" (redirects to {redirect_location})" if redirect_location else ""
        return _finding(
            path, url, status, "LOW", "informational",
            f"Path Discovered — {path}",
            f"{path} redirects to another page on the same site{dest_note}. This confirms the path "
            f"exists but doesn't by itself indicate a problem.",
            how_to_fix="No action needed unless this path should not exist publicly at all — in that "
                       "case, remove it or block it at the server level.",
            cwe="",
        )

    if status in (401, 403):
        label = "authentication" if status == 401 else "access control"
        return _finding(
            path, url, status, "LOW", "informational",
            f"Protected Path — {path}",
            f"{path} returned HTTP {status}. This confirms the path exists, but {label} prevented "
            f"access — it was not accessed.",
            how_to_fix="No action needed if this is intentionally restricted. Confirm the credentials "
                       "protecting it are strong and not left at a default.",
            cwe="CWE-284",
        )

    if status == 429:
        return None  # rate limiting — handled at the scan-loop level, not a finding

    if status >= 500:
        return _finding(
            path, url, status, "INFO", "informational",
            f"Server Error on {path}",
            f"{path} returned HTTP {status}. Recorded for visibility, not re-tested to avoid "
            f"repeatedly triggering a server error.",
            how_to_fix="Review server logs for this path if it isn't expected to error.",
        )

    if status not in (200, 204):
        return None

    # 200/204 from here — this is exactly where soft-404 pages masquerading as
    # "found" would otherwise become false positives; caller has already
    # filtered those out via _matches_baseline() before calling _classify().

    secret_hits = _detect_sensitive_content(path, text, headers)
    if secret_hits:
        label, evidence = secret_hits[0]
        extra = f" ({len(secret_hits) - 1} more redacted)" if len(secret_hits) > 1 else ""
        return _finding(
            path, url, status, "HIGH", "confirmed",
            f"Confirmed Sensitive-Content Exposure — {path}",
            f"{path} returned HTTP {status} and its content matched a known secret pattern "
            f"({label}). This was not a soft-404 or generic page — real sensitive content was present.",
            evidence=evidence + extra,
            business_risk=(
                "Whatever secret is exposed here (credentials, keys, or connection strings) can be used "
                "immediately by anyone who requests this URL — no further exploitation needed."
            ),
            real_world_example=(
                "Example: an automated bot that continuously scans for exposed .env/config files finds "
                "this one and tests the leaked credentials against the relevant service within minutes."
            ),
            how_to_fix=(
                f"Remove or block public access to {path} immediately (web server rule, e.g. Nginx "
                f"'location ~ {re.escape(path)} {{ deny all; }}'), and rotate every credential that "
                f"may have been exposed, since it should be treated as compromised."
            ),
            cwe="CWE-798",
            urgency="Fix immediately",
        )

    if _looks_like_archive_or_db(path, headers, content_bytes):
        return _finding(
            path, url, status, "MEDIUM", "probable",
            f"Publicly Accessible Backup/Archive — {path}",
            f"{path} returned HTTP {status} and its content looks like an archive or database file "
            f"(matched by content type / file signature), not a soft-404 page.",
            how_to_fix=f"Remove {path} from the public web root or block it at the server level. Store "
                       f"backups somewhere not served by the web server.",
            cwe="CWE-552",
        )

    if any(lower_path.endswith(suf) for suf in _HIGH_VALUE_SENSITIVE_SUFFIXES):
        return _finding(
            path, url, status, "HIGH", "probable",
            f"Sensitive Path Publicly Accessible — {path}",
            f"{path} returned HTTP {status} — a real, distinct response, not the site's soft-404 page. "
            f"No specific secret pattern was matched in this response, but this path is normally "
            f"never meant to be public.",
            how_to_fix=f"Remove or block public access to {path} immediately, and rotate any credentials "
                       f"it may have contained.",
            cwe="CWE-552",
            urgency="Fix immediately",
        )

    if any(lower_path.endswith(suf) or suf in lower_path for suf in _MEDIUM_VALUE_SUFFIXES):
        return _finding(
            path, url, status, "MEDIUM", "probable",
            f"Sensitive Path Publicly Accessible — {path}",
            f"{path} returned HTTP {status}, a real distinct page rather than a soft-404 — this kind "
            f"of path (backup/debug/admin-tooling) shouldn't normally be reachable by the public.",
            how_to_fix=f"Remove {path} from the public web root, or restrict access to it by IP allowlist.",
            cwe="CWE-552",
        )

    if any(tag in lower_path for tag in _API_DOC_SUFFIXES):
        # Distinguish "reveals internal endpoints" from "generic docs" isn't
        # possible without deeper parsing — flag as MEDIUM-and-explain rather
        # than guess, matching the "don't exaggerate" requirement.
        return _finding(
            path, url, status, "MEDIUM", "informational",
            f"API Documentation Exposed — {path}",
            f"{path} returned HTTP {status}. Publicly exposed API documentation can reveal internal "
            f"endpoints, parameters, or authentication schemes that weren't otherwise easy to find. "
            f"Review its contents manually to judge how sensitive it actually is.",
            how_to_fix="If this API is internal-only, restrict access to this documentation endpoint. "
                       "If it's meant to be public, no action needed.",
            cwe="CWE-200",
        )

    if path.rstrip("/") in ("/robots.txt",):
        return _finding(
            path, url, status, "INFO", "informational",
            "robots.txt Present", f"{path} is present and was used to seed additional path checks.",
            how_to_fix="No action needed — robots.txt is meant to be public.",
        )
    if path.rstrip("/") in ("/sitemap.xml",):
        return _finding(
            path, url, status, "INFO", "informational",
            "sitemap.xml Present", f"{path} is present and was used to seed additional path checks.",
            how_to_fix="No action needed — sitemap.xml is meant to be public.",
        )

    if path in _LOGIN_LIKE_PATHS:
        return _finding(
            path, url, status, "LOW", "informational",
            f"Login/Admin Path Discovered — {path}",
            f"{path} returned HTTP {status} with no authentication challenge. This confirms a login "
            f"or admin entry point exists at this path.",
            how_to_fix="Confirm this login is protected by a strong password and, ideally, multi-factor "
                       "authentication. Consider IP-restricting it if it's only used by internal staff.",
            cwe="CWE-284",
        )

    # Generic discovered path with normal-looking content and no other signal.
    return _finding(
        path, url, status, "INFO", "informational",
        f"Path Discovered — {path}",
        f"{path} returned HTTP {status}, a real distinct response rather than the site's soft-404 page.",
        how_to_fix="No action needed unless this path should not be public at all.",
    )


# ── Public entry point ────────────────────────────────────────────────────────

def run_content_discovery_checks(host: str, profile: str = DEFAULT_PROFILE) -> list:
    if not HAS_HTTPX:
        return []

    profile = profile if profile in _PROFILES else DEFAULT_PROFILE
    cfg = _PROFILES[profile]

    base_url, base_netloc = _resolve_base_url(host)
    if not base_url:
        return []

    headers = {"User-Agent": "RapidVuln-Scanner/1.0 (+https://rapidvuln.com; authorized-scan)"}

    with httpx.Client(headers=headers, verify=False, follow_redirects=False) as client:
        baseline = _build_baseline(client, base_url)
        seed_paths = _discover_seed_paths(client, base_url, base_netloc)
        paths = _build_path_list(profile, seed_paths)

        findings = []
        rate_limit_streak = 0
        stopped_early = False

        batch_size = cfg["concurrency"]
        for i in range(0, len(paths), batch_size):
            if stopped_early:
                break
            batch = paths[i:i + batch_size]

            with ThreadPoolExecutor(max_workers=batch_size) as pool:
                future_to_path = {
                    pool.submit(_probe_one, client, base_url, base_netloc, p): p
                    for p in batch
                }
                for future in as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if result is None:
                        continue

                    status, url, resp_headers, text, content_bytes, redirect_location, throttled = result

                    if throttled:
                        rate_limit_streak += 1
                        if rate_limit_streak >= RATE_LIMIT_STREAK_STOP:
                            stopped_early = True
                        continue
                    rate_limit_streak = 0

                    if status in (200, 204) and _matches_baseline(baseline, status, text):
                        continue  # soft-404 — matches the site's catch-all page, not a real finding

                    finding = _classify(path, url, status, resp_headers, text,
                                        content_bytes, redirect_location, base_netloc)
                    if finding:
                        findings.append(finding)

            if cfg["delay_between_batches"]:
                time.sleep(cfg["delay_between_batches"])

        if stopped_early:
            findings.append(_finding(
                "", base_url, 429, "INFO", "informational",
                "Content Discovery Scan Throttled",
                f"The target began responding with repeated rate-limit/unavailable statuses, so the "
                f"remaining {len(paths) - i} path(s) in this scan were skipped rather than risk "
                f"overloading the server.",
                how_to_fix="Re-run content discovery later, or use a lower-concurrency profile.",
                urgency="Monitor",
            ))

    findings.sort(key=lambda f: RISK_ORDER.get(f.get("risk", "INFO"), 99))
    return findings


def _probe_one(client, base_url: str, base_netloc: str, path: str):
    """Runs one GET, resolving redirects manually so we can refuse to follow
    off-origin ones and still record same-origin destinations. Returns
    (status, url, headers, text, content_bytes, redirect_location, throttled)
    or None on request failure."""
    url = urljoin(base_url + "/", path.lstrip("/"))
    redirects_followed = 0
    redirect_location = ""

    try:
        while True:
            r = client.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code in (429, 503):
                return (r.status_code, url, r.headers, "", b"", "", True)

            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                dest = urljoin(url, location) if location else ""
                if not dest:
                    return (r.status_code, url, r.headers, r.text, r.content, "", False)
                if not _is_same_origin(base_netloc, dest):
                    return (r.status_code, url, r.headers, r.text, r.content, dest, False)
                # Same-origin redirect — follow it ourselves (bounded) so we can
                # report what a browser would actually end up seeing, while
                # still refusing to ever leave the target's origin.
                redirects_followed += 1
                if redirects_followed > MAX_REDIRECTS:
                    return (r.status_code, url, r.headers, r.text, r.content, dest, False)
                url = dest
                continue

            return (r.status_code, url, r.headers, r.text, r.content, "", False)
    except Exception:
        return None
