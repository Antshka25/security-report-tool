"""
breach_checks.py — Checks common business email addresses for the scanned
domain (info@, admin@, contact@, etc.) against HaveIBeenPwned's breach
database. Uses HIBP's Core-tier single-account lookup endpoint, not their
domain-wide search — the domain-wide API requires the domain owner to verify
ownership with HIBP directly, which doesn't fit a self-serve scan tool. The
common-address-guessing approach trades completeness (only catches these
specific addresses, not every employee) for something that works today at
low cost ($4.39/mo Core plan) with no per-customer verification step.
"""
import os
import time

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

HIBP_API_KEY     = os.environ.get("HIBP_API_KEY", "")
HIBP_API_URL     = "https://haveibeenpwned.com/api/v3/breachedaccount"
REQUEST_TIMEOUT  = 8
# HIBP's Core tier is rate-limited (single-digit requests/minute) — space
# lookups out so a scan doesn't get 429'd partway through the guessed list.
REQUEST_DELAY    = 2

# Common small-business inbox patterns — kept short deliberately: every entry
# costs a real API call against a rate-limited paid tier, and these are the
# addresses most likely to actually exist and be reused across services
# (newsletter signups, vendor accounts, etc.), which is exactly what shows up
# in breach dumps.
_COMMON_LOCAL_PARTS = ["info", "admin", "contact", "sales", "support"]


def run_breach_checks(host: str) -> list:
    if not HAS_HTTPX or not HIBP_API_KEY:
        return []

    domain = host.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    candidates = [f"{local}@{domain}" for local in _COMMON_LOCAL_PARTS]

    breached = []
    checked = []
    for i, email in enumerate(candidates):
        if i > 0:
            time.sleep(REQUEST_DELAY)
        try:
            breaches = _lookup_breach(email)
        except Exception:
            continue
        checked.append(email)
        if breaches:
            breached.append((email, breaches))

    if not checked:
        # Every lookup failed (network/API issue) — say nothing rather than
        # falsely implying a clean check ran.
        return []

    if not breached:
        return [_clean_finding(checked)]

    return [_breach_finding(email, breaches) for email, breaches in breached]


def _lookup_breach(email: str):
    """Returns a list of breach names for this exact email, or [] if it has
    never appeared in a known breach. Raises on network/API errors so the
    caller can distinguish "checked, clean" from "couldn't check"."""
    r = httpx.get(
        f"{HIBP_API_URL}/{email}",
        params={"truncateResponse": "false"},
        headers={
            "hibp-api-key": HIBP_API_KEY,
            "user-agent": "RapidVuln-Security-Scanner",
        },
        timeout=REQUEST_TIMEOUT,
    )
    if r.status_code == 404:
        return []
    if r.status_code != 200:
        raise RuntimeError(f"HIBP returned {r.status_code}")
    data = r.json()
    return [b.get("Name", b.get("Title", "Unknown breach")) for b in data]


def _breach_finding(email: str, breaches: list) -> dict:
    breach_list = ", ".join(breaches[:5]) + ("…" if len(breaches) > 5 else "")
    return _finding(
        "HTTPS", "Email Breach Exposure", "MEDIUM",
        f"{email} was found in {len(breaches)} known data breach(es): {breach_list}.",
        title=f"Business Email Found in Data Breach — {email}",
        category="breach",
        business_risk=(
            "If this address's password was reused anywhere else (a common habit), attackers who buy or "
            "trade breach data can use it to break into email, admin panels, or other accounts tied to "
            "this business. Breached credentials are a leading cause of small-business account takeovers."
        ),
        how_to_fix=(
            f"Change the password for {email} immediately, and anywhere else it was reused. Enable "
            "two-factor authentication on this inbox and any connected accounts (website admin, payment "
            "processor, domain registrar). If this address is on a shared/generic inbox, treat this as a "
            "reminder to rotate its password regularly."
        ),
        urgency="Fix within 1 week",
    )


def _clean_finding(checked: list) -> dict:
    checked_list = ", ".join(checked)
    return _finding(
        "HTTPS", "Email Breach Exposure", "INFO",
        f"Checked {len(checked)} common business email address(es) ({checked_list}) against known data "
        "breaches — none were found.",
        title="No Breach Exposure Found (Common Addresses)",
        category="breach",
        business_risk=(
            "This only covers the common address patterns checked above, not every employee's individual "
            "email — it's a spot-check, not a full audit."
        ),
        how_to_fix="No action required for the addresses checked.",
        urgency="Informational",
    )


def _finding(port, service, risk, reason, title="", version="",
             category="breach", how_to_fix="", urgency="", business_risk="",
             real_world_example=""):
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
        "real_world_example": real_world_example,
        "urgency":    urgency or (
            "Fix immediately" if risk == "HIGH" else
            "Fix within 1 week" if risk == "MEDIUM" else
            "Fix within 1 month"
        ),
    }
