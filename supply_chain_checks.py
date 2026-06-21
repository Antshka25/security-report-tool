"""
supply_chain_checks.py — Detects "watering hole" risk: structural weaknesses
that would let a compromised or tampered third-party script run unmodified in
every visitor's browser (loose CSP script policy, third-party scripts missing
Subresource Integrity, mixed-content script loads, broad third-party footprint).
This is passive detection only — no exploit payloads, just the conditions that
make a watering-hole-style supply-chain attack easier if it ever happens.
Every finding includes a specific how_to_fix instruction.
"""
import re
from urllib.parse import urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
REQUEST_TIMEOUT = 8
THIRD_PARTY_SCRIPT_THRESHOLD = 5

_SCRIPT_TAG_RE = re.compile(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', re.I)
_INTEGRITY_RE  = re.compile(r'\bintegrity=', re.I)


# ── Public entry point ────────────────────────────────────────────────────────

def run_supply_chain_checks(host: str) -> list[dict]:
    if not HAS_HTTPX:
        return []

    headers, html, base_url = {}, "", ""
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=REQUEST_TIMEOUT,
                          follow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in r.headers.items()}
            html = r.text
            base_url = str(r.url)
            break
        except Exception:
            continue
    if not html:
        return []

    findings = []
    try:
        findings.extend(_check_csp_script_policy(headers))
    except Exception:
        pass
    try:
        findings.extend(_check_third_party_scripts(html, base_url))
    except Exception:
        pass

    findings.sort(key=lambda f: RISK_ORDER.get(f.get("risk", "INFO"), 99))
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(port, service, risk, reason, title="", version="",
             category="supply_chain", how_to_fix="", urgency="", business_risk="", cwe="",
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
        # Verified CWE reference ID for this finding type — see web_checks.py's
        # _finding() for the sourcing/verification note.
        "cwe":        cwe,
        # Short illustrative scenario — see web_checks.py's _finding() note.
        "real_world_example": real_world_example,
        "how_to_fix": how_to_fix,
        "urgency":    urgency or (
            "Fix immediately" if risk == "HIGH" else
            "Fix within 1 week" if risk == "MEDIUM" else
            "Fix within 1 month"
        ),
    }


def _check_csp_script_policy(headers: dict) -> list[dict]:
    """If CSP exists, checks whether it actually restricts script execution.
    A missing CSP entirely is already flagged by web_checks.py — this only
    fires when CSP is present but loose enough that a hijacked third-party
    script would still run unmodified (the core watering-hole mechanic)."""
    csp = headers.get("content-security-policy", "")
    if not csp:
        return []

    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split()
        directives[bits[0].lower()] = bits[1:]

    script_src = directives.get("script-src") or directives.get("default-src")
    if script_src is None:
        return [_finding(
            "HTTPS", "Content Security Policy", "MEDIUM",
            "CSP is set but has no script-src or default-src directive — script execution isn't restricted at all",
            "CSP Missing script-src Restriction",
            cwe="CWE-693",
            business_risk=(
                "If an attacker compromises any third-party script you load — a classic 'watering hole' tactic, "
                "where they hijack a widget or library your site trusts instead of attacking you directly — "
                "nothing stops that code from running on every visitor's browser and stealing logins or payment data."
            ),
            real_world_example=(
                "Example: A third-party widget the site trusts and loads on every page gets compromised by "
                "attackers upstream; because nothing restricts which scripts can run, the malicious update "
                "executes on every visitor's browser the next time they load the page."
            ),
            how_to_fix=(
                "Add a script-src directive listing only the exact domains you actually load scripts from, e.g. "
                "\"script-src 'self' https://cdn.yourtrustedvendor.com;\". Avoid 'unsafe-inline' and wildcards."
            )
        )]

    loose_markers = [m for m in ("'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:") if m in script_src]
    if loose_markers:
        return [_finding(
            "HTTPS", "Content Security Policy", "MEDIUM",
            f"CSP script-src allows {', '.join(loose_markers)} — an injected or hijacked script can still run freely",
            "CSP script-src Too Permissive",
            cwe="CWE-693",
            business_risk=(
                "This setting defeats most of the protection CSP is meant to provide. If a third-party script "
                "you rely on is ever compromised — the exact mechanism behind most 'watering hole' attacks — it "
                "will execute without restriction and with no warning."
            ),
            real_world_example=(
                "Example: A vendor's analytics or chat-widget script gets compromised at the source; because "
                "the policy still allows it (or allows inline/eval scripts generally), the malicious code runs "
                "exactly as if it belonged on the site, with no warning to anyone."
            ),
            how_to_fix=(
                "Tighten script-src to an explicit allowlist of trusted domains and drop 'unsafe-inline'/'unsafe-eval'/wildcards. "
                "Move inline scripts to external files or use a nonce/hash. "
                "Test changes with https://csp-evaluator.withgoogle.com before deploying."
            )
        )]
    return []


def _check_third_party_scripts(html: str, base_url: str) -> list[dict]:
    """Flags third-party <script> tags missing Subresource Integrity (SRI) or
    loaded over plain HTTP — both let a compromised or on-path-tampered script
    run unmodified in every visitor's browser."""
    own_host = urlparse(base_url).netloc.lower()

    no_sri, insecure, third_party_domains = [], [], set()

    for m in _SCRIPT_TAG_RE.finditer(html):
        tag, src = m.group(0), m.group(1)
        if src.startswith("//"):
            src = "https:" + src
        if not src.lower().startswith(("http://", "https://")):
            continue  # same-origin relative script, not third-party

        parsed = urlparse(src)
        if parsed.netloc.lower() == own_host:
            continue

        third_party_domains.add(parsed.netloc.lower())
        if not _INTEGRITY_RE.search(tag):
            no_sri.append(parsed.netloc.lower())
        if parsed.scheme == "http":
            insecure.append(parsed.netloc.lower())

    findings = []

    if insecure:
        findings.append(_finding(
            "HTTPS", "Third-Party Script Loading", "HIGH",
            f"Script(s) loaded over plain HTTP from: {', '.join(sorted(set(insecure)))} — "
            "anyone on the network path can swap in malicious code",
            "Insecure (HTTP) Third-Party Script Load",
            cwe="CWE-494",
            business_risk=(
                "Any attacker positioned on the network between a visitor and that script's server — public "
                "wifi, a compromised router, an ISP — can silently replace the script with malicious code, "
                "turning your own page into the delivery point for an attack on your visitors."
            ),
            real_world_example=(
                "Example: A visitor on public wifi loads the page; an attacker on that same network swaps the "
                "plain-HTTP script in transit for a malicious version, and it runs in that visitor's browser as "
                "if it were the real thing."
            ),
            how_to_fix=(
                "Change every third-party script tag to load over https:// instead of http://. Most vendors "
                "support HTTPS — update the <script src> URLs and remove any that don't."
            )
        ))

    if no_sri:
        unique_domains = sorted(set(no_sri))
        findings.append(_finding(
            "HTTPS", "Third-Party Script Loading", "MEDIUM",
            f"{len(unique_domains)} third-party script source(s) loaded without Subresource Integrity (SRI): "
            f"{', '.join(unique_domains)}",
            "Third-Party Scripts Missing Subresource Integrity (SRI)",
            cwe="CWE-353",
            business_risk=(
                "If any of these third-party providers is ever compromised — a real, recurring attack pattern "
                "called a 'watering hole' or supply-chain attack, where attackers hit a widely-trusted vendor "
                "instead of you directly — the malicious code they inject would run on your site with no "
                "verification and no warning to you or your visitors."
            ),
            real_world_example=(
                "Example: A widely-used analytics or widget provider gets compromised (a real, recurring "
                "attack pattern), and because the script loads without integrity verification, the malicious "
                "version executes on every visitor's browser with no warning to you or them."
            ),
            how_to_fix=(
                "Add integrity and crossorigin attributes to each third-party <script> tag, e.g. "
                "<script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>. "
                "Most CDNs (cdnjs, jsdelivr, unpkg) publish the correct hash on their site — copy it directly."
            )
        ))

    if len(third_party_domains) > THIRD_PARTY_SCRIPT_THRESHOLD:
        findings.append(_finding(
            "HTTPS", "Third-Party Script Loading", "LOW",
            f"{len(third_party_domains)} distinct third-party domains serve scripts on this page",
            "Large Third-Party Script Footprint",
            cwe="CWE-829",
            business_risk=(
                "Every additional third-party script is another organization whose security posture your "
                "visitors are implicitly trusting — a wider footprint means a wider attack surface for a "
                "compromise to slip through unnoticed."
            ),
            real_world_example=(
                "Example: One of dozens of third-party scripts a site loads gets compromised at its source; "
                "with so many external providers in the mix, the bad update blends in and can run for weeks "
                "before anyone notices the unusual behavior."
            ),
            how_to_fix=(
                "Audit your third-party scripts and remove any that aren't actually needed. For the rest, apply "
                "SRI hashes and consider self-hosting critical libraries instead of pulling them from external CDNs."
            ),
            urgency="Monitor"
        ))

    return findings