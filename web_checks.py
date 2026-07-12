"""
web_checks.py — SSL/TLS, HTTP security headers, and DNS record checks.
Every finding includes a specific how_to_fix instruction.
"""
import re
import ssl
import socket
import subprocess
import ipaddress
import uuid
import hashlib
from datetime import datetime, timezone

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import dns.resolver as _dns_resolver
    import dns.exception as _dns_exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as _whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# ── Public entry point ────────────────────────────────────────────────────────

def run_web_checks(host: str) -> list[dict]:
    findings = []
    try:
        findings.extend(_check_ssl(host))
    except Exception:
        pass
    try:
        findings.extend(_check_http_headers(host))
    except Exception:
        pass
    try:
        findings.extend(_check_admin_panels(host))
    except Exception:
        pass
    if not _is_ip(host):
        try:
            findings.extend(_check_dns(host))
        except Exception:
            pass
        try:
            findings.extend(_check_domain_expiration(host))
        except Exception:
            pass
        try:
            findings.extend(_check_dkim_key_size(host))
        except Exception:
            pass
        try:
            findings.extend(_check_subdomain_takeover(host))
        except Exception:
            pass
    findings.sort(key=lambda f: RISK_ORDER.get(f.get("risk", "INFO"), 99))
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _finding(port, service, risk, reason, title="", version="",
             category="web", how_to_fix="", urgency="", business_risk="", cwe="",
             real_world_example="", confidence="confirmed"):
    return {
        "port":       port,
        "proto":      "tcp",
        "state":      "checked",
        "service":    service,
        "version":    version,
        "risk":       risk,
        "reason":     reason,
        "what_it_is": reason,
        # Always a distinct, consequence-focused sentence — never just a
        # repeat of "reason". Falls back to "reason" only if a call site
        # genuinely forgot to provide one, so nothing ever ends up blank.
        "business_risk": business_risk or reason,
        "dangerous":  risk in ("HIGH", "MEDIUM"),
        "title":      title or f"{service} Issue",
        "category":   category,
        # Verified CWE (Common Weakness Enumeration) reference ID(s) for this
        # finding type, e.g. "CWE-319". Cross-checked against cwe.mitre.org
        # and/or official OWASP ZAP alert pages — left blank ("") rather than
        # guessed when no real CWE legitimately applies (e.g. WHOIS findings).
        "cwe":        cwe,
        # A short, concrete, illustrative scenario showing how this exact
        # weakness plays out in practice and what it costs the business —
        # generic/hypothetical by design (never a specific named company or
        # incident), left blank if a call site doesn't provide one.
        "real_world_example": real_world_example,
        "how_to_fix": how_to_fix,
        "urgency":    urgency or (
            "Fix immediately" if risk == "HIGH" else
            "Fix within 1 week" if risk == "MEDIUM" else
            "Fix within 1 month"
        ),
        # "confirmed" (default): deterministic checks (missing header, expired
        # cert, etc.) — no ambiguity about whether the condition is real.
        # "probable" / "unverified": used by checks that infer existence from
        # indirect signals (e.g. a bare 401/403 with no content evidence) —
        # see _check_admin_panels(). scanner.py's risk-score weighting reads
        # this to avoid letting an unconfirmed guess score the same as a
        # deterministic finding.
        "confidence": confidence,
    }


# ── SSL / TLS ─────────────────────────────────────────────────────────────────

def _check_ssl(host: str) -> list[dict]:
    findings = []

    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE
    ctx_strict = ssl.create_default_context()

    cert = None
    cipher_info = None
    try:
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx_noverify.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
    except (ConnectionRefusedError, OSError):
        findings.append(_finding(
            "443", "HTTPS", "MEDIUM",
            "No HTTPS detected on port 443 — web traffic is sent in plain text, visible to anyone on the network",
            "No HTTPS / SSL Not Available",
            cwe="CWE-319",
            business_risk=(
                "Customer passwords, contact details, and any form submissions can be read by anyone on the "
                "same network (public wifi, ISPs, etc.), and modern browsers will actively warn visitors that "
                "your site is 'Not Secure' — which drives people away and can hurt your search rankings."
            ),
            real_world_example=(
                "Example: A visitor fills out a contact or login form on this site from a coffee-shop wifi "
                "network. Because the connection isn't encrypted, anyone else on that same network can read "
                "the form data — including a password — as it's sent."
            ),
            how_to_fix=(
                "Install an SSL certificate to enable HTTPS. "
                "If you use a web host (GoDaddy, Bluehost, Cloudflare, etc.), go to their control panel and enable 'Free SSL' or 'Let's Encrypt'. "
                "If you manage your own server, run: sudo certbot --nginx (or --apache) and follow the prompts. It's free."
            )
        ))
        return findings
    except Exception:
        return findings

    # Strict validation (catches self-signed / expired / mismatch)
    try:
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx_strict.wrap_socket(sock, server_hostname=host) as _:
                pass
    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        if "self" in err or "unknown ca" in err:
            findings.append(_finding(
                "SSL", "SSL Certificate", "HIGH",
                "Self-signed SSL certificate — browsers show a 'Your connection is not private' warning to every visitor",
                "Self-Signed SSL Certificate",
                cwe="CWE-295",
                business_risk=(
                    "Most visitors will leave the instant they see that warning, assuming the site is unsafe or "
                    "compromised — costing you sales and leads, especially on any page where customers enter "
                    "personal or payment information."
                ),
                real_world_example=(
                    "Example: A potential customer clicks through to checkout, sees a full-page 'Your "
                    "connection is not private' warning, and closes the tab — assuming the site has been "
                    "compromised rather than realizing it's a certificate misconfiguration."
                ),
                how_to_fix=(
                    "Replace the self-signed cert with a trusted one. "
                    "Use Let's Encrypt (free): run 'sudo certbot --nginx -d yourdomain.com' on your server. "
                    "Or log into your hosting control panel and enable the free SSL option. "
                    "After installing, test at https://www.ssllabs.com/ssltest/"
                )
            ))
        elif "expired" in err or "date" in err:
            findings.append(_finding(
                "SSL", "SSL Certificate", "HIGH",
                "SSL certificate is expired — every visitor sees a browser security warning and many will leave immediately",
                "Expired SSL Certificate",
                cwe="CWE-298",
                business_risk=(
                    "Every visitor right now is seeing a security warning, which most people read as a sign the "
                    "business is unsafe, broken, or even hacked — that's lost sales and damaged trust building up "
                    "for as long as it stays unfixed."
                ),
                real_world_example=(
                    "Example: A returning customer bookmarks the site, comes back a week later, and is greeted "
                    "with a security warning instead of the page they expect — most won't click through, and "
                    "some will assume the business closed or was hacked."
                ),
                how_to_fix=(
                    "Renew your SSL certificate immediately. "
                    "If using Let's Encrypt: run 'sudo certbot renew' on your server. "
                    "If using a paid cert from your hosting provider, log in and click 'Renew SSL'. "
                    "After renewing, restart your web server: 'sudo systemctl restart nginx' (or apache2)."
                )
            ))
        elif "hostname" in err or "mismatch" in err:
            findings.append(_finding(
                "SSL", "SSL Certificate", "HIGH",
                "SSL certificate is for a different domain — visitors get a browser warning saying the site can't be trusted",
                "SSL Certificate Hostname Mismatch",
                cwe="CWE-297",
                business_risk=(
                    "This warning makes your business look unprofessional or compromised, and many visitors "
                    "won't proceed past it — particularly damaging on login or checkout pages where trust matters most."
                ),
                real_world_example=(
                    "Example: A visitor reaches the site via a link that uses the 'www' version of the domain "
                    "while the certificate only covers the bare domain (or vice versa) — triggering a browser "
                    "warning that makes a legitimate business look fraudulent."
                ),
                how_to_fix=(
                    "Get an SSL certificate that matches this exact domain name. "
                    "Check: the cert may be for 'www.yourdomain.com' but you're visiting 'yourdomain.com' (or vice versa). "
                    "Request a new cert that covers both versions, or use a wildcard cert (*.yourdomain.com). "
                    "Let's Encrypt can issue this free: 'certbot --nginx -d yourdomain.com -d www.yourdomain.com'"
                )
            ))
        else:
            findings.append(_finding(
                "SSL", "SSL Certificate", "HIGH",
                f"SSL certificate error ({str(e)[:100]}) — visitors may see browser security warnings",
                "SSL Certificate Error",
                cwe="CWE-295",
                business_risk=(
                    "Unresolved certificate problems quietly erode customer trust and can drive away traffic "
                    "before you even notice a dip in sales or inquiries."
                ),
                real_world_example=(
                    "Example: Depending on the exact error, visitors may see anything from a vague browser "
                    "warning to a hard block — either way, an unresolved certificate problem is one of the few "
                    "security issues a customer can see with their own eyes, and it reads as 'this site isn't safe.'"
                ),
                how_to_fix="Contact your hosting provider or IT team to inspect and replace the SSL certificate. Test at https://www.ssllabs.com/ssltest/"
            ))
    except Exception:
        pass

    # Expiry check
    if cert:
        expires_str = cert.get("notAfter", "")
        try:
            expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(_finding(
                    "SSL", "SSL Certificate", "HIGH",
                    f"SSL certificate expired {abs(days_left)} days ago — visitors see browser security warnings right now",
                    "SSL Certificate Expired",
                    cwe="CWE-298",
                    business_risk=(
                        "Right now, every single visitor sees a 'Not Secure' or 'connection not private' warning — "
                        "many will assume the site is broken or unsafe and leave, which means lost business every "
                        "day this stays unfixed."
                    ),
                    real_world_example=(
                        "Example: A certificate lapses unnoticed over a weekend; by Monday, every visitor — "
                        "including customers checking an order — is blocked by a full-page warning, and support "
                        "starts fielding 'is your site hacked?' messages."
                    ),
                    how_to_fix="Run 'sudo certbot renew' immediately if using Let's Encrypt. Otherwise log into your hosting panel and renew the SSL certificate today."
                ))
            elif days_left < 14:
                findings.append(_finding(
                    "SSL", "SSL Certificate", "HIGH",
                    f"SSL certificate expires in {days_left} days — website will show security errors very soon",
                    f"SSL Expiring in {days_left} Days — Urgent",
                    cwe="CWE-298",
                    business_risk=(
                        "Once this certificate expires, every visitor will hit a security warning and many will "
                        "leave instead of buying or contacting you — handling the renewal now avoids a sudden, "
                        "preventable drop in traffic and trust."
                    ),
                    real_world_example=(
                        "Example: A previous business let a certificate expire without anyone noticing until a "
                        "customer called asking if the site had been hacked — renewing a few days ahead of time "
                        "is the only difference between routine maintenance and an avoidable scare."
                    ),
                    how_to_fix=f"Renew immediately. Let's Encrypt: run 'sudo certbot renew'. Hosting panel: find 'SSL/TLS' settings and click Renew. You have {days_left} days before visitors start seeing warnings."
                ))
            elif days_left < 30:
                findings.append(_finding(
                    "SSL", "SSL Certificate", "MEDIUM",
                    f"SSL certificate expires in {days_left} days — schedule renewal now",
                    f"SSL Expiring Soon ({days_left} Days)",
                    cwe="CWE-298",
                    business_risk=(
                        "Not urgent today, but if this lapses without warning, visitors will suddenly start seeing "
                        "security errors and conversions can drop overnight — renewing now avoids any disruption."
                    ),
                    real_world_example=(
                        "Example: A previous business let a certificate expire without anyone noticing until a "
                        "customer called asking if the site had been hacked — renewing a few days ahead of time "
                        "is the only difference between routine maintenance and an avoidable scare."
                    ),
                    how_to_fix="Renew your SSL certificate this week. Let's Encrypt: 'sudo certbot renew'. For auto-renewal: 'sudo crontab -e' and add '0 12 * * * certbot renew --quiet'"
                ))
            elif days_left < 90:
                findings.append(_finding(
                    "SSL", "SSL Certificate", "LOW",
                    f"SSL certificate expires in {days_left} days",
                    f"SSL Renewal Due in {days_left} Days",
                    cwe="CWE-298",
                    business_risk=(
                        "Plenty of runway here, but a forgotten renewal later means visitors will eventually hit "
                        "security warnings out of nowhere — worth a calendar reminder so it never becomes urgent."
                    ),
                    real_world_example=(
                        "Example: A previous business let a certificate expire without anyone noticing until a "
                        "customer called asking if the site had been hacked — renewing a few days ahead of time "
                        "is the only difference between routine maintenance and an avoidable scare."
                    ),
                    how_to_fix="Add a calendar reminder to renew in 60 days. Or set up auto-renewal: 'sudo systemctl enable certbot.timer' (Let's Encrypt).",
                    urgency="Monitor"
                ))
        except Exception:
            pass

    # Old TLS check
    try:
        ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_old.check_hostname = False
        ctx_old.verify_mode = ssl.CERT_NONE
        # On OpenSSL 3.x, the default security level (SECLEVEL=2, set system-wide
        # in openssl.cnf on most modern Linux distros — confirmed present in this
        # deployment environment) blocks the client from even attempting a
        # TLS1.0/1.1 handshake, regardless of what the remote server would accept.
        # Without lowering it here, wrap_socket() always raises SSLError
        # (NO_PROTOCOLS_AVAILABLE) before any bytes reach the server, silently
        # caught below — meaning this check never fired on modern hosts, even
        # against a server that genuinely still accepts old TLS. Lowering
        # SECLEVEL only on this throwaway probe context (not ctx_noverify/
        # ctx_strict above, which drive the real cert checks) restores the
        # client's ability to attempt the handshake; whether it actually
        # succeeds is still entirely up to the remote server.
        ctx_old.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx_old.minimum_version = ssl.TLSVersion.TLSv1
        ctx_old.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx_old.wrap_socket(sock) as ssock_old:
                ver = ssock_old.version()
                if ver in ("TLSv1", "TLSv1.1"):
                    findings.append(_finding(
                        "SSL", "TLS Version", "MEDIUM",
                        f"Server accepts {ver} which is deprecated and insecure since 2020",
                        f"Outdated TLS Version Accepted ({ver})",
                        cwe="CWE-327",
                        business_risk=(
                            "Security scanners and compliance audits (PCI-DSS, SOC 2, cyber-insurance "
                            "questionnaires, etc.) flag outdated TLS versions as a failing item, and major "
                            "browsers are gradually moving toward blocking these connections entirely."
                        ),
                        real_world_example=(
                            "Example: A compliance auditor or cyber-insurance questionnaire runs an automated "
                            "scan, flags the outdated TLS version as a failed control, and the business has to "
                            "scramble to fix it before a policy renewal or contract can close."
                        ),
                        how_to_fix=(
                            "Disable TLS 1.0 and 1.1 in your web server config. "
                            "For Nginx: add 'ssl_protocols TLSv1.2 TLSv1.3;' to your server block. "
                            "For Apache: set 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' in ssl.conf. "
                            "Then restart the server and verify at https://www.ssllabs.com/ssltest/"
                        )
                    ))
    except (ssl.SSLError, AttributeError, OSError):
        pass
    except Exception:
        pass

    # Weak cipher check — flags whatever cipher the server actually
    # negotiated by default (no forced downgrade), so this only fires
    # when the server itself is willing to use a weak suite.
    if cipher_info:
        cipher_name = cipher_info[0]
        secret_bits = cipher_info[2] if len(cipher_info) > 2 else 256
        weak_markers = ("RC4", "DES", "MD5", "NULL", "EXPORT", "ANON")
        if any(m in cipher_name.upper() for m in weak_markers) or secret_bits < 112:
            findings.append(_finding(
                "SSL", "Cipher Suite", "MEDIUM",
                f"Server negotiated a weak cipher suite ({cipher_name}, {secret_bits}-bit) — traffic encrypted "
                f"this way has a realistic chance of being decrypted by an attacker who intercepts it",
                "Weak SSL/TLS Cipher Suite In Use",
                cwe="CWE-327",
                business_risk=(
                    "An attacker who intercepts network traffic (public wifi, a compromised router, etc.) has a "
                    "real chance of decrypting it with this cipher, exposing whatever customers type — logins, "
                    "payment details, personal information."
                ),
                real_world_example=(
                    "Example: An attacker on the same public wifi as a customer captures the encrypted traffic "
                    "and, because of the weak cipher, is able to decrypt it later — recovering login credentials "
                    "that were assumed to be protected."
                ),
                how_to_fix=(
                    "Disable weak ciphers and only allow modern, strong cipher suites. "
                    "Nginx: set 'ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;' and 'ssl_protocols TLSv1.2 TLSv1.3;' in your server block. "
                    "Apache: set 'SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES' in ssl.conf. "
                    "Then restart the server and verify at https://www.ssllabs.com/ssltest/"
                )
            ))

    return findings


# ── HTTP Security Headers ─────────────────────────────────────────────────────

# Substrings in a cookie's *name* that suggest it's likely session/auth-related
# (not a confirmed fact — we never inspect the cookie's actual value). Used to
# decide whether session-hijacking language is warranted for a given cookie
# finding, or whether to report the gap without assuming high-value contents.
_SESSION_COOKIE_NAME_MARKERS = (
    "session", "sess", "auth", "token", "jwt", "sid", "login",
    "credential", "remember", "logged_in", "user_id", "uid",
)


def _check_http_headers(host: str) -> list[dict]:
    if not HAS_HTTPX:
        return []

    findings = []

    # HTTP → HTTPS redirect
    try:
        r = httpx.get(f"http://{host}", timeout=8, follow_redirects=False)
        loc = r.headers.get("location", "")
        if r.status_code not in (301, 302, 307, 308) or not loc.lower().startswith("https://"):
            findings.append(_finding(
                "HTTP", "HTTPS Redirect", "MEDIUM",
                "Visiting http:// doesn't redirect to https:// — some visitors may use an unencrypted connection without knowing",
                "HTTP Not Redirecting to HTTPS",
                cwe="CWE-319",
                business_risk=(
                    "Anyone who types or clicks an http:// link is sending their activity on your site — "
                    "potentially including form data or passwords — unencrypted, where it can be read by "
                    "anyone on the same public wifi or compromised network."
                ),
                real_world_example=(
                    "Example: A customer types the domain into their browser without 'https://', lands on the "
                    "unencrypted version of the site, and submits a form before ever reaching the secure page — "
                    "sending that data in plain text the whole time."
                ),
                how_to_fix=(
                    "Add a permanent redirect from HTTP to HTTPS. "
                    "Nginx: add 'return 301 https://$host$request_uri;' in your port 80 server block. "
                    "Apache: add 'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' in your .htaccess. "
                    "Cloudflare users: go to SSL/TLS > Edge Certificates > enable 'Always Use HTTPS'."
                )
            ))
    except Exception:
        pass

    # Fetch headers
    headers = {}
    resp = None
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=8, follow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in r.headers.items()}
            resp = r
            break
        except Exception:
            continue

    if not headers:
        return findings

    # HSTS
    if "strict-transport-security" not in headers:
        findings.append(_finding(
            "HTTPS", "HSTS Header", "MEDIUM",
            "Missing Strict-Transport-Security (HSTS) — browsers aren't forced to always use HTTPS, leaving visitors open to downgrade attacks",
            "Missing HSTS Header",
            cwe="CWE-319",
            business_risk=(
                "An attacker on the same network as a visitor (public wifi, a compromised router, etc.) can "
                "trick their browser into using the insecure version of your site and intercept what they type — "
                "raising the odds of stolen logins or payment details."
            ),
            real_world_example=(
                "Example: An attacker on a shared network intercepts a visitor's first request (which defaults "
                "to HTTP) before the redirect happens, and silently serves them a fake version of the page "
                "instead of the real site."
            ),
            how_to_fix=(
                "Add the HSTS header to your web server. "
                "Nginx: add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' in your server block. "
                "Apache: add 'Header always set Strict-Transport-Security \"max-age=31536000\"' in your config. "
                "Cloudflare: SSL/TLS > Edge Certificates > enable HTTP Strict Transport Security."
            )
        ))

    # Clickjacking
    has_frame_csp = "frame-ancestors" in headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and not has_frame_csp:
        findings.append(_finding(
            "HTTPS", "Clickjacking Protection", "MEDIUM",
            "Missing X-Frame-Options — your website can be embedded in an attacker's invisible iframe to trick users into unwanted actions",
            "Missing Clickjacking Protection (X-Frame-Options)",
            cwe="CWE-1021",
            business_risk=(
                "An attacker could trick your customers into clicking hidden buttons — like 'change password' or "
                "'confirm purchase' — without realizing it, potentially leading to account takeovers or "
                "unauthorized actions carried out under your brand's name."
            ),
            real_world_example=(
                "Example: An attacker embeds the site's 'delete account' or 'confirm payment' button inside an "
                "invisible iframe on their own page, disguised under something like a fake 'play video' button — "
                "a visitor's real click triggers the hidden action on your site."
            ),
            how_to_fix=(
                "Add the X-Frame-Options header. "
                "Nginx: 'add_header X-Frame-Options \"SAMEORIGIN\" always;' "
                "Apache: 'Header always set X-Frame-Options SAMEORIGIN' "
                "This tells browsers to only allow your site to be framed by pages on the same domain."
            )
        ))

    # MIME sniffing
    if "x-content-type-options" not in headers:
        findings.append(_finding(
            "HTTPS", "MIME Sniffing", "LOW",
            "Missing X-Content-Type-Options — browsers may guess file types incorrectly, which can enable content injection",
            "Missing MIME Sniffing Protection",
            cwe="CWE-693",
            business_risk=(
                "This is a minor gap on its own, but it slightly raises the odds that a malicious file could be "
                "misread as something else by a visitor's browser, helping a separate attack succeed."
            ),
            real_world_example=(
                "Example: A user-uploaded file intended to be harmless (like an image) is reinterpreted by the "
                "browser as executable script because the server never told it what the file actually was, "
                "letting an unrelated vulnerability turn into a working attack."
            ),
            how_to_fix=(
                "Add: 'add_header X-Content-Type-Options \"nosniff\" always;' (Nginx) "
                "or 'Header always set X-Content-Type-Options nosniff' (Apache). "
                "This is a one-line fix that takes 2 minutes."
            )
        ))

    # CSP
    if "content-security-policy" not in headers:
        findings.append(_finding(
            "HTTPS", "Content Security Policy", "MEDIUM",
            "Missing Content-Security-Policy (CSP) — this site has no CSP defense-in-depth layer, so if any "
            "cross-site scripting weakness exists elsewhere it's easier to exploit; this finding on its own "
            "doesn't mean an XSS vulnerability exists on this site",
            "Missing Content-Security-Policy (CSP)",
            cwe="CWE-693",
            business_risk=(
                "CSP is a defense-in-depth browser control, not evidence of an active vulnerability by itself — "
                "but if an attacker ever manages to slip malicious script onto your site through some other "
                "weakness (e.g. a vulnerable plugin or a comment field), a good CSP is often what stops that "
                "script from running and stealing customer data such as login sessions or payment details. "
                "Without it, that second layer of protection isn't there."
            ),
            real_world_example=(
                "Example: A vulnerable comment form or compromised ad widget lets an attacker inject a script "
                "tag; with a properly scoped CSP in place, the browser would refuse to run it — without CSP, "
                "that same injected script runs freely and can forward a visitor's session cookie to the attacker."
            ),
            how_to_fix=(
                "Add a Content-Security-Policy header, but roll it out carefully — a misconfigured CSP can break "
                "legitimate scripts/styles on the site. Start by deploying it in Report-Only mode first, which "
                "reports violations without blocking anything: "
                "'add_header Content-Security-Policy-Report-Only \"default-src \\'self\\'; script-src \\'self\\'; "
                "object-src \\'none\\'; report-uri /csp-report\";' "
                "Review the reports for a while to catch anything the policy would break, adjust the policy, "
                "then switch the header name to 'Content-Security-Policy' (without '-Report-Only') to start "
                "enforcing it. For WordPress or complex sites, use https://csp-evaluator.withgoogle.com to help "
                "build the policy."
            )
        ))

    # Referrer Policy
    if "referrer-policy" not in headers:
        findings.append(_finding(
            "HTTPS", "Referrer Policy", "LOW",
            "Missing Referrer-Policy — page URLs (which may include sensitive data) are shared with third-party sites your pages link to",
            "Missing Referrer-Policy Header",
            cwe="CWE-16",
            business_risk=(
                "If any of your page addresses contain sensitive details (like a password-reset token or account "
                "ID), that information could leak to outside sites your pages link to — a small but easily "
                "avoidable privacy gap."
            ),
            real_world_example=(
                "Example: A customer clicks an outbound link from a page whose URL happens to include an "
                "account ID or a password-reset token, and that full address — token included — is handed to "
                "the destination site in the Referer header."
            ),
            how_to_fix=(
                "Add: 'add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;' (Nginx) "
                "or 'Header always set Referrer-Policy strict-origin-when-cross-origin' (Apache)."
            )
        ))

    # Permissions Policy
    if "permissions-policy" not in headers:
        findings.append(_finding(
            "HTTPS", "Permissions Policy", "LOW",
            "Missing Permissions-Policy — browser features like camera, microphone, and location aren't restricted for embedded third-party scripts",
            "Missing Permissions-Policy Header",
            cwe="CWE-693",
            business_risk=(
                "If you ever embed third-party ads, widgets, or analytics scripts, they could request a "
                "visitor's camera, microphone, or location without you intending to allow it — an avoidable "
                "privacy risk for your customers."
            ),
            real_world_example=(
                "Example: An embedded ad network's script requests the visitor's location or microphone access "
                "through a permission prompt the site owner never intended to allow, simply because nothing in "
                "the page's headers restricted it."
            ),
            how_to_fix=(
                "Add: 'add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;' "
                "Adjust based on what your site actually uses. This limits what ad/analytics scripts can access."
            ),
            urgency="Monitor"
        ))

    # Server version
    server = headers.get("server", "")
    version_re = re.compile(r'(apache|nginx|iis|php|openssl|lighttpd|tomcat)[/\s][\d.]+', re.I)
    if server and version_re.search(server):
        findings.append(_finding(
            "HTTPS", "Server Version Disclosure", "LOW",
            f"Server header reveals exact software version ({server}) — attackers search vulnerability databases for that version",
            "Server Software Version Exposed",
            version=server,
            cwe="CWE-200",
            business_risk=(
                "Attackers use that exact version number to look up known, public vulnerabilities for that "
                "specific software release — making it easier to plan a targeted attack instead of guessing blind."
            ),
            real_world_example=(
                "Example: An attacker searches a public vulnerability database for the exact server version "
                "shown in the response headers and finds a known, unpatched exploit for it — turning a blind "
                "guess into a targeted attack in seconds."
            ),
            how_to_fix=(
                f"Hide the server version. "
                "Nginx: set 'server_tokens off;' in nginx.conf. "
                "Apache: set 'ServerSignature Off' and 'ServerTokens Prod' in apache2.conf. "
                "IIS: remove via IIS Manager > HTTP Response Headers, or use URLScan."
            )
        ))

    # X-Powered-By
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append(_finding(
            "HTTPS", "Technology Disclosure", "LOW",
            f"X-Powered-By header discloses your tech stack ({powered_by}) — makes targeted attacks easier",
            "Technology Stack Disclosed (X-Powered-By)",
            version=powered_by,
            cwe="CWE-200",
            business_risk=(
                "Knowing your exact tech stack lets an attacker focus their effort on vulnerabilities specific to "
                "that platform, slightly increasing the odds of being targeted compared to a generic, "
                "unidentified site."
            ),
            real_world_example=(
                "Example: Knowing the exact framework and version in use, an attacker skips general "
                "reconnaissance and goes straight to testing the specific, publicly known weaknesses for that "
                "platform."
            ),
            how_to_fix=(
                "Remove the X-Powered-By header. "
                "PHP: set 'expose_php = Off' in php.ini. "
                "Node/Express: 'app.disable(\"x-powered-by\")'. "
                "Nginx: 'more_clear_headers X-Powered-By;' (with headers_more module) or handle in your app."
            )
        ))

    # Cookie security flags — inspect each Set-Cookie line individually
    # since a flattened header dict would silently drop all but the last one.
    if resp is not None:
        try:
            set_cookie_headers = resp.headers.get_list("set-cookie")
        except Exception:
            set_cookie_headers = []
        for cookie_str in set_cookie_headers:
            cookie_name = cookie_str.split("=", 1)[0].strip()
            lower = cookie_str.lower()
            missing = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            # Exact attributes actually observed on this cookie, for a factual
            # record of what was seen rather than just what's missing.
            observed_attrs = [a.strip() for a in cookie_str.split(";")[1:] if a.strip()]
            observed_note = ", ".join(observed_attrs) if observed_attrs else "no additional attributes set"
            if missing:
                # Whether this looks like a session/auth cookie by name is a
                # heuristic, not a confirmed fact — we haven't inspected what
                # value the cookie actually holds. Only use session-hijacking
                # language when the name suggests that's plausible; otherwise
                # report the gap factually without assuming high-value content.
                name_lower = cookie_name.lower()
                looks_sensitive = any(m in name_lower for m in _SESSION_COOKIE_NAME_MARKERS)
                risk = "MEDIUM" if looks_sensitive and ("Secure" in missing or "HttpOnly" in missing) else "LOW"
                # CWE per missing flag — verified against cwe.mitre.org: Secure -> CWE-614,
                # HttpOnly -> CWE-1004, SameSite -> CWE-1275. Built dynamically since a
                # single cookie finding can be missing more than one flag at once.
                _cookie_cwe = {"Secure": "CWE-614", "HttpOnly": "CWE-1004", "SameSite": "CWE-1275"}
                cookie_cwe = ", ".join(_cookie_cwe[m] for m in missing)
                if looks_sensitive:
                    business_risk = (
                        f"This cookie's name suggests it may hold a session or authentication token, though "
                        f"its actual contents weren't inspected. If it does, a cookie missing these flags is "
                        f"easier to steal through cross-site scripting or to intercept over an unencrypted "
                        f"connection — and a stolen session cookie can let an attacker impersonate that logged-in "
                        f"user without ever needing their password."
                    )
                    example = (
                        "Example: A visitor on public wifi has their session cookie intercepted because it "
                        "wasn't marked Secure, or a malicious ad script reads it directly because it wasn't "
                        "marked HttpOnly — either way, the attacker is now logged in as that user without ever "
                        "seeing their password."
                    )
                else:
                    business_risk = (
                        f"This cookie's name doesn't clearly indicate it holds session or authentication data, "
                        f"so the practical impact depends on what value it actually stores — anywhere from "
                        f"low-stakes (a UI preference) to more sensitive (tracking or personalization data). "
                        f"Missing these flags means whatever the cookie does hold is more exposed than it needs "
                        f"to be to interception or script access."
                    )
                    example = (
                        f"Example: whatever value '{cookie_name}' holds could be read by an injected script "
                        f"(no HttpOnly) or intercepted on an unencrypted connection (no Secure) — the actual "
                        f"severity depends on how sensitive that value turns out to be."
                    )
                findings.append(_finding(
                    "HTTPS", "Cookie Security", risk,
                    f"Cookie '{cookie_name}' is missing the {', '.join(missing)} flag(s). Observed attributes: "
                    f"{observed_note}.",
                    f"Insecure Cookie Flags ({cookie_name})",
                    cwe=cookie_cwe,
                    business_risk=business_risk,
                    real_world_example=example,
                    how_to_fix=(
                        f"Add the missing flag(s) when setting this cookie: Secure (only send over HTTPS), "
                        f"HttpOnly (block JavaScript access), SameSite=Lax or Strict (limit cross-site sending). "
                        f"Most frameworks expose this as a one-line config option — e.g. Flask: "
                        f"app.config['SESSION_COOKIE_SECURE']=True, SESSION_COOKIE_HTTPONLY=True, "
                        f"SESSION_COOKIE_SAMESITE='Lax'."
                    )
                ))

    return findings


# ── DNS / Email Security ──────────────────────────────────────────────────────

def _check_dns(host: str) -> list[dict]:
    if HAS_DNS:
        return _check_dns_dnspython(host)
    return _check_dns_nslookup(host)


def _check_dns_dnspython(host: str) -> list[dict]:
    findings = []

    # SPF
    spf_found = False
    try:
        answers = _dns_resolver.resolve(host, "TXT", lifetime=8)
        for rdata in answers:
            txt = "".join(
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            if txt.lower().startswith("v=spf1"):
                spf_found = True
                if "+all" in txt:
                    findings.append(_finding(
                        "DNS", "SPF Record", "HIGH",
                        "SPF record uses '+all' — the SPF check passes for any sending server, so this record "
                        "provides no envelope-sender authorization at all",
                        "SPF Record Too Permissive (+all)",
                        category="dns",
                        cwe="CWE-290",
                        business_risk=(
                            "SPF only authorizes which mail servers may use your domain in the invisible SMTP "
                            "'envelope sender' — with '+all', that check is disabled entirely, so any server can "
                            "pass it. On top of that, SPF alone (even set to '-all') never stops the visible "
                            "'From:' address a recipient actually sees from being spoofed — that protection "
                            "comes from DMARC enforcing alignment between SPF/DKIM and the From header, so this "
                            "gap matters even more if DMARC isn't set to enforce."
                        ),
                        real_world_example=(
                            "Example: A scammer sends an invoice-fraud email that appears to come from "
                            "'billing@yourdomain.com,' asking a customer to wire payment to a new account — "
                            "because SPF does nothing to stop it, the email sails through with no warning."
                        ),
                        how_to_fix=(
                            "Change '+all' to '-all' (hard fail) in your SPF record in your DNS settings. "
                            "Log into your domain registrar (GoDaddy, Namecheap, etc.), go to DNS settings, "
                            "find the TXT record starting with 'v=spf1', and change '+all' to '-all'. "
                            "Example: 'v=spf1 include:_spf.google.com -all' — but list every service that "
                            "legitimately sends mail for this domain (email provider, helpdesk, marketing tools, "
                            "etc.) in the 'include:' entries first, or their mail will start failing SPF too. "
                            "Also add a DMARC record (see below) so From-header spoofing is covered, not just "
                            "the envelope sender."
                        )
                    ))
                elif "?all" in txt:
                    findings.append(_finding(
                        "DNS", "SPF Record", "MEDIUM",
                        "SPF record uses '?all' (neutral) — spoofed emails aren't blocked or flagged",
                        "SPF Record Neutral — Not Enforced",
                        category="dns",
                        cwe="CWE-290",
                        business_risk=(
                            "Phishing emails impersonating your business can land in customers' inboxes without "
                            "any warning label, raising the chance someone falls for a scam and blames your "
                            "company for it."
                        ),
                        real_world_example=(
                            "Example: A phishing email spoofing the company's domain lands in a customer's "
                            "inbox with no spam warning, because the SPF record exists but is set to a value "
                            "that doesn't actually instruct mail servers to reject or flag forgeries."
                        ),
                        how_to_fix="Change '?all' to '~all' (soft fail) or '-all' (hard fail) in your DNS TXT record. Use '-all' for strongest protection."
                    ))
                break
    except Exception:
        pass

    if not spf_found:
        findings.append(_finding(
            "DNS", "SPF Record", "HIGH",
            "No SPF record — there's no DNS-level list of which mail servers are authorized to send using "
            "this domain's envelope sender, so any server can pass an SPF check for your domain",
            "Missing SPF Record — Email Spoofing Possible",
            category="dns",
            cwe="CWE-290",
            business_risk=(
                "Without SPF, nothing tells receiving mail servers which senders are legitimate for this "
                "domain's SMTP envelope, making it easier for forged mail to get through — and easier for your "
                "own legitimate mail to be misjudged as spam. Note that SPF on its own, even correctly "
                "configured, doesn't stop the visible 'From:' address a recipient sees from being spoofed — "
                "that requires DMARC (see below) to enforce alignment between SPF/DKIM and the From header."
            ),
            real_world_example=(
                "Example: A customer receives an email that looks exactly like it's from the business — same "
                "display name, same domain — asking them to 'confirm' a payment or click a link, with nothing "
                "in DNS to stop the forgery or warn the recipient."
            ),
            how_to_fix=(
                "Add an SPF TXT record to your DNS listing every service that actually sends mail for this "
                "domain — leaving one out will cause its mail to fail SPF and possibly get rejected. "
                "Log into your domain registrar, go to DNS, add a TXT record for '@' with a value matching "
                "your provider: Google Workspace: 'v=spf1 include:_spf.google.com -all' | Microsoft 365: "
                "'v=spf1 include:spf.protection.outlook.com -all'. If you use additional senders (helpdesk, "
                "marketing platform, invoicing tool, etc.), add each as its own 'include:' entry in the same "
                "record — a domain can only have one SPF TXT record, so don't create a second one. "
                "Use https://mxtoolbox.com/spf.aspx to verify, then add a DMARC record too so the visible "
                "From address is covered as well."
            )
        ))

    # DMARC
    dmarc_found = False
    try:
        answers = _dns_resolver.resolve(f"_dmarc.{host}", "TXT", lifetime=8)
        for rdata in answers:
            txt = "".join(
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            if "v=dmarc1" in txt.lower():
                dmarc_found = True
                if "p=none" in txt.lower():
                    has_rua = "rua=" in txt.lower()
                    findings.append(_finding(
                        "DNS", "DMARC Policy", "MEDIUM",
                        "DMARC is set to monitor-only (p=none) — phishing emails pretending to be you aren't blocked, just reported",
                        "DMARC Monitor-Only (p=none) — Not Enforced",
                        category="dns",
                        cwe="CWE-290",
                        business_risk=(
                            "Phishing emails pretending to be your business can still reach customers' inboxes "
                            "today — you'll get aggregate reports about it after the fact (if 'rua=' reporting "
                            "is configured), but nothing actually stops the fraudulent emails from being "
                            "delivered right now. p=none is a legitimate and recommended first step — it lets "
                            "you review reports and confirm all your real mail sources pass DMARC alignment "
                            "(the From-header domain matching either an aligned SPF pass or an aligned DKIM "
                            "signature) before you start blocking anything — the risk is only in staying at "
                            "p=none indefinitely instead of using it as a monitoring phase."
                        ),
                        real_world_example=(
                            "Example: Forged emails impersonating the business keep reaching customers' "
                            "inboxes; DMARC reports quietly pile up showing exactly that it's happening, but "
                            "because the policy is monitor-only, nothing actually blocks a single one of them."
                        ),
                        how_to_fix=(
                            "Review DMARC aggregate reports (they require 'rua=mailto:...' in the record"
                            + ("" if has_rua else " — this record doesn't appear to have one, add it first")
                            + ") for a few weeks to confirm every legitimate mail source for this domain is "
                            "passing DMARC alignment. Once confirmed, move to 'p=quarantine' (suspicious mail "
                            "goes to spam) and monitor again before finally moving to 'p=reject' (spoofed mail "
                            "is rejected outright). Don't jump straight to p=reject — if a legitimate sender "
                            "was missed, that skips straight to real mail being dropped. "
                            "Example: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'"
                        )
                    ))
                break
    except Exception:
        pass

    if not dmarc_found:
        findings.append(_finding(
            "DNS", "DMARC Record", "HIGH",
            "No DMARC record — your domain has zero email authentication enforcement, making it trivial to impersonate your business",
            "Missing DMARC Record — Email Impersonation Risk",
            category="dns",
            cwe="CWE-290",
            business_risk=(
                "This makes it significantly easier for scammers to send convincing fake emails 'from' your "
                "business — a common tactic in invoice fraud and phishing — which can directly cost your "
                "customers money and damage trust in your brand."
            ),
            real_world_example=(
                "Example: A scammer sends an invoice-fraud email that appears to come straight from the "
                "business's own domain; with no DMARC record in place, nothing tells the recipient's mail "
                "provider the message is forged, so it lands in the inbox looking completely legitimate."
            ),
            how_to_fix=(
                "Add a DMARC TXT record to your DNS. Go to your domain registrar's DNS settings, "
                "add a TXT record for '_dmarc' (not '@') with value: "
                "'v=DMARC1; p=none; rua=mailto:youremail@yourdomain.com' "
                "Start at p=none — this only turns on reporting, nothing is blocked yet. Review the aggregate "
                "reports for a few weeks to confirm every legitimate mail source for this domain (email "
                "provider, helpdesk, marketing tools, etc.) is passing DMARC alignment, then move to "
                "p=quarantine, and finally p=reject once you're confident nothing legitimate will be caught. "
                "Verify at https://mxtoolbox.com/dmarc.aspx"
            )
        ))

    # DKIM
    dkim_found = False
    for selector in ("default", "google", "mail", "dkim", "k1", "selector1", "selector2",
                      "resend", "s1", "s2", "zoho", "mandrill"):
        try:
            _dns_resolver.resolve(f"{selector}._domainkey.{host}", "TXT", lifetime=4)
            dkim_found = True
            break
        except Exception:
            continue

    if not dkim_found:
        findings.append(_finding(
            "DNS", "DKIM Record", "MEDIUM",
            "No DKIM record found under common selector names — this does not confirm DKIM is unconfigured, "
            "only that it wasn't found under any of the selector names checked; many providers use a custom "
            "or provider-specific selector this check can't guess",
            "DKIM Not Detected Under Common Selectors",
            category="dns",
            cwe="CWE-290",
            confidence="probable",
            business_risk=(
                "If DKIM genuinely isn't configured, email providers increasingly use it as a trust signal, "
                "and its absence can make legitimate emails more likely to be flagged as suspicious or land in "
                "spam. But this check only queries a fixed list of common selector names (default, google, "
                "mail, etc.) — many providers assign a random or account-specific selector, so this finding "
                "should be treated as 'couldn't confirm DKIM,' not 'DKIM is definitely missing.'"
            ),
            real_world_example=(
                "Example: A legitimate invoice email from the business gets flagged as suspicious or dropped "
                "into spam by the recipient's mail provider, simply because there's no DKIM signature to prove "
                "the message wasn't altered or forged in transit — this only actually happens if DKIM is truly "
                "unconfigured, which this check alone can't confirm."
            ),
            how_to_fix=(
                "First confirm whether DKIM is actually configured: check your email provider's admin console "
                "(Google Workspace: Admin console > Apps > Gmail > Authenticate email; Microsoft 365: Defender "
                "> Email authentication > DKIM) for the exact selector name in use, since it's often not one of "
                "the common defaults this scan checks. If it turns out DKIM genuinely isn't enabled, turn it on "
                "there and add the resulting TXT record to DNS. If you're not sure how to check, share the "
                "selector name your provider gives you and this can be verified directly."
            )
        ))

    return findings


def _check_dns_nslookup(host: str) -> list[dict]:
    """Fallback when dnspython not installed — uses nslookup subprocess."""
    findings = []

    def _lookup(query_host):
        try:
            r = subprocess.run(["nslookup", "-type=TXT", query_host],
                               capture_output=True, text=True, timeout=8)
            return r.stdout.lower()
        except Exception:
            return ""

    if "v=spf1" not in _lookup(host):
        findings.append(_finding(
            "DNS", "SPF Record", "HIGH",
            "No SPF record — anyone can send emails pretending to be from your domain",
            "Missing SPF Record — Email Spoofing Possible",
            category="dns",
            cwe="CWE-290",
            business_risk=(
                "Scammers can use this gap to send convincing fake emails that appear to come from your "
                "business, putting your customers at risk and potentially damaging your reputation."
            ),
            real_world_example=(
                "Example: A scammer sends a payment-redirect email that looks like it came straight from the "
                "business's own domain; with no SPF record to fail the check, the email passes through to "
                "customers' inboxes unflagged."
            ),
            how_to_fix=(
                "Add a TXT record to your DNS for '@' with value: 'v=spf1 include:_spf.google.com -all' "
                "(adjust for your email provider). Verify at https://mxtoolbox.com/spf.aspx"
            )
        ))

    if "v=dmarc1" not in _lookup(f"_dmarc.{host}"):
        findings.append(_finding(
            "DNS", "DMARC Record", "HIGH",
            "No DMARC record — attackers can impersonate your business in emails",
            "Missing DMARC Record — Email Impersonation Risk",
            category="dns",
            cwe="CWE-290",
            business_risk=(
                "This makes email scams impersonating your business easier to pull off, which can cost "
                "customers money and erode trust in your brand."
            ),
            real_world_example=(
                "Example: A fraudulent email impersonating the business reaches a customer's inbox with no "
                "warning label, because nothing in DNS instructs mail providers to question or block messages "
                "claiming to be from this domain."
            ),
            how_to_fix=(
                "Add a TXT record for '_dmarc' with value: 'v=DMARC1; p=quarantine; rua=mailto:you@yourdomain.com' "
                "Verify at https://mxtoolbox.com/dmarc.aspx"
            )
        ))

    return findings


# ── WHOIS / Domain Registration Expiration ────────────────────────────────────

def _check_domain_expiration(host: str) -> list[dict]:
    if not HAS_WHOIS:
        return []

    findings = []
    try:
        w = _whois.whois(host, timeout=10)
    except Exception:
        return findings

    expires = w.get("expiration_date") if isinstance(w, dict) else getattr(w, "expiration_date", None)
    if isinstance(expires, list):
        expires = expires[0] if expires else None
    if not isinstance(expires, datetime):
        return findings
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    days_left = (expires - datetime.now(timezone.utc)).days
    registrar = w.get("registrar") if isinstance(w, dict) else getattr(w, "registrar", None)
    registrar_note = f" (registrar: {registrar})" if registrar else ""

    if days_left < 0:
        findings.append(_finding(
            "WHOIS", "Domain Registration", "HIGH",
            f"Domain registration expired {abs(days_left)} days ago{registrar_note} — it can be suspended or released to the public at any time",
            "Domain Registration Expired",
            category="dns",
            business_risk=(
                "Once a domain lapses, the website and every @yourdomain.com email address can go down without "
                "warning, and after a short grace period anyone — including squatters or competitors — can "
                "register it out from under you."
            ),
            real_world_example=(
                "Example: A business misses a renewal notice buried in spam; the domain lapses, the website and "
                "every @company.com email address go dark without warning, and a squatter registers it the "
                "moment the grace period ends."
            ),
            how_to_fix=(
                "Log into your domain registrar (GoDaddy, Namecheap, Google Domains, etc.) and renew the domain "
                "immediately, before it enters redemption/auction status, which can cost far more to recover."
            )
        ))
    elif days_left < 30:
        findings.append(_finding(
            "WHOIS", "Domain Registration", "HIGH",
            f"Domain registration expires in {days_left} days{registrar_note} — losing it would take down the website and all email",
            f"Domain Expiring in {days_left} Days — Urgent",
            category="dns",
            business_risk=(
                "If this renewal is missed, the website goes offline and every email address on this domain "
                "stops working — including invoices, password resets, and customer replies — until it's "
                "renewed or, worst case, recovered from whoever registers it after it lapses."
            ),
            real_world_example=(
                "Example: The card on file for auto-renew has expired without anyone noticing; unless someone "
                "renews manually in the next few days, the site and every email address on the domain go dark "
                "with no advance warning to customers."
            ),
            how_to_fix=(
                f"Renew the domain now at your registrar — {days_left} days left. Turn on auto-renew and confirm "
                "the card on file and contact email are current so this never happens silently again."
            )
        ))
    elif days_left < 60:
        findings.append(_finding(
            "WHOIS", "Domain Registration", "MEDIUM",
            f"Domain registration expires in {days_left} days{registrar_note}",
            f"Domain Renewal Due in {days_left} Days",
            category="dns",
            business_risk=(
                "Not urgent yet, but a missed renewal takes the site and all email on this domain offline — "
                "worth confirming auto-renew is on now rather than relying on remembering later."
            ),
            real_world_example=(
                "Example: A similar business assumed auto-renew was on, it wasn't, and the domain quietly "
                "lapsed — a five-minute check now is the only thing standing between routine upkeep and that "
                "same scramble."
            ),
            how_to_fix="Confirm auto-renew is enabled at your registrar, or renew manually in the next few weeks.",
            urgency="Monitor"
        ))
    elif days_left < 120:
        findings.append(_finding(
            "WHOIS", "Domain Registration", "LOW",
            f"Domain registration expires in {days_left} days{registrar_note}",
            f"Domain Renewal Due in {days_left} Days",
            category="dns",
            business_risk=(
                "Plenty of runway, but this is the kind of date that's easy to forget — a calendar reminder or "
                "auto-renew now avoids any risk of losing the domain later."
            ),
            real_world_example=(
                "Example: Renewal dates like this are exactly the kind of thing that get forgotten between "
                "other priorities — a quick calendar reminder now costs nothing and rules out a future scramble."
            ),
            how_to_fix="Turn on auto-renew at your registrar, or add a calendar reminder for the renewal date.",
            urgency="Monitor"
        ))

    return findings


# ── Open admin / sensitive panel probing ──────────────────────────────────────

# Paths to probe, in order. Tuples of (path, title, severity, body_keywords, kind).
# body_keywords: if any appear in the response body it's more likely a real panel;
# empty list means a 200 status alone is sufficient (e.g. .git/HEAD has a
# distinctive body regardless of keywords).
# kind controls which explanatory narrative gets used below — these paths are
# NOT all the same type of exposure (a login-brute-forceable admin panel is a
# very different risk from a Git-metadata leak or a diagnostic info page), so
# a single generic "admin panel" business_risk/how_to_fix was wrong for the
# non-admin-panel entries. See _check_admin_panels()'s _NARRATIVES below.
_ADMIN_PATHS = [
    ("/.git/HEAD",          "Exposed .git Directory",          "HIGH",
     ["ref: refs/heads/"], "git"),
    ("/wp-admin/",          "WordPress Admin Panel Exposed",    "HIGH",
     ["wordpress", "wp-login", "log in", "username", "password"], "admin_panel"),
    ("/phpmyadmin/",        "phpMyAdmin Exposed",               "HIGH",
     ["phpmyadmin", "mysql", "sql", "database"], "admin_panel"),
    ("/phpmyadmin",         "phpMyAdmin Exposed",               "HIGH",
     ["phpmyadmin", "mysql", "sql", "database"], "admin_panel"),
    ("/admin/",             "Admin Panel Exposed",              "HIGH",
     ["login", "admin", "dashboard", "username", "password", "sign in"], "admin_panel"),
    ("/admin",              "Admin Panel Exposed",              "HIGH",
     ["login", "admin", "dashboard", "username", "password", "sign in"], "admin_panel"),
    ("/administrator/",     "Admin Panel Exposed",              "HIGH",
     ["login", "admin", "dashboard", "username", "password"], "admin_panel"),
    ("/admin.php",          "Admin Panel Exposed",              "HIGH",
     ["login", "admin", "dashboard", "username", "password"], "admin_panel"),
    ("/login",              "Admin Login Page Exposed",         "MEDIUM",
     ["admin", "dashboard", "control panel", "management"], "admin_panel"),
    ("/dashboard",          "Admin Dashboard Exposed",          "HIGH",
     ["admin", "dashboard", "control panel", "users", "settings"], "admin_panel"),
    ("/cpanel/",            "cPanel Exposed",                   "HIGH",
     ["cpanel", "webmail", "hosting", "control panel"], "admin_panel"),
    ("/server-status",      "Apache Server Status Exposed",     "HIGH",
     ["apache", "server status", "requests currently being processed"], "diagnostic"),
    ("/server-info",        "Apache Server Info Exposed",       "MEDIUM",
     ["apache", "server information", "module"], "diagnostic"),
    ("/elmah.axd",          "ELMAH Error Log Exposed",          "HIGH",
     ["elmah", "error log", "exception"], "diagnostic"),
]

# Per-kind explanatory text. "admin_panel" keeps the original brute-force/
# login framing (accurate for those paths); "git" and "diagnostic" get their
# own accurate narratives instead of inheriting admin-panel language that
# doesn't apply to them (e.g. .git/HEAD isn't a login page to brute-force).
_ADMIN_NARRATIVES = {
    "admin_panel": {
        "reason_suffix": "this exposes administration functionality to anyone on the internet",
        "cwe": "CWE-284",
        "business_risk": (
            "Publicly reachable admin panels are a primary target for automated attacks. "
            "An attacker who can reach {path} can attempt brute-force login, exploit known "
            "vulnerabilities in the admin software, or leverage it as a stepping stone to full "
            "server compromise — without needing any insider knowledge of the site."
        ),
        "real_world_example": (
            "Example: Automated bots constantly scan the internet for paths like {path}. A business "
            "that left a default admin URL accessible was compromised when a bot found it, brute-forced "
            "a weak password in minutes, and installed backdoor malware — all without any human attacker "
            "being involved."
        ),
        "how_to_fix": (
            "Restrict access to {path} by IP allowlist, move it to a non-standard path, or disable it "
            "if not needed. Nginx: 'location ^~ {path} {{ allow YOUR_IP; deny all; }}'. "
            "Also ensure strong, unique credentials are set for any admin accounts, and enable "
            "multi-factor authentication where supported."
        ),
    },
    "git": {
        "reason_suffix": "this exposes the site's Git repository metadata, not an admin login",
        "cwe": "CWE-527",
        "business_risk": (
            "This is not a login page to brute-force — a publicly accessible {path} can let an attacker "
            "reconstruct this site's Git repository: full source code, configuration files, commit "
            "history, internal file paths, and any secrets that were ever committed, even ones later "
            "removed from the latest version but never rotated."
        ),
        "real_world_example": (
            "Example: A free, widely available tool rebuilds this site's entire source code and commit "
            "history from the exposed .git folder within minutes — sometimes turning up a hardcoded "
            "API key or password that was deleted from the current code but never actually rotated."
        ),
        "how_to_fix": (
            "Block public access to {path} entirely — it should never be servable. Nginx: "
            "'location ~ /\\.git {{ deny all; }}'. Apache: '<DirectoryMatch \"\\.git\"> Require all "
            "denied </DirectoryMatch>'. Better yet, don't deploy the .git folder to the live server at "
            "all. If any credentials were ever committed to this repo, rotate them — treat them as compromised."
        ),
    },
    "diagnostic": {
        "reason_suffix": "this exposes internal server diagnostic information, not a login panel",
        "cwe": "CWE-200",
        "business_risk": (
            "This page reveals internal details about the server's configuration, active connections, "
            "or recent errors — not something the general public should be able to see, and useful "
            "reconnaissance an attacker can use to plan a more targeted attack elsewhere on the site."
        ),
        "real_world_example": (
            "Example: An attacker reviews this page to learn internal server details, request patterns, "
            "or recent error messages, then uses that information to plan a more targeted attack "
            "elsewhere on the site instead of guessing blind."
        ),
        "how_to_fix": (
            "Restrict access to {path} by IP allowlist, or disable it entirely if not needed. Nginx: "
            "'location ^~ {path} {{ allow YOUR_IP; deny all; }}'. Apache ('server-status'/'server-info'): "
            "add 'Require ip YOUR_IP' inside the relevant <Location> block, or remove the module if unused."
        ),
    },
}

_ADMIN_DEDUP: set = set()  # avoid duplicate titles within a single scan

# How many distinct random-path control probes to baseline against. A single
# control path only proves "this one random path behaves like X" — several
# samples make it much harder for one coincidental match (e.g. a CDN cache
# hit) to slip a false positive through.
_ADMIN_BASELINE_SAMPLES = 3


def _title_of(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return (m.group(1).strip() if m else "")[:120]


def _body_hash(text: str) -> str:
    normalized = re.sub(r"\s+", " ", (text or "")[:3000]).strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _response_signature(status: int, body: str, headers) -> dict:
    return {
        "status":     status,
        "length":     len(body or ""),
        "title":      _title_of(body),
        "hash":       _body_hash(body),
        "server":     (headers.get("server") or "").lower(),
        "www_auth":   (headers.get("www-authenticate") or "").lower(),
        "redirect":   (headers.get("location") or "").lower(),
    }


def _build_admin_baseline(host: str) -> list:
    """Probe several definitely-nonexistent random paths and record a rich
    signature for each (status, body hash, length, title, server header,
    WWW-Authenticate realm, redirect target). Comparing a real candidate
    against several of these — not just one — is what lets us tell "this
    WAF/proxy blocks everything identically" apart from "this specific path
    is handled differently," across every status code, not just 401/403."""
    baseline = []
    for _ in range(_ADMIN_BASELINE_SAMPLES):
        control_path = f"/rv-admin-control-{uuid.uuid4().hex[:10]}"
        try:
            r = httpx.get(f"https://{host}{control_path}", timeout=8,
                          follow_redirects=False, verify=False)
            baseline.append(_response_signature(r.status_code, r.text[:3000], r.headers))
        except Exception:
            continue
    return baseline


def _matches_admin_baseline(baseline: list, sig: dict) -> bool:
    """True if `sig` looks like the same generic response as one of the
    random-path control probes — meaning it's evidence about the site's
    general behavior (WAF, catch-all router, uniform block page), not
    evidence that this specific candidate path exists or is distinct."""
    for b in baseline:
        if b["status"] != sig["status"]:
            continue
        if b["hash"] == sig["hash"]:
            return True
        if abs(b["length"] - sig["length"]) <= 40 and b["title"] == sig["title"]:
            return True
        if (b["server"] and b["server"] == sig["server"]
                and b["www_auth"] == sig["www_auth"]
                and b["redirect"] == sig["redirect"]
                and abs(b["length"] - sig["length"]) <= 40):
            return True
    return False


def _check_admin_panels(host: str) -> list[dict]:
    if not HAS_HTTPX:
        return []

    findings = []
    seen_titles: set = set()

    # Fetch the homepage body once so we can detect catch-all 200 responses.
    homepage_text = ""
    try:
        for scheme in ("https", "http"):
            r = httpx.get(f"{scheme}://{host}", timeout=8,
                          follow_redirects=True, verify=False)
            if r.status_code == 200:
                homepage_text = r.text[:4000].lower()
                break
    except Exception:
        pass

    baseline = _build_admin_baseline(host)

    for path, title, risk, keywords, kind in _ADMIN_PATHS:
        if title in seen_titles:
            continue
        try:
            url = f"https://{host}{path}"
            r = httpx.get(url, timeout=8, follow_redirects=False, verify=False)

            if r.status_code not in (200, 401, 403):
                continue

            body = r.text[:3000]
            body_lower = body.lower()
            sig = _response_signature(r.status_code, body, r.headers)

            # This is the core anti-false-positive check, and it now applies
            # to every status code, not just 401/403: if this response is
            # indistinguishable (status + body hash/length+title, or
            # server+auth-realm+redirect fingerprint) from what several
            # definitely-nonexistent random paths returned, it's evidence
            # about the site in general, not about this path specifically —
            # never confirm a finding on that basis alone.
            if _matches_admin_baseline(baseline, sig):
                continue

            keyword_hit = bool(keywords) and any(kw in body_lower for kw in keywords)

            if r.status_code == 200:
                if keywords and not keyword_hit:
                    continue
                # Skip if the body is basically identical to the homepage (catch-all route)
                if homepage_text and len(body_lower) > 100:
                    overlap = sum(1 for kw in body_lower.split()[:80] if kw in homepage_text)
                    if overlap > 60:
                        continue
                # 200 + distinct-from-baseline + technology-specific content
                # match (or no keywords required for this path, e.g. .git/HEAD's
                # own distinctive body) — this is real, demonstrated evidence.
                confidence = "confirmed"
                access_restricted = False
            else:
                # 401/403, and NOT explained by the site's general baseline
                # behavior — genuinely distinct handling for this path. That's
                # real signal something is there, but a 401/403 body is
                # usually near-empty, so technology-specific content evidence
                # (the actual bar for "confirmed") is rarely available here.
                # Per the false positives already found for /.git/HEAD,
                # /wp-admin/, /phpmyadmin/, /admin.php: a bare distinct 401/403
                # alone is never enough to call this "publicly exposed
                # administration functionality" — that requires content
                # evidence keyword_hit gives us. Without it, this is
                # "probable" (something's there, restricted) not "confirmed".
                confidence = "confirmed" if keyword_hit else "probable"
                access_restricted = True

            seen_titles.add(title)

            narrative = _ADMIN_NARRATIVES.get(kind, _ADMIN_NARRATIVES["admin_panel"])

            if confidence == "confirmed":
                status_note = ("is accessible without authentication" if not access_restricted else
                               "returns a restricted-access response (401/403), and its content "
                               "matches known indicators for this resource, confirming what it is")
                effective_risk = risk
                effective_title = title
            else:
                status_note = ("returns a restricted-access response (401/403) that is genuinely "
                               "distinct from how this site handles random nonexistent paths — "
                               "this confirms *something* is being specially handled at this path, "
                               "but the response contains no content confirming what it actually is")
                # Never assign HIGH severity to an unconfirmed guess — cap it
                # one tier down so severity reflects actual demonstrated impact.
                effective_risk = "MEDIUM" if risk == "HIGH" else "LOW"
                effective_title = f"{title} (Unconfirmed)"

            findings.append(_finding(
                "HTTPS", title, effective_risk,
                f"The path {path} {status_note} — {narrative['reason_suffix']}",
                effective_title,
                category="web",
                cwe=narrative["cwe"],
                business_risk=narrative["business_risk"].format(path=path),
                real_world_example=narrative["real_world_example"].format(path=path),
                how_to_fix=narrative["how_to_fix"].format(path=path),
                confidence=confidence,
            ))
        except Exception:
            continue

    return findings


# ── DKIM key size check ───────────────────────────────────────────────────────

_DKIM_SELECTORS = (
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "zoho", "mandrill",
    "resend", "email", "smtp",
)


def _check_dkim_key_size(host: str) -> list[dict]:
    """Resolve existing DKIM records and flag undersized keys (< 2048 bits)."""
    if not HAS_DNS:
        return []

    import base64 as _b64

    findings = []

    for selector in _DKIM_SELECTORS:
        try:
            answers = _dns_resolver.resolve(
                f"{selector}._domainkey.{host}", "TXT", lifetime=4)
        except Exception:
            continue

        # Found a DKIM record — parse the p= field (public key in base64 DER)
        for rdata in answers:
            txt = "".join(
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            # p= is the base64-encoded public key (SubjectPublicKeyInfo DER for RSA)
            m = re.search(r"p=([A-Za-z0-9+/=]+)", txt)
            if not m:
                continue
            try:
                key_bytes = _b64.b64decode(m.group(1))
            except Exception:
                continue

            # Rough RSA key-size estimation from SPKI DER byte length:
            #   512-bit key  → ~74  bytes
            #   1024-bit key → ~162 bytes
            #   2048-bit key → ~294 bytes
            key_len = len(key_bytes)
            if key_len < 100:
                est_bits = 512
                risk = "HIGH"
                urgency = "Fix immediately"
                reason = (
                    f"DKIM key for selector '{selector}' appears to be approximately {est_bits} bits — "
                    f"this key size is cryptographically broken and can be factored by attackers, "
                    f"allowing them to forge valid DKIM signatures on emails impersonating your domain."
                )
                fix = (
                    f"Replace the DKIM key for selector '{selector}' with a 2048-bit RSA key immediately. "
                    f"Generate a new key through your email provider (Google Workspace: Admin > Gmail > "
                    f"Authenticate email; Microsoft 365: Defender > Email auth > DKIM), update the DNS TXT "
                    f"record, and delete the old weak key."
                )
            elif key_len < 210:
                est_bits = 1024
                risk = "MEDIUM"
                urgency = "Fix within 1 week"
                reason = (
                    f"DKIM key for selector '{selector}' appears to be approximately {est_bits} bits — "
                    f"1024-bit RSA keys are considered weak by modern standards and NIST has deprecated them. "
                    f"A well-resourced attacker could factor this key, breaking your email authentication."
                )
                fix = (
                    f"Upgrade the DKIM key for selector '{selector}' to 2048 bits. Generate a new key "
                    f"through your email provider, update the DNS TXT record to the new public key, "
                    f"and retire the old 1024-bit key."
                )
            else:
                # Key size is fine — no finding
                continue

            findings.append(_finding(
                "DNS", "DKIM Key Strength", risk,
                reason,
                f"Weak DKIM Key — {est_bits}-bit RSA (selector: {selector})",
                category="dns",
                cwe="CWE-326",
                business_risk=(
                    "A forged DKIM signature lets an attacker send phishing or fraud emails that "
                    "cryptographically appear to come from your domain — bypassing email filters that "
                    "rely on DKIM as a trust signal, and making impersonation emails indistinguishable "
                    "from your real ones."
                ),
                real_world_example=(
                    "Example: A security researcher demonstrated in a published study that 512-bit DKIM keys "
                    "could be factored in under 72 hours using cloud computing resources costing less than "
                    "$100 — allowing anyone with that capability to forge valid email signatures for the "
                    "affected domain."
                ),
                how_to_fix=fix,
                urgency=urgency,
            ))
            break  # one finding per selector is enough

    return findings


# ── Subdomain takeover detection ──────────────────────────────────────────────

# Map of CNAME target patterns → (service_name, takeover_indicator_strings)
# The indicator strings are checked in the HTTP response body of the CNAME target.
_TAKEOVER_SERVICES = {
    "github.io":              ("GitHub Pages",  ["there isn't a github pages site here",
                                                  "for root urls, you can only use custom domains"]),
    "herokuapp.com":          ("Heroku",         ["no such app", "heroku | no such app",
                                                   "there's nothing here, yet."]),
    "herokudns.com":          ("Heroku",         ["no such app", "heroku | no such app"]),
    "s3.amazonaws.com":       ("AWS S3",         ["nosuchbucket", "the specified bucket does not exist"]),
    "s3-website":             ("AWS S3 Website", ["nosuchbucket", "the specified bucket does not exist",
                                                   "nosuchkey"]),
    "cloudfront.net":         ("AWS CloudFront", ["the request could not be satisfied",
                                                   "bad request"]),
    "fastly.net":             ("Fastly",         ["fastly error: unknown domain",
                                                   "please check that this domain has been added"]),
    "pantheonsite.io":        ("Pantheon",       ["the gods are in error", "404 error unknown site"]),
    "ghost.io":               ("Ghost",          ["domain does not exist", "site not found"]),
    "surge.sh":               ("Surge",          ["project not found"]),
    "bitbucket.io":           ("Bitbucket",      ["repository not found", "404 not found"]),
    "azurewebsites.net":      ("Azure",          ["404 web site not found", "this web app is stopped"]),
    "cloudapp.azure.com":     ("Azure",          ["404 web site not found"]),
    "trafficmanager.net":     ("Azure Traffic Manager", ["404"]),
    "azureedge.net":          ("Azure CDN",      ["404"]),
    "zendesk.com":            ("Zendesk",        ["this help center no longer exists",
                                                   "uh oh. it looks like the help center"]),
    "helpscoutdocs.com":      ("HelpScout Docs", ["no settings were found for this company"]),
    "readme.io":              ("ReadMe",         ["project doesnt exist", "404 to serial"]),
    "cargo.site":             ("Cargo",          ["404 not found"]),
    "webflow.io":             ("Webflow",        ["the page you are looking for doesn't exist"]),
    "fly.dev":                ("Fly.io",         ["404", "not found"]),
}

# A few services (Azure Traffic Manager/CDN, Fly.io) don't return a distinctive
# error message for a dangling endpoint — just a bare "404"/"not found" — which
# is too generic to trust on its own (it'll also match plenty of ordinary pages,
# e.g. anything mentioning a 404 area code or quoting an HTTP status in passing).
# Entries whose indicators are *entirely* drawn from this generic set get an
# extra "response body is short and bare" requirement below, matching what
# these services' real dangling-endpoint pages actually look like.
_GENERIC_TAKEOVER_MARKERS = {"404", "not found", "bad request"}

_SUBDOMAINS_TO_CHECK = (
    "www", "mail", "api", "dev", "staging", "blog", "app", "test",
    "portal", "shop", "store", "cdn", "static", "assets", "media",
    "docs", "help", "support",
)


def _check_subdomain_takeover(host: str) -> list[dict]:
    """Check common subdomains for dangling CNAME records pointing to unclaimed cloud services."""
    if not HAS_DNS or not HAS_HTTPX:
        return []

    findings = []

    for sub in _SUBDOMAINS_TO_CHECK:
        fqdn = f"{sub}.{host}"
        try:
            answers = _dns_resolver.resolve(fqdn, "CNAME", lifetime=4)
        except Exception:
            continue  # no CNAME → skip

        for rdata in answers:
            cname_target = str(rdata.target).rstrip(".").lower()

            # Find matching service
            matched_service = None
            matched_indicators = []
            for pattern, (svc_name, indicators) in _TAKEOVER_SERVICES.items():
                if pattern in cname_target:
                    matched_service = svc_name
                    matched_indicators = indicators
                    break

            if not matched_service:
                continue  # CNAME to unknown service — skip

            # Confirm the service actually serves a "not found / unclaimed" response
            try:
                r = httpx.get(f"https://{fqdn}", timeout=8,
                              follow_redirects=True, verify=False)
                body = r.text[:2000].lower()
                generic_only = matched_indicators and all(
                    ind in _GENERIC_TAKEOVER_MARKERS for ind in matched_indicators)
                if generic_only:
                    confirmed = len(r.text.strip()) < 300 and any(ind in body for ind in matched_indicators)
                else:
                    confirmed = any(ind in body for ind in matched_indicators)
            except Exception:
                # Connection failed entirely — the CNAME dangling is itself a signal
                confirmed = True

            if not confirmed:
                continue

            findings.append(_finding(
                "DNS", "Subdomain Takeover Risk", "HIGH",
                (
                    f"{fqdn} has a CNAME record pointing to {cname_target} ({matched_service}), "
                    f"but that service/resource is unclaimed — an attacker can register it and "
                    f"serve content from your subdomain."
                ),
                f"Subdomain Takeover Risk — {fqdn}",
                category="dns",
                cwe="CWE-284",
                business_risk=(
                    f"An attacker who claims the abandoned {matched_service} resource at {cname_target} "
                    f"instantly controls {fqdn} — they can host phishing pages that appear to be part of "
                    f"your site, steal session cookies from visitors, or send emails through a subdomain "
                    f"that your customers trust."
                ),
                real_world_example=(
                    f"Example: A company forgot to remove a CNAME record for a decommissioned {matched_service} "
                    f"deployment. An attacker claimed the abandoned resource for free, then hosted a convincing "
                    f"'reset your password' phishing page on the company's own subdomain — harvesting "
                    f"credentials from customers who saw the legitimate-looking URL."
                ),
                how_to_fix=(
                    f"Either (a) delete the DNS CNAME record for {fqdn} if the subdomain is no longer needed, "
                    f"or (b) recreate the {matched_service} resource so the CNAME is no longer dangling. "
                    f"Log into your DNS provider and remove the CNAME for '{sub}' pointing to {cname_target}."
                )
            ))
            break  # one finding per subdomain

    return findings
