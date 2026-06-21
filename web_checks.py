"""
web_checks.py — SSL/TLS, HTTP security headers, and DNS record checks.
Every finding includes a specific how_to_fix instruction.
"""
import re
import ssl
import socket
import subprocess
import ipaddress
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
    if not _is_ip(host):
        try:
            findings.extend(_check_dns(host))
        except Exception:
            pass
        try:
            findings.extend(_check_domain_expiration(host))
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
             category="web", how_to_fix="", urgency="", business_risk="", cwe=""):
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
        "how_to_fix": how_to_fix,
        "urgency":    urgency or (
            "Fix immediately" if risk == "HIGH" else
            "Fix within 1 week" if risk == "MEDIUM" else
            "Fix within 1 month"
        ),
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
                how_to_fix=(
                    "Disable weak ciphers and only allow modern, strong cipher suites. "
                    "Nginx: set 'ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;' and 'ssl_protocols TLSv1.2 TLSv1.3;' in your server block. "
                    "Apache: set 'SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES' in ssl.conf. "
                    "Then restart the server and verify at https://www.ssllabs.com/ssltest/"
                )
            ))

    return findings


# ── HTTP Security Headers ─────────────────────────────────────────────────────

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
            "Missing Content-Security-Policy (CSP) — no browser protection against cross-site scripting attacks that steal customer data",
            "Missing Content-Security-Policy (CSP)",
            cwe="CWE-693",
            business_risk=(
                "If an attacker ever manages to slip malicious script onto your site (e.g. through a vulnerable "
                "plugin or a comment field), there's nothing in place to stop it from running and stealing "
                "customer data such as login sessions or payment details."
            ),
            how_to_fix=(
                "Add a Content-Security-Policy header. Start with a basic policy: "
                "'add_header Content-Security-Policy \"default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\'\";' "
                "For WordPress or complex sites, use https://csp-evaluator.withgoogle.com to generate a custom policy. "
                "This is one of the most effective defenses against data theft."
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
            if missing:
                risk = "MEDIUM" if ("Secure" in missing or "HttpOnly" in missing) else "LOW"
                # CWE per missing flag — verified against cwe.mitre.org: Secure -> CWE-614,
                # HttpOnly -> CWE-1004, SameSite -> CWE-1275. Built dynamically since a
                # single cookie finding can be missing more than one flag at once.
                _cookie_cwe = {"Secure": "CWE-614", "HttpOnly": "CWE-1004", "SameSite": "CWE-1275"}
                cookie_cwe = ", ".join(_cookie_cwe[m] for m in missing)
                findings.append(_finding(
                    "HTTPS", "Cookie Security", risk,
                    f"Cookie '{cookie_name}' is missing the {', '.join(missing)} flag(s), making it easier to steal or misuse",
                    f"Insecure Cookie Flags ({cookie_name})",
                    cwe=cookie_cwe,
                    business_risk=(
                        "Without these flags, a cookie is easier to steal through cross-site scripting or to "
                        "intercept over an unencrypted connection — and a stolen session cookie can let an "
                        "attacker impersonate that logged-in user without ever needing their password."
                    ),
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
                        "SPF record uses '+all' — anyone on the internet can send emails as your domain, the record does nothing",
                        "SPF Record Too Permissive (+all)",
                        category="dns",
                        cwe="CWE-290",
                        business_risk=(
                            "Scammers can send phishing or fraud emails that look exactly like they came from "
                            "your business, and recipients have no way to tell them apart from the real thing — "
                            "putting your customers and your reputation at risk."
                        ),
                        how_to_fix=(
                            "Change '+all' to '-all' (hard fail) in your SPF record in your DNS settings. "
                            "Log into your domain registrar (GoDaddy, Namecheap, etc.), go to DNS settings, "
                            "find the TXT record starting with 'v=spf1', and change '+all' to '-all'. "
                            "Example: 'v=spf1 include:_spf.google.com -all'"
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
                        how_to_fix="Change '?all' to '~all' (soft fail) or '-all' (hard fail) in your DNS TXT record. Use '-all' for strongest protection."
                    ))
                break
    except Exception:
        pass

    if not spf_found:
        findings.append(_finding(
            "DNS", "SPF Record", "HIGH",
            "No SPF record — anyone can send emails pretending to be from your domain, used for phishing scams targeting your customers",
            "Missing SPF Record — Email Spoofing Possible",
            category="dns",
            cwe="CWE-290",
            business_risk=(
                "Without SPF, scammers can convincingly impersonate your business by email — which can lead to "
                "customers being defrauded, your domain's email reputation being damaged, and your own real "
                "emails landing in spam as a result."
            ),
            how_to_fix=(
                "Add an SPF TXT record to your DNS. Log into your domain registrar, go to DNS, "
                "add a new TXT record for '@' with value: 'v=spf1 include:_spf.google.com -all' "
                "(replace the include with your email provider's SPF). "
                "Google Workspace: 'v=spf1 include:_spf.google.com -all' | "
                "Microsoft 365: 'v=spf1 include:spf.protection.outlook.com -all' | "
                "Generic: 'v=spf1 a mx -all'. Use https://mxtoolbox.com/spf.aspx to verify."
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
                    findings.append(_finding(
                        "DNS", "DMARC Policy", "MEDIUM",
                        "DMARC is set to monitor-only (p=none) — phishing emails pretending to be you aren't blocked, just reported",
                        "DMARC Monitor-Only (p=none) — Not Enforced",
                        category="dns",
                        cwe="CWE-290",
                        business_risk=(
                            "Phishing emails pretending to be your business can still reach customers' inboxes "
                            "today — you'll get reports about it after the fact, but nothing actually stops the "
                            "fraudulent emails from being delivered right now."
                        ),
                        how_to_fix=(
                            "Upgrade DMARC from p=none to p=quarantine or p=reject. "
                            "In your DNS, update the _dmarc TXT record: change 'p=none' to 'p=quarantine' first (sends suspicious mail to spam). "
                            "After a week with no issues, change to 'p=reject' (blocks spoofed emails completely). "
                            "Example final record: 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'"
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
            how_to_fix=(
                "Add a DMARC TXT record to your DNS. Go to your domain registrar's DNS settings, "
                "add a TXT record for '_dmarc' (not '@') with value: "
                "'v=DMARC1; p=quarantine; rua=mailto:youremail@yourdomain.com' "
                "Start with p=quarantine, monitor for a week, then change to p=reject for full protection. "
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
            "No DKIM signature detected — outgoing emails aren't cryptographically signed, making spoofing and tampering easier",
            "DKIM Not Detected",
            category="dns",
            cwe="CWE-290",
            business_risk=(
                "Email providers increasingly use DKIM as a trust signal — without it, your legitimate emails "
                "are more likely to be flagged as suspicious or land in spam, hurting delivery of invoices, "
                "marketing, and everyday customer communications."
            ),
            how_to_fix=(
                "Enable DKIM signing through your email provider. "
                "Google Workspace: Admin console > Apps > Gmail > Authenticate email > Generate DKIM key, then add the TXT record to DNS. "
                "Microsoft 365: Security > Email authentication > DKIM > enable for your domain. "
                "Other providers: check their docs for 'DKIM setup'. "
                "Note: we checked common selectors — if you use a custom DKIM selector this may be a false alarm."
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
            how_to_fix="Turn on auto-renew at your registrar, or add a calendar reminder for the renewal date.",
            urgency="Monitor"
        ))

    return findings
