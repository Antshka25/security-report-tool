"""
cwe_reference.py — human-readable names and plain-English explanations for the
CWE (Common Weakness Enumeration) IDs used elsewhere in the report pipeline.

Every name/explanation below is verified against the official definition at
cwe.mitre.org for the exact CWE IDs assigned in web_checks.py, vuln_checks.py,
and supply_chain_checks.py. Never add an entry here without checking the real
MITRE page first — a security report must never show an invented reference.
"""

# cwe id -> (official MITRE name, one-sentence plain-English explanation)
CWE_INFO = {
    "CWE-16":   ("Configuration",
                 "The weakness comes from how the software was configured, not from a flaw in its code."),
    "CWE-78":   ("OS Command Injection",
                 "User input isn't filtered properly before being used in a system command, letting an attacker run unintended commands on the server."),
    "CWE-79":   ("Cross-Site Scripting (XSS)",
                 "User input isn't filtered properly before being shown on a web page, letting an attacker inject scripts that run in other visitors' browsers."),
    "CWE-89":   ("SQL Injection",
                 "User input isn't filtered properly before being used in a database query, letting an attacker manipulate or steal data from the database."),
    "CWE-200":  ("Exposure of Sensitive Information",
                 "The system reveals information to someone who shouldn't have access to it."),
    "CWE-290":  ("Authentication Bypass by Spoofing",
                 "The login or identity check can be tricked by faking trusted information, letting an attacker in without real credentials."),
    "CWE-295":  ("Improper Certificate Validation",
                 "The system doesn't properly verify a security certificate, so it could be tricked into trusting an impostor server."),
    "CWE-297":  ("Improper Certificate Validation (Hostname Mismatch)",
                 "The system accepts a security certificate without checking that it actually matches the site being connected to."),
    "CWE-298":  ("Improper Certificate Validation (Expiration Check)",
                 "The system accepts a security certificate without checking whether it has expired."),
    "CWE-319":  ("Cleartext Transmission of Sensitive Information",
                 "Sensitive data is sent over the network unencrypted, so anyone monitoring the connection can read it."),
    "CWE-327":  ("Use of a Broken or Risky Cryptographic Algorithm",
                 "The encryption method in use is outdated or weak enough that attackers can break it with modern tools."),
    "CWE-353":  ("Missing Support for Integrity Check",
                 "There's no way to verify that data wasn't altered in transit, so tampering would go unnoticed."),
    "CWE-494":  ("Download of Code Without Integrity Check",
                 "The system downloads and runs code without verifying it hasn't been tampered with, so a compromised source could slip in malicious code."),
    "CWE-552":  ("Files or Directories Accessible to External Parties",
                 "Files that should be private can be reached by people who shouldn't have access to them."),
    "CWE-601":  ("URL Redirection to Untrusted Site (Open Redirect)",
                 "The site redirects visitors to a web address taken from user input without checking it, which attackers can abuse to send victims to a malicious site."),
    "CWE-693":  ("Protection Mechanism Failure",
                 "A security safeguard that should be protecting the system is missing, disabled, or not strong enough."),
    "CWE-798":  ("Use of Hard-coded Credentials",
                 "A username, password, or key is built directly into the code or configuration, where it can be found and reused by an attacker."),
    "CWE-829":  ("Inclusion of Functionality from Untrusted Control Sphere",
                 "The system loads code, such as a script or library, from an outside source it doesn't fully control or trust."),
    "CWE-942":  ("Permissive Cross-domain Security Policy with Untrusted Domains",
                 "The site's cross-domain access policy is configured too loosely, letting untrusted websites interact with it as if they were trusted."),
    "CWE-1021": ("Improper Restriction of Rendered UI Layers (Clickjacking)",
                 "The site doesn't prevent itself from being embedded inside another page, which attackers can exploit to trick users into clicking something they didn't intend to."),
    "CWE-614":  ("Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                 "The cookie isn't marked Secure, so a browser could send it over an unencrypted connection where it can be intercepted."),
    "CWE-1004": ("Sensitive Cookie Without 'HttpOnly' Flag",
                 "The cookie isn't marked HttpOnly, so a malicious script on the page (such as one injected via XSS) can read and steal it."),
    "CWE-1275": ("Sensitive Cookie with Improper SameSite Attribute",
                 "The cookie's SameSite attribute isn't set to a safe value, making it easier for other sites to trick a visitor's browser into sending it in cross-site requests."),
}


def annotate_findings(findings):
    """
    Attach cwe_name / cwe_desc to each finding whose 'cwe' field matches one or
    more verified entries above. A finding's cwe field is normally a single ID
    (e.g. "CWE-89") but can be a comma-separated list (e.g. "CWE-1004, CWE-1275")
    when more than one weakness applies at once — the cookie-flags check in
    web_checks.py does this. Each id is looked up individually and only ids
    found in CWE_INFO contribute a name/description, so an unrecognized or
    hallucinated id never produces a fabricated entry.
    """
    for f in findings:
        ids = [c.strip() for c in f.get("cwe", "").split(",") if c.strip()]
        names, descs = [], []
        for cid in ids:
            info = CWE_INFO.get(cid)
            if info:
                names.append(info[0])
                descs.append(info[1])
        if names:
            f["cwe_name"] = "; ".join(names)
            f["cwe_desc"] = " ".join(descs)
    return findings
