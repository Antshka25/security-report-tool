"""
scanner.py — Nmap-based port/service scanner for the Security Report Tool.
Adapted from NOX's cyber_scan.py + cyber_parse.py modules.
"""
import re
import subprocess
import socket
import ipaddress
from collections import defaultdict
from typing import Optional


# ── Risk mapping ───────────────────────────────────────────────────────────────

DANGEROUS_PORTS = {
    "21":   {"service": "FTP",            "risk": "HIGH",   "reason": "Unencrypted file transfer — credentials sent in plain text"},
    "23":   {"service": "Telnet",         "risk": "HIGH",   "reason": "Unencrypted remote access — all traffic visible to attackers"},
    "25":   {"service": "SMTP",           "risk": "MEDIUM", "reason": "Mail server — often exploited for spam relay if misconfigured"},
    "53":   {"service": "DNS",            "risk": "MEDIUM", "reason": "DNS exposed publicly — risk of amplification attacks"},
    "80":   {"service": "HTTP",           "risk": "MEDIUM", "reason": "Unencrypted web traffic — data sent in plain text"},
    "110":  {"service": "POP3",           "risk": "HIGH",   "reason": "Unencrypted email retrieval — passwords exposed"},
    "135":  {"service": "RPC",            "risk": "HIGH",   "reason": "Windows RPC — historically exploited by worms (Blaster, Sasser)"},
    "139":  {"service": "NetBIOS",        "risk": "HIGH",   "reason": "Windows file sharing — used in ransomware lateral movement"},
    "143":  {"service": "IMAP",           "risk": "MEDIUM", "reason": "Unencrypted email — sensitive if not using STARTTLS"},
    "389":  {"service": "LDAP",           "risk": "HIGH",   "reason": "Directory service exposed — risk of credential harvesting"},
    "443":  {"service": "HTTPS",          "risk": "LOW",    "reason": "Encrypted web traffic — ensure SSL/TLS is up to date"},
    "445":  {"service": "SMB",            "risk": "HIGH",   "reason": "Windows file sharing — primary target for ransomware (WannaCry, NotPetya)"},
    "1433": {"service": "MSSQL",          "risk": "HIGH",   "reason": "SQL Server exposed to internet — high value target for data theft"},
    "1521": {"service": "Oracle DB",      "risk": "HIGH",   "reason": "Oracle database exposed — should never be publicly accessible"},
    "3306": {"service": "MySQL",          "risk": "HIGH",   "reason": "Database exposed to internet — direct path to your data"},
    "3389": {"service": "RDP",            "risk": "HIGH",   "reason": "Remote Desktop exposed — #1 ransomware entry point, brute-forced constantly"},
    "5432": {"service": "PostgreSQL",     "risk": "HIGH",   "reason": "Database exposed to internet — should be behind firewall"},
    "5900": {"service": "VNC",            "risk": "HIGH",   "reason": "Remote desktop — often no encryption, weak auth"},
    "6379": {"service": "Redis",          "risk": "HIGH",   "reason": "Redis database — frequently misconfigured with no auth"},
    "8080": {"service": "HTTP-Alt",       "risk": "MEDIUM", "reason": "Alternative web port — often admin panels or dev servers"},
    "8443": {"service": "HTTPS-Alt",      "risk": "LOW",    "reason": "Alternative HTTPS port — verify what service is running"},
    "9200": {"service": "Elasticsearch",  "risk": "HIGH",   "reason": "Search database — many data breaches from public Elasticsearch"},
    "27017":{"service": "MongoDB",        "risk": "HIGH",   "reason": "MongoDB exposed — many breaches from default no-auth config"},
    "22":   {"service": "SSH",            "risk": "LOW",    "reason": "Encrypted remote access — ensure key-based auth and disable root login"},
}

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# ── Target validation ─────────────────────────────────────────────────────────

def resolve_target(target: str) -> dict:
    """
    Resolve a URL or IP to a scannable host.
    Returns {"host": str, "ip": str, "original": str, "error": str|None}
    """
    original = target.strip()
    # Strip protocol
    host = re.sub(r'^https?://', '', original).rstrip('/')
    # Strip path
    host = host.split('/')[0]
    # Strip port if present
    host = host.split(':')[0]

    if not host:
        return {"host": "", "ip": "", "original": original, "error": "No valid host found in input"}

    # Check if it's already an IP
    try:
        ipaddress.ip_address(host)
        return {"host": host, "ip": host, "original": original, "error": None}
    except ValueError:
        pass

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
        return {"host": host, "ip": ip, "original": original, "error": None}
    except socket.gaierror as e:
        return {"host": host, "ip": "", "original": original, "error": f"Could not resolve {host}: {e}"}


def validate_target(host: str) -> Optional[str]:
    """Return error string if target is invalid/unsafe, else None."""
    try:
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "Cannot scan loopback address"
        if addr.is_multicast:
            return "Cannot scan multicast address"
    except Exception:
        pass
    return None


# ── Nmap execution ────────────────────────────────────────────────────────────

def run_scan(host: str, scan_type: str = "standard") -> dict:
    """
    Run an Nmap scan against host. Returns structured result dict.

    scan_type:
      "quick"    — top 100 ports, fast (-T4 -F)
      "standard" — top 1000 ports with service/version detection
      "full"     — all ports with scripts (slow, thorough)
    """
    nmap_flags = {
        "quick":    ["-T4", "-F", "--open"],
        "standard": ["-T4", "-sV", "--top-ports", "1000", "--open"],
        "full":     ["-T4", "-sV", "-sC", "-p-", "--open"],
    }.get(scan_type, ["-T4", "-sV", "--top-ports", "1000", "--open"])

    cmd = ["nmap"] + nmap_flags + [host]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180, check=False)
        raw_output = proc.stdout or ""
        stderr = proc.stderr or ""

        if not raw_output.strip():
            return {"error": f"Nmap returned no output. {stderr[:200]}",
                    "raw": "", "ports": [], "host": host}

        ports = _parse_nmap_output(raw_output)
        return {
            "error": None,
            "raw": raw_output,
            "ports": ports,
            "host": host,
            "scan_type": scan_type,
        }

    except FileNotFoundError:
        return {"error": "Nmap is not installed. Install with: sudo apt install nmap",
                "raw": "", "ports": [], "host": host}
    except subprocess.TimeoutExpired:
        return {"error": f"Scan timed out after 180 seconds for {host}",
                "raw": "", "ports": [], "host": host}
    except Exception as e:
        return {"error": str(e), "raw": "", "ports": [], "host": host}


# ── Nmap output parser ────────────────────────────────────────────────────────

def _parse_nmap_output(text: str) -> list[dict]:
    """
    Parse nmap stdout into a list of port dicts:
    [{"port": "443", "proto": "tcp", "state": "open",
      "service": "HTTPS", "version": "nginx 1.18", "risk": "LOW",
      "reason": "...", "dangerous": False}, ...]
    """
    ports = []
    # Match lines like: 443/tcp  open  https  nginx 1.18.0
    port_re = re.compile(
        r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?$', re.MULTILINE)

    for m in port_re.finditer(text):
        port_num = m.group(1)
        proto    = m.group(2)
        state    = m.group(3)
        svc_raw  = m.group(4) or ""
        version  = (m.group(5) or "").strip()

        info = DANGEROUS_PORTS.get(port_num, {})
        service  = info.get("service") or svc_raw.upper()
        risk     = info.get("risk", "INFO")
        reason   = info.get("reason", "Review what this service is and whether it needs to be public")

        ports.append({
            "port":      port_num,
            "proto":     proto,
            "state":     state,
            "service":   service,
            "version":   version,
            "risk":      risk,
            "reason":    reason,
            "dangerous": risk in ("HIGH", "MEDIUM"),
        })

    # Sort: HIGH first, then MEDIUM, LOW, INFO; then by port number
    ports.sort(key=lambda p: (RISK_ORDER.get(p["risk"], 99), int(p["port"])))
    return ports


# ── Summary helpers ───────────────────────────────────────────────────────────

def build_scan_summary(scan_result: dict, extra_findings: list = None) -> dict:
    """
    Build a summary dict from scan results for use in the AI prompt.
    extra_findings: additional findings from web_checks (SSL, headers, DNS) merged in.
    """
    ports = scan_result.get("ports", []) + (extra_findings or [])
    host  = scan_result.get("host", "")

    # Sort merged list: by risk priority, then port number (non-numeric ports go last)
    ports.sort(key=lambda p: (
        RISK_ORDER.get(p.get("risk", "INFO"), 99),
        int(p["port"]) if str(p.get("port", "")).isdigit() else 9999
    ))

    high   = [p for p in ports if p["risk"] == "HIGH"]
    medium = [p for p in ports if p["risk"] == "MEDIUM"]
    low    = [p for p in ports if p["risk"] in ("LOW", "INFO")]

    # Count only open network ports (not web/dns checks) for display
    open_ports = [p for p in ports if str(p.get("port", "")).isdigit()]

    # Overall risk score 1-10
    score = min(10, len(high) * 2 + len(medium))
    if score == 0 and ports:
        score = 2  # at least some exposure

    return {
        "host":        host,
        "total_ports": len(open_ports),
        "total_findings": len(ports),
        "high_count":  len(high),
        "medium_count":len(medium),
        "low_count":   len(low),
        "risk_score":  score,
        "risk_label":  "CRITICAL" if score >= 8 else "HIGH" if score >= 5 else "MEDIUM" if score >= 3 else "LOW",
        "ports":       ports,
        "high_ports":  high,
        "medium_ports":medium,
        "low_ports":   low,
    }
