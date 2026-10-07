"""
Local rule-based security analyzer.

Defines the analysis result types (HostAnalysis, ScanAnalysis) and produces
them without contacting any external service. Uses a curated rule set covering:
  - Cleartext protocols (telnet, ftp, http auth, pop3/imap without TLS)
  - Exposed admin surfaces (RDP, SMB, WinRM, IPMI, SNMP)
  - Unauthenticated-by-default datastores (Redis, MongoDB, Elasticsearch, Memcached)
  - End-of-life service and OS versions
  - CVEs and "VULNERABLE" findings already parsed from nmap's vuln scripts
"""

import ipaddress
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from parser import ScanResult, Host, ScriptResult, scan_args_are_discovery
except ImportError:
    from .parser import ScanResult, Host, ScriptResult, scan_args_are_discovery


@dataclass
class HostAnalysis:
    """Rule-based analysis for a single host."""
    ip: str
    risk_level: str  # critical, high, medium, low, info
    summary: str
    findings: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanAnalysis:
    """Complete rule-based analysis of a scan."""
    overall_risk: str
    executive_summary: str
    host_analyses: List[HostAnalysis]
    network_observations: List[str]
    priority_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_risk': self.overall_risk,
            'executive_summary': self.executive_summary,
            'host_analyses': [h.to_dict() for h in self.host_analyses],
            'network_observations': self.network_observations,
            'priority_actions': self.priority_actions,
        }


RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}


def _max_risk(a: str, b: str) -> str:
    return a if RISK_RANK.get(a, 0) >= RISK_RANK.get(b, 0) else b


# port -> (risk, finding, recommendation)
PORT_RULES: Dict[int, Tuple[str, str, str]] = {
    21:    ("high",     "FTP is exposed. FTP transmits credentials and data in cleartext and often allows anonymous login.",
                        "Replace FTP with SFTP (SSH) or FTPS. If FTP must remain, disable anonymous access and restrict source IPs."),
    23:    ("critical", "Telnet is exposed. All traffic including credentials is transmitted in cleartext.",
                        "Disable telnet immediately and use SSH (port 22) instead."),
    25:    ("medium",   "SMTP is exposed. Verify it does not allow open relay and that STARTTLS is enforced.",
                        "Require STARTTLS, disable open relay, restrict to expected sender networks."),
    69:    ("high",     "TFTP is exposed. TFTP has no authentication and is frequently used to exfiltrate configs.",
                        "Disable TFTP unless required for PXE / network device provisioning; if required, firewall to a management VLAN."),
    79:    ("low",      "Finger service is exposed. Finger leaks user account information.",
                        "Disable the finger service."),
    110:   ("medium",   "POP3 is exposed. Without STARTTLS, credentials transmit in cleartext.",
                        "Migrate to POP3S (995) or require STARTTLS on 110."),
    111:   ("medium",   "rpcbind/portmapper is exposed. Discloses RPC service inventory and is used in amplification attacks.",
                        "Restrict rpcbind to local interfaces or block at the perimeter."),
    135:   ("medium",   "Microsoft RPC endpoint mapper is exposed.",
                        "Block ports 135-139 and 445 at the perimeter. Restrict to management networks only."),
    137:   ("medium",   "NetBIOS Name Service is exposed and can leak host/workgroup names.",
                        "Block NetBIOS ports (137-139) at the perimeter."),
    139:   ("high",     "NetBIOS Session Service / legacy SMB is exposed.",
                        "Block 139/445 at the perimeter. Disable SMBv1. Patch against MS17-010."),
    143:   ("medium",   "IMAP is exposed. Without STARTTLS, credentials transmit in cleartext.",
                        "Migrate to IMAPS (993) or require STARTTLS on 143."),
    161:   ("high",     "SNMP is exposed. SNMP is frequently left with default community strings (public/private).",
                        "Migrate to SNMPv3 with authentication and encryption. Block UDP/161 from untrusted networks. Verify community strings are not default."),
    389:   ("medium",   "LDAP is exposed without TLS.",
                        "Use LDAPS (636) or StartTLS on 389. Restrict directory queries to authenticated clients."),
    445:   ("critical", "SMB is exposed. SMB is the vector for EternalBlue (MS17-010), SMBGhost (CVE-2020-0796), and ransomware lateral movement.",
                        "Block port 445 at the perimeter. Disable SMBv1. Patch MS17-010 and CVE-2020-0796. Require SMB signing."),
    512:   ("high",     "rexec is exposed.",
                        "Disable rexec. It is cleartext and deprecated."),
    513:   ("high",     "rlogin is exposed.",
                        "Disable rlogin and use SSH."),
    514:   ("high",     "rsh is exposed.",
                        "Disable rsh and use SSH."),
    515:   ("low",      "LPD print service is exposed.",
                        "Restrict print services to internal networks."),
    623:   ("high",     "IPMI is exposed. IPMI 2.0 has an authentication bypass (CVE-2013-4786) and often runs default credentials.",
                        "Restrict IPMI/iLO/iDRAC to a dedicated out-of-band management network."),
    873:   ("medium",   "rsync daemon is exposed.",
                        "Require authentication, restrict modules, or tunnel rsync over SSH."),
    1080:  ("medium",   "SOCKS proxy is exposed.",
                        "Require authentication and restrict source IPs. Open SOCKS proxies are abused for traffic laundering."),
    1433:  ("high",     "Microsoft SQL Server is exposed to the network.",
                        "Restrict SQL Server to application subnets. Enforce a strong sa password and disable xp_cmdshell."),
    1521:  ("high",     "Oracle TNS Listener is exposed.",
                        "Restrict to application servers. Set a listener password. Patch CPU advisories."),
    1900:  ("low",      "UPnP/SSDP is exposed. SSDP is used for reflection/amplification DDoS.",
                        "Disable UPnP on internet-facing devices."),
    2049:  ("high",     "NFS is exposed.",
                        "Restrict exports by IP, require Kerberos (sec=krb5), or block 2049 at the perimeter."),
    2375:  ("critical", "Docker daemon is exposed without TLS. This grants unauthenticated remote root code execution.",
                        "Bind dockerd to localhost only, or enable TLS client-certificate authentication on 2376."),
    2376:  ("medium",   "Docker daemon (TLS) is exposed. Verify client certificate authentication is enforced.",
                        "Confirm TLS verification mode and rotate client certificates regularly."),
    3306:  ("high",     "MySQL/MariaDB is exposed to the network.",
                        "Bind MySQL to localhost or an application subnet. Require TLS. Ensure root is not accessible remotely."),
    3389:  ("high",     "RDP is exposed. RDP is a top target for brute force and BlueKeep (CVE-2019-0708) attacks.",
                        "Place RDP behind a VPN or jump host. Enable Network Level Authentication. Patch BlueKeep. Enforce account lockout."),
    4444:  ("medium",   "Port 4444 is commonly used by Metasploit handlers.",
                        "Investigate this port and confirm it is a legitimate service."),
    5060:  ("medium",   "SIP is exposed. Common target for toll fraud.",
                        "Restrict SIP to known peers. Enable abuse mitigation (fail2ban or equivalent)."),
    5432:  ("high",     "PostgreSQL is exposed to the network.",
                        "Restrict PostgreSQL via pg_hba.conf. Bind to application subnet only. Require TLS."),
    5601:  ("medium",   "Kibana is exposed.",
                        "Place Kibana behind an authenticated reverse proxy. Restrict by source IP."),
    5900:  ("high",     "VNC is exposed. VNC frequently runs with weak or no authentication.",
                        "Tunnel VNC over SSH. Require a strong password. Restrict source IPs."),
    5984:  ("high",     "CouchDB is exposed. Older versions allow unauthenticated admin access (CVE-2017-12635).",
                        "Bind to localhost. Patch to current version. Enable authentication."),
    5985:  ("medium",   "WinRM (HTTP) is exposed.",
                        "Prefer WinRM HTTPS (5986). Restrict to management networks."),
    5986:  ("low",      "WinRM (HTTPS) is exposed.",
                        "Restrict to management networks and require client certificate authentication where possible."),
    6379:  ("critical", "Redis is exposed. Redis defaults to no authentication and is routinely abused for RCE via config rewrite.",
                        "Bind Redis to localhost or require AUTH. Block 6379 at the perimeter."),
    6443:  ("medium",   "Kubernetes API server is exposed.",
                        "Restrict the API server to known operator networks. Enforce RBAC and audit logging."),
    7001:  ("medium",   "WebLogic admin port is exposed.",
                        "WebLogic has had multiple unauthenticated RCEs (CVE-2017-10271, CVE-2019-2725). Patch and restrict access."),
    8009:  ("medium",   "AJP connector (Tomcat) is exposed. Vulnerable to Ghostcat (CVE-2020-1938) on older Tomcat.",
                        "Disable AJP if unused. Patch Tomcat. Bind AJP to localhost."),
    8080:  ("info",     "HTTP service on 8080 detected.",
                        "Verify TLS is used for any admin or authenticated interface."),
    8443:  ("info",     "HTTPS service on 8443 detected.",
                        "Verify certificate validity and TLS configuration."),
    9100:  ("medium",   "JetDirect/raw printing port is exposed.",
                        "Restrict to print servers. Print services should never be reachable from the internet."),
    9200:  ("critical", "Elasticsearch is exposed. Elasticsearch defaults to no authentication and is a top data-leak source.",
                        "Bind to localhost or enable security features (auth + TLS). Block 9200 at the perimeter."),
    9300:  ("high",     "Elasticsearch transport port is exposed.",
                        "Restrict to cluster nodes only."),
    10000: ("medium",   "Webmin is exposed. Has a history of unauthenticated RCE (CVE-2019-15107).",
                        "Patch Webmin. Restrict by source IP."),
    11211: ("high",     "Memcached is exposed. Used for UDP reflection/amplification DDoS.",
                        "Bind to localhost. Disable UDP. Block 11211 at the perimeter."),
    15672: ("medium",   "RabbitMQ management UI is exposed.",
                        "Restrict to management networks. Change default guest/guest credentials."),
    27017: ("critical", "MongoDB is exposed. Older versions default to no authentication.",
                        "Enable authentication. Bind to application subnet. Block 27017 at the perimeter."),
    27018: ("critical", "MongoDB shard is exposed.",
                        "Apply the same hardening as port 27017: enable auth, restrict network access."),
    50070: ("medium",   "Hadoop NameNode is exposed.",
                        "Enable Kerberos for HDFS. Restrict to operator networks."),
}


# Service-name fallback for non-standard ports. Key = nmap service name (lower).
SERVICE_RULES: Dict[str, Tuple[str, str, str]] = {
    "telnet":        PORT_RULES[23],
    "ftp":           PORT_RULES[21],
    "tftp":          PORT_RULES[69],
    "vnc":           PORT_RULES[5900],
    "redis":         PORT_RULES[6379],
    "mongodb":       PORT_RULES[27017],
    "elasticsearch": PORT_RULES[9200],
    "memcached":     PORT_RULES[11211],
    "ms-sql-s":      PORT_RULES[1433],
    "mysql":         PORT_RULES[3306],
    "postgresql":    PORT_RULES[5432],
    "ms-wbt-server": PORT_RULES[3389],
    "microsoft-ds":  PORT_RULES[445],
    "netbios-ssn":   PORT_RULES[139],
    "snmp":          PORT_RULES[161],
    "rdp":           PORT_RULES[3389],
    "ipmi":          PORT_RULES[623],
    "rsh":           PORT_RULES[514],
    "rlogin":        PORT_RULES[513],
}


# (service_substring, version_regex, risk, finding, recommendation)
VERSION_RULES: List[Tuple[str, str, str, str, str]] = [
    ("vsftpd",        r"^2\.3\.4",           "critical", "vsftpd 2.3.4 detected — this version contains a documented backdoor.",
                                                         "Upgrade vsftpd immediately."),
    ("openssh",       r"^([1-6]\.|7\.[0-3])","medium",   "OpenSSH older than 7.4 — historical user enumeration and other CVEs apply.",
                                                         "Upgrade OpenSSH to the latest stable release."),
    ("apache",        r"^2\.4\.(49|50)$",    "critical", "Apache httpd 2.4.49/2.4.50 — path traversal and RCE (CVE-2021-41773, CVE-2021-42013).",
                                                         "Upgrade Apache to 2.4.51 or later immediately."),
    ("apache",        r"^2\.[0-2]\.",        "high",     "Apache httpd 2.2 or older — end of life.",
                                                         "Upgrade Apache to a supported 2.4.x release."),
    ("microsoft-iis", r"^[67]\.",            "high",     "IIS 6/7 detected — end of life.",
                                                         "Upgrade to a supported Windows Server release."),
    ("proftpd",       r"^1\.3\.5$",          "high",     "ProFTPD 1.3.5 — CVE-2015-3306 (mod_copy) applies.",
                                                         "Upgrade ProFTPD to the latest stable release."),
    # \d, not just "3.": nmap's generic match reports every Samba server as
    # version "3.X - 4.X", which is not a Samba 3 detection.
    ("samba",         r"^3\.\d",             "high",     "Samba 3.x detected — end of life.",
                                                         "Upgrade Samba to 4.x. Disable SMBv1."),
    ("exim",          r"^4\.(8\d|9[01])(\D|$)", "high",     "Exim older than 4.92 — multiple RCEs (CVE-2019-10149 et al).",
                                                         "Upgrade Exim to the latest stable release."),
    ("nginx",         r"^(0\.|1\.[0-9]\.|1\.1[0-3]\.)", "medium", "nginx older than 1.14 detected — end of life.",
                                                         "Upgrade nginx to a supported release."),
]


# (os_name_substring, risk, finding, recommendation)
OS_RULES: List[Tuple[str, str, str, str]] = [
    ("windows xp",          "critical", "Windows XP is unsupported and unpatched since 2014.",
                                         "Decommission this host or isolate on a segmented network with no internet access."),
    ("windows 2000",        "critical", "Windows 2000 is unsupported and unpatched since 2010.",
                                         "Decommission this host."),
    ("windows server 2003", "critical", "Windows Server 2003 is unsupported since 2015.",
                                         "Decommission or migrate workloads to a supported OS."),
    ("windows server 2008", "high",     "Windows Server 2008/2008 R2 is end-of-life (extended support ended 2020/2023).",
                                         "Upgrade to a supported Windows Server release."),
    ("windows 7",           "high",     "Windows 7 is end-of-life (extended support ended 2020).",
                                         "Upgrade endpoints to Windows 10/11."),
    ("windows 8",           "high",     "Windows 8.x is end-of-life.",
                                         "Upgrade endpoints to Windows 10/11."),
    ("windows server 2012", "medium",   "Windows Server 2012/2012 R2 is end-of-life (extended support ended 2023).",
                                         "Upgrade to Windows Server 2019 or later."),
]


# Script-based findings. Each: (script_id_substring, output_regex, risk, finding,
# recommendation). These turn nmap's `default`/`vuln` script output into concrete,
# actionable findings beyond raw port exposure.
SCRIPT_RULES: List[Tuple[str, str, str, str, str]] = [
    ("smb2-security-mode", r"message signing.*(not required|disabled)", "medium",
        "SMB signing is not required — exposes the host to NTLM relay / SMB MITM.",
        "Require SMB signing (GPO: 'Microsoft network server: Digitally sign communications (always)')."),
    ("smb-security-mode", r"(message_signing:\s*disabled|signing.*not required)", "medium",
        "SMB signing is not required — exposes the host to NTLM relay / SMB MITM.",
        "Require SMB signing on this host."),
    ("ssl-enum-ciphers", r"(SSLv3|TLSv1\.0|TLSv1\.1)", "medium",
        "Deprecated TLS protocol (SSLv3 / TLS 1.0 / TLS 1.1) is offered.",
        "Disable SSLv3/TLS1.0/TLS1.1; offer TLS 1.2+ only."),
    ("ssl-enum-ciphers", r"least strength:\s*[EF]\b", "medium",
        "Weak TLS cipher strength (grade E/F) reported.",
        "Remove weak/export ciphers; prefer forward-secrecy AEAD suites (target grade A)."),
    ("http-methods", r"Potentially risky methods:\s*[^\n]*(PUT|DELETE)", "medium",
        "Web server allows risky HTTP methods (PUT/DELETE).",
        "Disable WebDAV / risky HTTP methods unless explicitly required."),
    ("snmp-brute", r"Valid credentials", "high",
        "SNMP community string was guessed (default/weak, e.g. 'public').",
        "Change SNMP community strings, migrate to SNMPv3, and restrict UDP/161."),
    ("http-default-accounts", r"(credentials found|default credentials)", "high",
        "Default application credentials detected.",
        "Change all default credentials immediately."),
]

# ssl-cert: nmap prints "Not valid after:  YYYY-MM-DDTHH:MM:SS"
_SSL_NOT_AFTER_RE = re.compile(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})")


def _ssl_cert_finding(output: str) -> Optional[Tuple[str, str, str]]:
    """Turn an ssl-cert script output into an expiry finding, if applicable."""
    m = _SSL_NOT_AFTER_RE.search(output)
    if not m:
        return None
    try:
        not_after = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    days = (not_after - now).days
    if days < 0:
        return ("high", f"TLS certificate expired {abs(days)} day(s) ago (on {m.group(1)}).",
                "Renew/replace the TLS certificate immediately.")
    if days <= 30:
        return ("medium", f"TLS certificate expires in {days} day(s) (on {m.group(1)}).",
                "Renew the TLS certificate before it expires.")
    return None


def analyze_scripts(scripts: List[ScriptResult]) -> List[Tuple[str, str, str]]:
    """Return (risk, finding, recommendation) tuples from a set of script results."""
    out: List[Tuple[str, str, str]] = []
    seen = set()
    for s in scripts:
        sid = (s.script_id or "").lower()
        # ssl-cert expiry (special-cased: needs date math)
        if "ssl-cert" in sid:
            res = _ssl_cert_finding(s.output)
            if res and (sid, res[1]) not in seen:
                seen.add((sid, res[1]))
                out.append(res)
        # Pattern-based script rules
        for sub, regex, risk, finding, rec in SCRIPT_RULES:
            if sub in sid and re.search(regex, s.output, re.IGNORECASE):
                key = (sub, finding)
                if key not in seen:
                    seen.add(key)
                    out.append((risk, finding, rec))
    return out


def analyze_host(host: Host) -> HostAnalysis:
    findings: List[str] = []
    recommendations: List[str] = []
    risk = "info"

    if host.status != "up":
        return HostAnalysis(
            ip=host.ip, risk_level="info",
            summary="Host did not respond.",
            findings=[], recommendations=[],
        )

    seen_rule_keys = set()

    # Only confirmed-open ports produce findings. An open|filtered port is
    # nmap saying "no reply, can't tell" — scoring it invents a service that
    # was never observed, and on a subnet scan that manufactures identical
    # findings for every silent address. See parser.STATE_UNCONFIRMED.
    for port in [p for p in host.ports if p.is_open]:
        port_key = ("port", port.port)
        service_key = ("svc", port.service.lower())

        # Port-based rule
        rule = PORT_RULES.get(port.port)
        if rule and port_key not in seen_rule_keys:
            r, f, rec = rule
            findings.append(f"[{r.upper()}] Port {port.port}/{port.protocol} ({port.service}): {f}")
            recommendations.append(rec)
            risk = _max_risk(risk, r)
            seen_rule_keys.add(port_key)
        # Service-name fallback (non-standard ports)
        elif port.service and port.service.lower() in SERVICE_RULES and service_key not in seen_rule_keys:
            r, f, rec = SERVICE_RULES[port.service.lower()]
            findings.append(f"[{r.upper()}] {port.service} on port {port.port}/{port.protocol}: {f}")
            recommendations.append(rec)
            risk = _max_risk(risk, r)
            seen_rule_keys.add(service_key)

        # Version-pattern rules
        product_l = (port.product or "").lower()
        service_l = (port.service or "").lower()
        for svc_substr, vregex, r, f, rec in VERSION_RULES:
            if (svc_substr in product_l or svc_substr in service_l) and port.version:
                if re.search(vregex, port.version, re.IGNORECASE):
                    label = port.product or port.service
                    findings.append(f"[{r.upper()}] {label} {port.version} on port {port.port}: {f}")
                    recommendations.append(rec)
                    risk = _max_risk(risk, r)

        # Vulnerabilities already extracted by parser from nmap scripts
        for vuln in port.vulnerabilities:
            sev = vuln.severity if vuln.severity in RISK_RANK and vuln.severity != "unknown" else "high"
            cve_str = f" ({', '.join(sorted(set(vuln.cve_ids)))})" if vuln.cve_ids else ""
            findings.append(f"[{sev.upper()}] nmap script {vuln.script_id} flagged port {port.port}{cve_str}.")
            recommendations.append(f"Investigate the {vuln.script_id} finding on port {port.port} and apply vendor patches.")
            risk = _max_risk(risk, sev)

        # Script-based findings (SSL cert expiry, SMB signing, weak TLS, ...)
        for r, f, rec in analyze_scripts(port.scripts):
            findings.append(f"[{r.upper()}] Port {port.port}/{port.protocol} ({port.service}): {f}")
            recommendations.append(rec)
            risk = _max_risk(risk, r)

    # OS-based rule
    if host.os_matches:
        os_name = host.os_matches[0].name.lower()
        for substr, r, f, rec in OS_RULES:
            if substr in os_name:
                findings.append(f"[{r.upper()}] OS: {f}")
                recommendations.append(rec)
                risk = _max_risk(risk, r)
                break

    # Host-level vulnerabilities (from <hostscript>, e.g. smb-vuln-ms17-010)
    for vuln in host.host_vulnerabilities:
        sev = vuln.severity if vuln.severity in RISK_RANK and vuln.severity != "unknown" else "high"
        cve_str = f" ({', '.join(sorted(set(vuln.cve_ids)))})" if vuln.cve_ids else ""
        findings.append(f"[{sev.upper()}] nmap host script {vuln.script_id} flagged this host{cve_str}.")
        recommendations.append(f"Investigate the {vuln.script_id} finding and apply vendor patches.")
        risk = _max_risk(risk, sev)

    # Host-level script findings (SMB signing, SMB OS discovery context, ...)
    for r, f, rec in analyze_scripts(host.host_scripts):
        findings.append(f"[{r.upper()}] {f}")
        recommendations.append(rec)
        risk = _max_risk(risk, r)

    # Summary
    open_ports = [p for p in host.ports if p.is_open]
    unconfirmed = [p for p in host.ports if p.is_unconfirmed]
    if not open_ports:
        summary = "Host responded but no open ports were detected by this scan."
        if unconfirmed:
            # Say what was actually observed: silence, not a service.
            summary += (f" {len(unconfirmed)} port(s) gave no reply (open|filtered) — "
                        "not evidence of a running service.")
    else:
        port_list = ", ".join(str(p.port) for p in open_ports[:6])
        more = f", +{len(open_ports) - 6} more" if len(open_ports) > 6 else ""
        summary = f"{len(open_ports)} open port(s): {port_list}{more}."
        if risk in ("critical", "high"):
            summary += f" {risk.capitalize()}-risk findings present."
        elif risk == "info":
            summary += " No rule matches; manual review still recommended."

    # Deduplicate recommendations preserving order
    seen = set()
    deduped_recs = []
    for r in recommendations:
        if r not in seen:
            seen.add(r)
            deduped_recs.append(r)

    return HostAnalysis(
        ip=host.ip,
        risk_level=risk,
        summary=summary,
        findings=findings,
        recommendations=deduped_recs,
    )


def _edge_addresses(scan_args: str) -> Optional[set]:
    """
    Network and broadcast addresses of the CIDR blocks in an nmap command line,
    or None when it names no CIDR block.

    Worked out from the real prefix because ".0" and ".255" are only special in
    a /24: 10.0.1.0 and 10.0.0.255 are ordinary host addresses inside a /23.
    """
    edges = set()
    found = False
    for token in (scan_args or "").split():
        if "/" not in token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        found = True
        if net.version == 4 and net.prefixlen <= 30:
            edges.add(str(net.network_address))
            edges.add(str(net.broadcast_address))
    return edges if found else None


def scan_quality_warnings(scan_result: ScanResult) -> List[str]:
    """
    Detect results that indicate the scan itself was wrong, not the network.

    The signature case is a VM using NAT/shared networking. The virtual gateway
    answers ARP for every address in the subnet (proxy ARP), so nmap sees the
    whole range as alive, spends hours probing addresses where nothing exists,
    and reports each one with an identical set of never-answered ports. The scan
    "succeeds" and every number in it is fiction.

    Nothing downstream can tell that from a genuinely dense network, so it has
    to be caught here and said plainly, next to the results it invalidates.
    """
    warnings: List[str] = []
    up_hosts = [h for h in scan_result.hosts if h.status == "up"]
    if not up_hosts:
        return warnings

    # A whole /24 answering is not a network, it is an artifact — and this
    # holds however the hosts were found, so it is checked first and applies
    # to ping sweeps too (where it is the earliest possible warning).
    if len(up_hosts) >= 250:
        warnings.append(
            f"SCAN QUALITY: {len(up_hosts)} hosts reported up — essentially every "
            "address in the range. Real subnets are not fully populated. Host "
            "discovery is almost certainly answering for addresses that do not "
            "exist (typically a VM on NAT/shared networking, whose virtual "
            "gateway proxy-ARPs the entire subnet). Switch the VM's network "
            "adapter to Bridged and re-scan."
        )

    silent = [h for h in up_hosts if not any(p.is_open for p in h.ports)]

    # A real subnet has devices that answer something. A large block where
    # almost nothing does means the "hosts" are an artifact of discovery.
    # Meaningless for a ping sweep, which probes no ports by design.
    is_sweep = scan_args_are_discovery(scan_result.scan_args)
    if not is_sweep and len(up_hosts) >= 32 and len(silent) / len(up_hosts) >= 0.8:
        pct = round(100 * len(silent) / len(up_hosts))
        warnings.append(
            f"SCAN QUALITY: {len(up_hosts)} hosts reported up, but {pct}% of them "
            f"({len(silent)}) have no confirmed open port — only unanswered probes. "
            "This is the signature of host discovery answering for addresses that "
            "do not exist, usually because the scanner is running in a VM with "
            "NAT/shared networking (the virtual gateway proxy-ARPs the whole "
            "subnet). Switch the VM's network adapter to Bridged and re-scan; "
            "treat this run's host count and per-host findings as unreliable."
        )

    # A subnet's network and broadcast addresses are never real hosts.
    edge_addresses = _edge_addresses(scan_result.scan_args)
    if edge_addresses is None:
        # Target wasn't given as CIDR (a range or wildcard): assume /24s.
        edge = sorted(h.ip for h in up_hosts
                      if h.ip.endswith(".0") or h.ip.endswith(".255"))
    else:
        edge = sorted(h.ip for h in up_hosts if h.ip in edge_addresses)
    if edge:
        warnings.append(
            f"SCAN QUALITY: network/broadcast address(es) reported as live hosts "
            f"({', '.join(edge)}). These are not devices — their presence confirms "
            "host discovery is responding for addresses that do not exist."
        )

    return warnings


def analyze_locally(scan_result: ScanResult) -> ScanAnalysis:
    """Run the rule engine over a parsed scan and produce a ScanAnalysis."""
    host_analyses = [analyze_host(h) for h in scan_result.hosts if h.status == "up"]

    overall = "info"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for ha in host_analyses:
        overall = _max_risk(overall, ha.risk_level)
        counts[ha.risk_level] = counts.get(ha.risk_level, 0) + 1

    up = scan_result.total_hosts_up
    down = scan_result.total_hosts_down

    if up == 0:
        exec_summary = f"No live hosts detected ({down} did not respond)."
    else:
        parts = []
        for tier in ("critical", "high", "medium"):
            if counts[tier]:
                parts.append(f"{counts[tier]} {tier}")
        risk_phrase = ", ".join(parts) if parts else "no significant"
        exec_summary = (
            f"Scanned {up} live host(s) ({down} not responding). "
            f"{risk_phrase}-risk host(s) identified. Overall network risk: {overall.upper()}."
        )

    # Network-level observations
    cleartext_ports = {21, 23, 69, 80, 110, 143, 512, 513, 514}
    admin_ports = {22, 161, 623, 3389, 5985, 5986, 10000}
    db_ports = {1433, 3306, 5432, 5984, 6379, 9200, 11211, 27017, 27018}
    # Confirmed-open ports only — an unanswered UDP probe is not an exposure.
    open_ports_all = [p for h in scan_result.hosts for p in h.ports if p.is_open]
    n_cleartext = sum(1 for p in open_ports_all if p.port in cleartext_ports)
    n_admin = sum(1 for p in open_ports_all if p.port in admin_ports)
    n_db = sum(1 for p in open_ports_all if p.port in db_ports)
    n_vuln = sum(len(p.vulnerabilities) for p in open_ports_all)

    # Scan-quality problems come first: if host discovery was wrong, every
    # other number below is wrong too, and the reader needs to know that
    # before they read them.
    quality_warnings = scan_quality_warnings(scan_result)
    obs: List[str] = list(quality_warnings)
    if n_cleartext:
        obs.append(f"{n_cleartext} cleartext protocol exposure(s) detected across the scan.")
    if n_admin:
        obs.append(f"{n_admin} administrative service(s) exposed on scanned hosts.")
    if n_db:
        obs.append(f"{n_db} database/datastore port(s) reachable on scanned hosts.")
    if n_vuln:
        obs.append(f"{n_vuln} nmap script vulnerability finding(s) recorded.")
    if len(obs) == len(quality_warnings):
        obs.append("No high-level network-wide exposure patterns flagged by the rule engine.")

    # Priority actions: rank deduplicated recommendations by (max host severity, frequency)
    rec_index: Dict[str, Dict[str, int]] = {}
    for ha in host_analyses:
        sev = RISK_RANK.get(ha.risk_level, 0)
        for rec in ha.recommendations:
            entry = rec_index.setdefault(rec, {"count": 0, "max_sev": 0})
            entry["count"] += 1
            entry["max_sev"] = max(entry["max_sev"], sev)

    sorted_recs = sorted(
        rec_index.items(),
        key=lambda kv: (kv[1]["max_sev"], kv[1]["count"]),
        reverse=True,
    )
    priority_actions = [rec for rec, _ in sorted_recs[:5]]
    if not priority_actions:
        priority_actions = ["No critical actions identified by the rule engine. Manual review still recommended."]

    return ScanAnalysis(
        overall_risk=overall,
        executive_summary=exec_summary,
        host_analyses=host_analyses,
        network_observations=obs,
        priority_actions=priority_actions,
    )
