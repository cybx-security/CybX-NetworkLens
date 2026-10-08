"""
Nmap XML output parser - converts nmap XML output to structured Python objects.
"""

import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime
import re


# ---------------------------------------------------------------------------
# Port state semantics — the one place that defines what "open" means.
#
# nmap's "open|filtered" does NOT mean open. It means nmap got no reply at all
# and cannot tell an open port from a firewalled one. For a UDP probe that is
# the normal result for any address that isn't there: silence is
# indistinguishable from a service that simply didn't answer.
#
# Treating it as open is catastrophic on a subnet scan. Every silent address
# turns into a "device" with the full set of probed UDP ports "open", each one
# firing its port rule — so a /24 with 40 real devices reports 256 hosts, all
# with identical fake services and identical fake findings. That is exactly the
# failure this constant exists to prevent, so keep these two states distinct
# everywhere: parse open|filtered (it is real data worth keeping), but never
# count, score, report, or diff it as an open port.
STATE_OPEN = 'open'
STATE_UNCONFIRMED = 'open|filtered'
PARSED_STATES = (STATE_OPEN, STATE_UNCONFIRMED)


def state_is_open(state: str) -> bool:
    """True only for a confirmed-open port. 'open|filtered' is not open."""
    return state == STATE_OPEN


def port_dict_is_open(port: Dict[str, Any]) -> bool:
    """state_is_open for a serialized port dict (report JSON consumers)."""
    return state_is_open(str(port.get('state', '')))


def scan_args_are_discovery(scan_args: str) -> bool:
    """
    Whether an nmap command line was a ping sweep (-sn), i.e. probed no ports.

    Callers need this to tell "no open ports because none exist" apart from
    "no open ports because we never looked".
    """
    return bool(re.search(r"(^|\s)-sn(\s|$)", scan_args or ""))


@dataclass
class Vulnerability:
    """Represents a vulnerability finding from nmap scripts."""
    script_id: str
    output: str
    severity: str = "unknown"
    cve_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScriptResult:
    """Raw output of any nmap NSE script (vuln or informational)."""
    script_id: str
    output: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Port:
    """A port nmap reported as open or open|filtered. See STATE_OPEN above."""
    port: int
    protocol: str
    state: str
    service: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scripts: List[ScriptResult] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        """Confirmed open. Use this for anything user-facing or scored."""
        return state_is_open(self.state)

    @property
    def is_unconfirmed(self) -> bool:
        """No reply — nmap can't tell open from filtered. Not evidence of a service."""
        return self.state == STATE_UNCONFIRMED

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        d['scripts'] = [s.to_dict() for s in self.scripts]
        return d


@dataclass
class OSMatch:
    """Represents an OS detection match."""
    name: str
    accuracy: int
    os_family: str = ""
    os_gen: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Host:
    """Represents a scanned host with all findings."""
    ip: str
    status: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    ports: List[Port] = field(default_factory=list)
    os_matches: List[OSMatch] = field(default_factory=list)
    uptime: Optional[int] = None
    distance: Optional[int] = None
    host_scripts: List[ScriptResult] = field(default_factory=list)
    host_vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            'ip': self.ip,
            'status': self.status,
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'vendor': self.vendor,
            'ports': [p.to_dict() for p in self.ports],
            'os': self.os_matches[0].to_dict() if self.os_matches else None,
            'os_matches': [o.to_dict() for o in self.os_matches],
            'uptime': self.uptime,
            'distance': self.distance,
            'host_scripts': [s.to_dict() for s in self.host_scripts],
            'vulnerabilities': self._get_all_vulnerabilities()
        }
        return d

    def _get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Aggregate all vulnerabilities from all ports and host-level scripts."""
        vulns = []
        for port in self.ports:
            for vuln in port.vulnerabilities:
                vuln_dict = vuln.to_dict()
                vuln_dict['port'] = port.port
                vulns.append(vuln_dict)
        for vuln in self.host_vulnerabilities:
            vuln_dict = vuln.to_dict()
            vuln_dict['port'] = 0  # host-level (not tied to a single port)
            vulns.append(vuln_dict)
        return vulns


@dataclass
class ScanResult:
    """Represents the complete scan result."""
    hosts: List[Host]
    scan_start: str
    scan_end: str
    scan_args: str
    scanner_version: str
    total_hosts_up: int = 0
    total_hosts_down: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_metadata': {
                'timestamp': self.scan_start,
                'scan_end': self.scan_end,
                'scan_args': self.scan_args,
                'scanner_version': self.scanner_version,
                'total_hosts_up': self.total_hosts_up,
                'total_hosts_down': self.total_hosts_down
            },
            'hosts': [h.to_dict() for h in self.hosts]
        }


def parse_scripts(parent_elem: ET.Element) -> List[ScriptResult]:
    """Collect every NSE script result directly under a port or hostscript element."""
    scripts = []
    for script in parent_elem.findall('script'):
        script_id = script.get('id', '')
        output = script.get('output', '')
        if not script_id and not output:
            continue
        scripts.append(ScriptResult(script_id=script_id, output=output.strip()))
    return scripts


# How nmap scripts report a vulnerability. Its vulns library prints a state per
# finding - "VULNERABLE", "LIKELY VULNERABLE", "VULNERABLE (Exploitable)" - and
# "NOT VULNERABLE" for a clean check, which contains the word and means the
# opposite. Uppercase only: lowercase "vulnerable" turns up in prose such as
# "does not appear to be vulnerable".
_VULN_STATE_RE = re.compile(r"(?<!NOT )\bVULNERABLE\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
# "Risk factor: High" is how the vulns library states severity.
_RISK_FACTOR_RE = re.compile(r"Risk factor:\s*(Critical|High|Medium|Low)", re.IGNORECASE)
# CVSS scores as vulners prints them: "CVE-2016-10009  7.5  https://..."
_CVSS_RE = re.compile(r"CVE-\d{4}-\d+\s+(\d{1,2}\.\d)\b")


def _vulnerability_severity(output: str) -> str:
    """Severity of a script result already known to describe a vulnerability."""
    m = _RISK_FACTOR_RE.search(output)
    if m:
        return m.group(1).lower()

    scores = [float(x) for x in _CVSS_RE.findall(output)]
    if scores:
        worst = max(scores)
        if worst >= 9.0:
            return "critical"
        if worst >= 7.0:
            return "high"
        if worst >= 4.0:
            return "medium"
        return "low"

    # A script that says VULNERABLE without grading it: treat as high.
    return "high"


def extract_vulnerabilities(scripts: List[ScriptResult]) -> List[Vulnerability]:
    """
    Pick out the script results that actually report a vulnerability.

    Decided by what the script SAID, never by what it is called. Most scripts
    in nmap's vuln category print something even when the answer is "no"
    ("smb-vuln-ms10-054: false", "http-vuln-cve2017-1001000: ERROR: Script
    execution failed"), and ssl-cert / ssl-date / ssl-enum-ciphers are plain
    information that runs against every TLS port. Matching on a name prefix
    turned all of those into high-risk findings on any host with HTTPS or SMB.
    """
    vulnerabilities = []

    for script in scripts:
        output = script.output
        if output.lstrip().upper().startswith("ERROR"):
            continue

        cve_ids = sorted(set(_CVE_RE.findall(output)))
        flagged = bool(_VULN_STATE_RE.search(output))
        # CVE ids with no state line are a version-based match (vulners). CVE
        # ids next to "NOT VULNERABLE" are the script naming what it ruled out.
        if not flagged and not (cve_ids and "NOT VULNERABLE" not in output):
            continue

        vulnerabilities.append(Vulnerability(
            script_id=script.script_id,
            output=output,
            severity=_vulnerability_severity(output),
            cve_ids=cve_ids
        ))

    return vulnerabilities


def parse_port(port_elem: ET.Element) -> Optional[Port]:
    """Parse a single port element."""
    state_elem = port_elem.find('state')
    if state_elem is None:
        return None
    
    state = state_elem.get('state', 'unknown')
    
    # Keep open and open|filtered; drop closed/filtered. open|filtered is
    # retained as data but is NOT an open port — see STATE_UNCONFIRMED.
    if state not in PARSED_STATES:
        return None
    
    port_num = int(port_elem.get('portid', 0))
    protocol = port_elem.get('protocol', 'tcp')
    
    # Parse service info
    service_elem = port_elem.find('service')
    service = "unknown"
    product = ""
    version = ""
    extra_info = ""
    
    if service_elem is not None:
        service = service_elem.get('name', 'unknown')
        product = service_elem.get('product', '')
        version = service_elem.get('version', '')
        extra_info = service_elem.get('extrainfo', '')
    
    # Collect all NSE script output on this port, then pick out the vuln ones
    scripts = parse_scripts(port_elem)
    vulnerabilities = extract_vulnerabilities(scripts)

    return Port(
        port=port_num,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        extra_info=extra_info,
        vulnerabilities=vulnerabilities,
        scripts=scripts
    )


def parse_os_matches(host_elem: ET.Element) -> List[OSMatch]:
    """Parse OS detection results."""
    os_matches = []
    
    os_elem = host_elem.find('os')
    if os_elem is None:
        return os_matches
    
    for osmatch in os_elem.findall('osmatch'):
        name = osmatch.get('name', 'Unknown')
        accuracy = int(osmatch.get('accuracy', 0))
        
        # Get OS class info
        os_family = ""
        os_gen = ""
        osclass = osmatch.find('osclass')
        if osclass is not None:
            os_family = osclass.get('osfamily', '')
            os_gen = osclass.get('osgen', '')
        
        os_matches.append(OSMatch(
            name=name,
            accuracy=accuracy,
            os_family=os_family,
            os_gen=os_gen
        ))
    
    # Sort by accuracy descending
    os_matches.sort(key=lambda x: x.accuracy, reverse=True)
    
    return os_matches


def parse_host(host_elem: ET.Element) -> Optional[Host]:
    """Parse a single host element."""
    # Get host status
    status_elem = host_elem.find('status')
    if status_elem is None:
        return None
    
    status = status_elem.get('state', 'unknown')
    
    # Get IP address
    ip = ""
    mac = ""
    vendor = ""
    
    for addr in host_elem.findall('address'):
        addr_type = addr.get('addrtype', '')
        if addr_type in ('ipv4', 'ipv6'):
            ip = addr.get('addr', '')
        elif addr_type == 'mac':
            mac = addr.get('addr', '')
            vendor = addr.get('vendor', '')
    
    if not ip:
        return None
    
    # Get hostname
    hostname = ""
    hostnames_elem = host_elem.find('hostnames')
    if hostnames_elem is not None:
        hostname_elem = hostnames_elem.find('hostname')
        if hostname_elem is not None:
            hostname = hostname_elem.get('name', '')
    
    # Parse ports
    ports = []
    ports_elem = host_elem.find('ports')
    if ports_elem is not None:
        for port_elem in ports_elem.findall('port'):
            port = parse_port(port_elem)
            if port:
                ports.append(port)
    
    # Parse OS matches
    os_matches = parse_os_matches(host_elem)

    # Host-level scripts (nmap <hostscript>): smb-os-discovery, smb2-security-mode,
    # smb-vuln-*, etc. These are not attached to any single port.
    host_scripts = []
    host_vulnerabilities = []
    hostscript_elem = host_elem.find('hostscript')
    if hostscript_elem is not None:
        host_scripts = parse_scripts(hostscript_elem)
        host_vulnerabilities = extract_vulnerabilities(host_scripts)

    # Get uptime and distance
    uptime = None
    uptime_elem = host_elem.find('uptime')
    if uptime_elem is not None:
        try:
            uptime = int(uptime_elem.get('seconds', 0))
        except ValueError:
            pass
    
    distance = None
    distance_elem = host_elem.find('distance')
    if distance_elem is not None:
        try:
            distance = int(distance_elem.get('value', 0))
        except ValueError:
            pass
    
    return Host(
        ip=ip,
        status=status,
        hostname=hostname,
        mac_address=mac,
        vendor=vendor,
        ports=ports,
        os_matches=os_matches,
        uptime=uptime,
        distance=distance,
        host_scripts=host_scripts,
        host_vulnerabilities=host_vulnerabilities
    )


def nmap_run_error(xml_content: str) -> Optional[str]:
    """
    The fatal error nmap reported, or None if the run completed normally.

    When nmap quits early it still writes a well-formed XML document: an empty
    <nmaprun> whose runstats carry exit="error" and the reason in errormsg.
    That parses cleanly into a perfectly valid "0 hosts up" result, so a caller
    checking only the exit code and whether XML exists will present a scan that
    never ran as a clean scan with nothing to report. Check this before trusting
    parsed results.
    """
    if not xml_content:
        return None
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        # Truncated output means nmap died mid-write; the caller's own parse
        # will surface that with a better message than we can give here.
        return None

    finished = root.find('runstats/finished')
    if finished is None:
        return "nmap did not finish the scan (no run statistics were written)."
    if finished.get('exit') == 'error':
        return finished.get('errormsg') or "nmap exited with an error."
    return None


def salvage_partial_xml(xml_content: str) -> Optional[str]:
    """
    Close off the XML of a scan that was stopped mid-run so the hosts it had
    finished can still be parsed.

    nmap writes each host as it completes, so a killed scan leaves a document
    that is complete up to the last </host> and then cut off. Everything after
    that point is dropped and the root element closed. Returns None when no
    host was finished (nothing to salvage) or the input already parses.
    """
    if not xml_content:
        return None
    try:
        ET.fromstring(xml_content)
        return None  # complete already
    except ET.ParseError:
        pass
    cut = xml_content.rfind("</host>")
    if cut < 0:
        return None
    candidate = xml_content[:cut + len("</host>")] + "\n</nmaprun>\n"
    try:
        ET.fromstring(candidate)
    except ET.ParseError:
        return None
    return candidate


def _ip_sort_key(host: Host):
    """Numeric IP ordering; IPv4 before IPv6, unparseable addresses last."""
    try:
        ip = ipaddress.ip_address(host.ip)
        return (ip.version, int(ip))
    except ValueError:
        return (99, 0)


def parse_nmap_xml(xml_content: str) -> ScanResult:
    """
    Parse nmap XML output into structured data.
    
    Args:
        xml_content: Raw XML string from nmap -oX output
    
    Returns:
        ScanResult object containing all parsed data
    """
    root = ET.fromstring(xml_content)
    
    # Get scan metadata
    scan_args = root.get('args', '')
    scanner_version = root.get('version', '')
    scan_start = root.get('startstr', '')
    
    # Get scan end time
    scan_end = ""
    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        if finished is not None:
            scan_end = finished.get('timestr', '')
    
    # Parse hosts
    hosts = []
    total_up = 0
    total_down = 0
    
    for host_elem in root.findall('host'):
        host = parse_host(host_elem)
        if host:
            hosts.append(host)
            if host.status == 'up':
                total_up += 1
            else:
                total_down += 1

    # nmap writes hosts in scan-COMPLETION order: it scans hosts in parallel
    # batches and emits each one as its batch finishes, so on a subnet scan the
    # hosts with results end up clumped mid-list among the empty ones. Sort
    # numerically by IP so every consumer (GUI, CLI, JSON, diff) sees a stable,
    # human-expected order.
    hosts.sort(key=_ip_sort_key)

    return ScanResult(
        hosts=hosts,
        scan_start=scan_start,
        scan_end=scan_end,
        scan_args=scan_args,
        scanner_version=scanner_version,
        total_hosts_up=total_up,
        total_hosts_down=total_down
    )
