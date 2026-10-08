"""
JSON output formatter for CybX Insight.
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    from parser import ScanResult, port_dict_is_open
    from local_analyzer import ScanAnalysis
    from paths import claim_for_owner
except ImportError:
    from .parser import ScanResult, port_dict_is_open
    from .local_analyzer import ScanAnalysis
    from .paths import claim_for_owner


def _mkdir_owned(path: Path) -> None:
    """Create parent folders, handing any new ones to the real user."""
    missing = []
    probe = path.parent
    while not probe.exists() and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    path.parent.mkdir(parents=True, exist_ok=True)
    for folder in missing:
        claim_for_owner(folder)


# Integration tag the CybX Insight dashboard filters on when it pulls network
# scan events (see getNetworkEvents in the Insights project). Every event this
# scanner emits for ingestion MUST carry this exact value under `data.integration`,
# or Insights will never surface it.
NMAP_CHAT_INTEGRATION = "nmap_chat"

_FINDING_SEV_RE = re.compile(r"^\s*\[([A-Za-z]+)\]")
_FINDING_PORT_RE = re.compile(r"port\s+(\d+)", re.IGNORECASE)


def create_insights_report(
    scan_result: ScanResult,
    analysis: Optional[ScanAnalysis],
    target: str,
    scanner_version: str = "1.0.0",
    include_raw_nmap: bool = False,
    raw_xml: str = "",
    scan_type: str = "comprehensive"
) -> Dict[str, Any]:
    """
    Format scan results and analysis as the CybX Insight report JSON.

    Args:
        scan_result: Parsed nmap scan results
        analysis: Local rule-based analysis of the scan (optional)
        target: Original scan target specification
        scanner_version: Version of this scanner application
        include_raw_nmap: Whether to include raw nmap XML
        raw_xml: Raw nmap XML output
        scan_type: What kind of scan produced this. "discovery" marks a ping
            sweep, where every host legitimately has zero ports because none
            were probed. Recorded so a later diff can tell "no ports found"
            apart from "ports not looked at" instead of reporting every port on
            the network as newly closed.

    Returns:
        Dictionary ready for JSON serialization
    """
    # Build base output structure
    output = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_start": scan_result.scan_start,
            "scan_end": scan_result.scan_end,
            "target": target,
            "scan_type": scan_type,
            "scan_args": scan_result.scan_args,
            "scanner_version": scanner_version,
            "nmap_version": scan_result.scanner_version,
            "hosts_up": scan_result.total_hosts_up,
            "hosts_down": scan_result.total_hosts_down
        },
        "hosts": []
    }
    
    # Summary of the local rule-based analysis. Kept under the "ai_analysis_summary"
    # tag because the downstream reporter is wired to read that field.
    if analysis:
        output["ai_analysis_summary"] = {
            "overall_risk": analysis.overall_risk,
            "executive_summary": analysis.executive_summary,
            "network_observations": analysis.network_observations,
            "priority_actions": analysis.priority_actions
        }
    
    # Build host entries with the per-host rule-based analysis attached
    analysis_by_ip = {}
    if analysis:
        for host_analysis in analysis.host_analyses:
            analysis_by_ip[host_analysis.ip] = host_analysis.to_dict()
    
    for host in scan_result.hosts:
        host_dict = host.to_dict()
        
        # Per-host analysis, under the "ai_analysis" tag the reporter expects
        if host.ip in analysis_by_ip:
            host_dict["ai_analysis"] = analysis_by_ip[host.ip]
        else:
            host_dict["ai_analysis"] = None
        
        output["hosts"].append(host_dict)
    
    # Optionally include raw nmap output
    if include_raw_nmap and raw_xml:
        output["raw_nmap_xml"] = raw_xml
    
    return output


def write_json_output(
    output_data: Dict[str, Any],
    output_path: str,
    pretty: bool = True
) -> str:
    """
    Write JSON output to file.
    
    Args:
        output_data: Dictionary to serialize
        output_path: Path to output file
        pretty: Whether to format with indentation
    
    Returns:
        Absolute path to written file
    """
    path = Path(output_path)
    _mkdir_owned(path)

    with open(path, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        else:
            json.dump(output_data, f, ensure_ascii=False)
    # Written as root (sudo / the app's own elevation)? Then it belongs to
    # the user who ran the scan, not to root.
    claim_for_owner(path)

    return str(path.absolute())


def generate_filename(target: str, extension: str = "json") -> str:
    """
    Generate a filename based on target and timestamp.
    
    Args:
        target: Scan target (IP, subnet, etc.)
        extension: File extension
    
    Returns:
        Generated filename
    """
    # Sanitize target for filename. nmap accepts target specs Windows cannot
    # put in a file name ("192.168.1.*", "10.0.0.1, 10.0.0.9"), so anything
    # outside a safe set becomes "_" rather than failing the save after the
    # scan has already run.
    safe_target = target.strip().replace('.', '-')
    safe_target = re.sub(r'[^A-Za-z0-9_-]+', '_', safe_target).strip('_')[:80] or 'scan'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    return f"scan_{safe_target}_{timestamp}.{extension}"


def _port_severity_map(host_analysis: Optional[Any]) -> Dict[int, str]:
    """
    Derive a per-port risk level from a host's analysis findings.

    Findings are strings prefixed with a severity tag and (usually) a port
    number, e.g. "[CRITICAL] Port 445/tcp (microsoft-ds): SMB is exposed...".
    We map each referenced port to the highest severity seen for it. Findings
    with no port (e.g. OS end-of-life) are ignored here.
    """
    sev_map: Dict[int, str] = {}
    if not host_analysis or not getattr(host_analysis, "findings", None):
        return sev_map
    for finding in host_analysis.findings:
        sev_match = _FINDING_SEV_RE.match(finding)
        port_match = _FINDING_PORT_RE.search(finding)
        if not sev_match or not port_match:
            continue
        sev = sev_match.group(1).lower()
        if sev not in _RISK_LEVEL:
            continue
        port = int(port_match.group(1))
        if port not in sev_map or _RISK_LEVEL[sev] > _RISK_LEVEL[sev_map[port]]:
            sev_map[port] = sev
    return sev_map


def _findings_for_port(host_analysis: Optional[Any], port: int) -> List[str]:
    """Return the subset of a host's findings that reference the given port."""
    if not host_analysis or not getattr(host_analysis, "findings", None):
        return []
    out = []
    for finding in host_analysis.findings:
        m = _FINDING_PORT_RE.search(finding)
        if m and int(m.group(1)) == port:
            out.append(finding)
    return out


def create_nmap_chat_events(
    scan_result: ScanResult,
    analysis: Optional[ScanAnalysis],
    target: str,
    scanner_version: str = "1.0.0",
    analysis_source: str = "local",
    scan_type: str = "comprehensive",
) -> List[Dict[str, Any]]:
    """
    Build per-port events for ingestion into CybX Insight.

    The Insights dashboard queries for network events tagged
    `data.integration == "nmap_chat"` and reads one row per open port
    (see getNetworkEvents / NetworkEvent in the Insights project). Each dict
    returned here is one JSON log line: when the Insights collector reads the
    NDJSON file, these root keys land under `data.*`, so `integration`,
    `nmap.*` and `ai_assessment` become `data.integration`, `data.nmap.*` and
    `data.ai_assessment`.

    `agent.id` / `agent.name`, `rule.*` and the alert `timestamp` are added by
    the Insights collector — this scanner does not set them.

    Args:
        scan_result: Parsed nmap scan results.
        analysis: Rule-based or AI analysis for the same scan.
        target: Original scan target specification.
        scanner_version: Version of this scanner.
        analysis_source: provenance tag recorded on each event (default
            "local"). The scanner only produces local analysis; the field lets
            the reporter distinguish it from AI enrichment it adds downstream.
        scan_type: "discovery" for a ping sweep. Only changes the wording of the
            host-level event summary — a discovery scan must not report "no open
            ports detected", which reads as an all-clear it never checked for.
            Field names and structure are identical either way.

    Returns:
        A list of event dicts, one per open port (plus one host-level event for
        live hosts with no open ports).
    """
    analysis_by_ip: Dict[str, Any] = {}
    if analysis:
        for ha in analysis.host_analyses:
            analysis_by_ip[ha.ip] = ha

    scan_time = datetime.now(timezone.utc).isoformat()
    events: List[Dict[str, Any]] = []

    for host in scan_result.hosts:
        if host.status != "up":
            continue

        ha = analysis_by_ip.get(host.ip)
        os_guess = host.os_matches[0].name if host.os_matches else ""
        port_sev = _port_severity_map(ha)
        # Confirmed open only. An open|filtered port means nmap got no reply,
        # so emitting an event for it ships a service that was never observed
        # into Insights — one fake row per probed port per silent address.
        open_ports = [p for p in host.ports if p.is_open]

        def _base(risk: str) -> Dict[str, Any]:
            return {
                "integration": NMAP_CHAT_INTEGRATION,
                "scan": {
                    "target": target,
                    "scanner_version": scanner_version,
                    "scan_start": scan_result.scan_start,
                    "scan_end": scan_result.scan_end,
                    "scan_args": scan_result.scan_args,
                    "nmap_version": scan_result.scanner_version,
                    "time": scan_time,
                },
                "insights_level_hint": _risk_to_level(risk),
            }

        if not open_ports:
            risk = ha.risk_level if ha else "info"
            evt = _base(risk)
            evt["nmap"] = {
                "host": host.ip,
                "hostname": host.hostname or "",
                "os_guess": os_guess,
                "port": None,
                "protocol": "",
                "service": "",
                "risk": risk,
                "cve_ids": [],
                "nse_results": "",
            }
            if scan_type == "discovery":
                no_port_summary = "Host is alive (discovery scan — ports were not scanned)."
            else:
                no_port_summary = ha.summary if ha else "Host is up; no open ports detected."
            evt["ai_assessment"] = {
                "summary": no_port_summary,
                "risk_level": risk,
                "findings": ha.findings if ha else [],
                "recommendations": ha.recommendations if ha else [],
                "source": analysis_source,
            }
            events.append(evt)
            continue

        for port in open_ports:
            risk = port_sev.get(port.port, "info")
            cve_ids = sorted({cve for v in port.vulnerabilities for cve in v.cve_ids})
            # Include ALL script output (ssl-cert, http-title, smb signing, ...),
            # not just vuln scripts, so the reporter has full service context.
            nse_results = "\n".join(
                f"{s.script_id}: {s.output}".strip() for s in port.scripts
            )
            port_findings = _findings_for_port(ha, port.port)
            if port_findings:
                summary = "; ".join(_FINDING_SEV_RE.sub("", f).strip() for f in port_findings)
            else:
                svc = port.service or "service"
                summary = f"{svc} on {port.port}/{port.protocol} — no rule match; manual review recommended."

            evt = _base(risk)
            evt["nmap"] = {
                "host": host.ip,
                "hostname": host.hostname or "",
                "os_guess": os_guess,
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "product": port.product or "",
                "version": port.version or "",
                "state": port.state,
                "risk": risk,
                "cve_ids": cve_ids,
                "nse_results": nse_results,
            }
            evt["ai_assessment"] = {
                "summary": summary,
                "risk_level": risk,
                "findings": port_findings,
                "recommendations": ha.recommendations if ha else [],
                "source": analysis_source,
            }
            events.append(evt)

    return events


def write_ndjson_events(events: List[Dict[str, Any]], output_path: str, append: bool = False) -> str:
    """
    Write events as newline-delimited JSON (one compact object per line).

    NDJSON is what the Insights collector expects: it reads one JSON object per
    line. A pretty-printed multi-line document would fail to decode, so these are
    written compact, one per line.

    Args:
        events: Event dicts from create_nmap_chat_events().
        output_path: Destination file.
        append: When True, append lines instead of overwriting. Use this for a
            fixed file that the Insights collector tails, so previously-shipped
            lines are preserved. Use False (default) for a fresh per-scan file.

    Returns the absolute path written.
    """
    path = Path(output_path)
    _mkdir_owned(path)
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as f:
        for evt in events:
            f.write(json.dumps(evt, ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
    claim_for_owner(path)
    return str(path.absolute())


# Risk-level names ranked low->high, and the mapping to a numeric alert level
# used as a hint on each event (the Insights nmap_chat rule sets the
# authoritative level on the collector side).
_RISK_LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 0}


def _risk_to_level(risk: str) -> int:
    """Convert a risk level string to the Insights numeric alert level."""
    risk_map = {
        "critical": 15,
        "high": 12,
        "medium": 8,
        "low": 4,
        "info": 2,
        "unknown": 3
    }
    return risk_map.get(risk.lower(), 3)


def print_summary(output_data: Dict[str, Any]) -> None:
    """
    Print a human-readable summary of the scan results.
    
    Args:
        output_data: Complete output data dictionary
    """
    metadata = output_data.get('scan_metadata', {})
    hosts = output_data.get('hosts', [])
    ai_summary = output_data.get('ai_analysis_summary', {})
    
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Target: {metadata.get('target', 'N/A')}")
    print(f"Scan completed: {metadata.get('scan_end', 'N/A')}")
    print(f"Hosts up: {metadata.get('hosts_up', 0)}")
    print(f"Hosts down: {metadata.get('hosts_down', 0)}")
    
    if ai_summary:
        print(f"\nOverall Risk: {ai_summary.get('overall_risk', 'N/A').upper()}")
        print(f"\nExecutive Summary:")
        print(f"  {ai_summary.get('executive_summary', 'N/A')}")
        
        if ai_summary.get('priority_actions'):
            print(f"\nPriority Actions:")
            for i, action in enumerate(ai_summary['priority_actions'][:5], 1):
                print(f"  {i}. {action}")
    
    print("\nHosts Scanned:")
    for host in hosts:
        ip = host.get('ip', 'N/A')
        hostname = host.get('hostname', '')
        all_ports = host.get('ports', [])
        ports = [p for p in all_ports if port_dict_is_open(p)]
        unconfirmed = len(all_ports) - len(ports)
        vulns = host.get('vulnerabilities', [])
        ai = host.get('ai_analysis', {})

        host_str = f"  • {ip}"
        if hostname:
            host_str += f" ({hostname})"
        host_str += f" - {len(ports)} open ports"
        if unconfirmed:
            host_str += f" ({unconfirmed} no-reply)"
        if vulns:
            host_str += f", {len(vulns)} vulnerabilities"
        if ai:
            host_str += f" [Risk: {ai.get('risk_level', 'N/A').upper()}]"
        
        print(host_str)
    
    print("="*60 + "\n")
