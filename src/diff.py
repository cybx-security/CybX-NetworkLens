"""
Scan-to-scan comparison: "what changed since the last scan?"

Operates on the report dicts written by create_insights_report (i.e. the saved
JSON files), so any two saved reports can be compared without re-running or
re-parsing anything. Host identity is the IP address; port identity is
(port, protocol) — hostnames and DHCP-churned MACs are too unstable to key on.

For recurring audits of the same network, the diff is the finding that matters:
a port that opened since last month is a stronger signal than the same port
observed twice.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from parser import port_dict_is_open, scan_args_are_discovery
except ImportError:
    from .parser import port_dict_is_open, scan_args_are_discovery


def is_discovery_report(report: Dict[str, Any]) -> bool:
    """
    Whether a report came from a ping sweep rather than a port scan.

    Matters because a discovery report has zero ports for every host — not
    because they were closed, but because nothing was probed. Comparing one
    against a full scan would otherwise report every open port on the network as
    newly closed, which reads as "someone fixed everything" rather than "we
    didn't look". Falls back to the nmap args for reports written before
    scan_type was recorded.
    """
    meta = report.get("scan_metadata", {})
    if meta.get("scan_type") == "discovery":
        return True
    args = meta.get("scan_args") or ""
    return bool(re.search(r"(^|\s)-sn(\s|$)", args))


def _up_hosts(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Map ip -> host dict for hosts that were up in a report."""
    hosts = {}
    for host in report.get("hosts", []):
        # Reports only carry hosts nmap saw; missing status counts as up.
        if host.get("status", "up") == "up" and host.get("ip"):
            hosts[host["ip"]] = host
    return hosts


def _open_ports(host: Dict[str, Any]) -> Dict[Tuple[int, str], Dict[str, Any]]:
    """
    Map (port, protocol) -> port dict for confirmed-open ports on a host.

    open|filtered is excluded: it means nmap got no reply, so it flips between
    scans purely on timing and would otherwise generate a stream of phantom
    "opened"/"closed" changes that bury the real ones.
    """
    out = {}
    for p in host.get("ports", []):
        if port_dict_is_open(p):
            out[(p.get("port"), p.get("protocol", "tcp"))] = p
    return out


def _service_label(p: Dict[str, Any]) -> str:
    """Human-readable service string for a port dict, e.g. 'http nginx 1.18.0'."""
    return " ".join(x for x in (p.get("service", ""), p.get("product", ""),
                                p.get("version", "")) if x)


def _risk_of(host: Dict[str, Any]) -> str:
    ai = host.get("ai_analysis") or {}
    return (ai.get("risk_level") or "info").lower()


def _ip_sort_key(ip: str):
    """Sort IPs numerically, falling back to string order for hostnames."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return (0, addr.version, int(addr))
    except ValueError:
        return (1, 0, ip)


def _port_entry(key: Tuple[int, str], p: Dict[str, Any]) -> Dict[str, Any]:
    return {"port": key[0], "protocol": key[1], "service": _service_label(p)}


def diff_reports(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two scan reports and return a structured diff.

    Returns a dict with:
      previous / current: {timestamp, target} of each report
      target_mismatch: True when the two scans covered different target specs
          (the diff still runs, but "new"/"missing" mostly reflects scan scope)
      new_hosts: hosts up now that weren't up before, with their open ports
      missing_hosts: hosts up before that didn't respond now
      changed_hosts: hosts present in both with any of: newly opened ports,
          closed ports, changed services on a still-open port, or a changed
          risk level
      has_changes: False when the network looks identical to last time
    """
    prev_meta = previous.get("scan_metadata", {})
    curr_meta = current.get("scan_metadata", {})
    prev_hosts = _up_hosts(previous)
    curr_hosts = _up_hosts(current)

    # With a ping sweep on either side there is no port data to compare, only
    # host presence. Reporting ports here would invent findings.
    prev_discovery = is_discovery_report(previous)
    curr_discovery = is_discovery_report(current)
    ports_comparable = not (prev_discovery or curr_discovery)
    if prev_discovery and curr_discovery:
        skip_reason = "both scans were discovery-only (ping sweeps), so only host presence is compared."
    elif prev_discovery:
        skip_reason = "the previous scan was discovery-only (a ping sweep), so it has no port data to compare against."
    elif curr_discovery:
        skip_reason = "this scan was discovery-only (a ping sweep), so no ports were probed."
    else:
        skip_reason = ""

    new_hosts = []
    for ip in sorted(set(curr_hosts) - set(prev_hosts), key=_ip_sort_key):
        host = curr_hosts[ip]
        ports = _open_ports(host)
        new_hosts.append({
            "ip": ip,
            "hostname": host.get("hostname", ""),
            "risk": _risk_of(host),
            "ports": [_port_entry(k, p) for k, p in sorted(ports.items())] if ports_comparable else [],
        })

    missing_hosts = []
    for ip in sorted(set(prev_hosts) - set(curr_hosts), key=_ip_sort_key):
        host = prev_hosts[ip]
        missing_hosts.append({
            "ip": ip,
            "hostname": host.get("hostname", ""),
            "ports": ([_port_entry(k, p) for k, p in sorted(_open_ports(host).items())]
                      if ports_comparable else []),
        })

    changed_hosts = []
    for ip in (sorted(set(prev_hosts) & set(curr_hosts), key=_ip_sort_key) if ports_comparable else []):
        before, after = prev_hosts[ip], curr_hosts[ip]
        ports_before, ports_after = _open_ports(before), _open_ports(after)

        opened = [_port_entry(k, ports_after[k])
                  for k in sorted(set(ports_after) - set(ports_before))]
        closed = [_port_entry(k, ports_before[k])
                  for k in sorted(set(ports_before) - set(ports_after))]

        changed_services = []
        for k in sorted(set(ports_before) & set(ports_after)):
            old_label = _service_label(ports_before[k])
            new_label = _service_label(ports_after[k])
            if old_label != new_label:
                changed_services.append({
                    "port": k[0], "protocol": k[1],
                    "before": old_label, "after": new_label,
                })

        risk_before, risk_after = _risk_of(before), _risk_of(after)
        risk_changed = risk_before != risk_after

        if opened or closed or changed_services or risk_changed:
            changed_hosts.append({
                "ip": ip,
                "hostname": after.get("hostname", "") or before.get("hostname", ""),
                "opened_ports": opened,
                "closed_ports": closed,
                "changed_services": changed_services,
                "risk_before": risk_before,
                "risk_after": risk_after,
            })

    prev_target = prev_meta.get("target", "")
    curr_target = curr_meta.get("target", "")
    return {
        "previous": {"timestamp": prev_meta.get("timestamp", ""), "target": prev_target,
                     "discovery_only": prev_discovery},
        "current": {"timestamp": curr_meta.get("timestamp", ""), "target": curr_target,
                    "discovery_only": curr_discovery},
        "ports_compared": ports_comparable,
        "ports_skipped_reason": skip_reason,
        "target_mismatch": bool(prev_target and curr_target and prev_target != curr_target),
        "new_hosts": new_hosts,
        "missing_hosts": missing_hosts,
        "changed_hosts": changed_hosts,
        "has_changes": bool(new_hosts or missing_hosts or changed_hosts),
    }


def format_diff_lines(diff: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Render a diff as (line, tag) pairs so the CLI and GUI share one renderer.

    Tags: "header", "add" (new host/port — needs attention), "remove"
    (disappeared), "change" (service/risk changed), "ok", "info".
    """
    lines: List[Tuple[str, str]] = []

    prev_ts = diff["previous"]["timestamp"] or "unknown time"
    curr_ts = diff["current"]["timestamp"] or "unknown time"
    lines.append((f"Comparing against previous scan from {prev_ts}", "header"))
    lines.append((f"Current scan: {curr_ts}", "info"))
    if diff.get("target_mismatch"):
        lines.append((f"NOTE: the scans covered different targets "
                      f"({diff['previous']['target']} vs {diff['current']['target']}) — "
                      f"new/missing hosts may just reflect the different scope.", "change"))
    if not diff.get("ports_compared", True):
        lines.append((f"NOTE: ports were NOT compared — {diff.get('ports_skipped_reason', '')}",
                      "change"))
    lines.append(("", "info"))

    if not diff["has_changes"]:
        if diff.get("ports_compared", True):
            lines.append(("No changes: same hosts, same open ports, same services as the previous scan.", "ok"))
        else:
            lines.append(("No changes in which hosts are alive. Ports were not compared "
                          "(see the note above).", "ok"))
        return lines

    if diff["new_hosts"]:
        lines.append((f"NEW HOSTS ({len(diff['new_hosts'])}) — not seen in the previous scan:", "header"))
        for h in diff["new_hosts"]:
            name = f" ({h['hostname']})" if h["hostname"] else ""
            risk = f"  [risk: {h['risk'].upper()}]" if h.get("risk") else ""
            lines.append((f"  + {h['ip']}{name}{risk}", "add"))
            for p in h["ports"]:
                svc = f" — {p['service']}" if p["service"] else ""
                lines.append((f"      + {p['port']}/{p['protocol']}{svc}", "add"))
        lines.append(("", "info"))

    if diff["missing_hosts"]:
        lines.append((f"MISSING HOSTS ({len(diff['missing_hosts'])}) — up last time, not responding now:", "header"))
        for h in diff["missing_hosts"]:
            name = f" ({h['hostname']})" if h["hostname"] else ""
            ports = ", ".join(f"{p['port']}/{p['protocol']}" for p in h["ports"])
            detail = f" (had: {ports})" if ports else ""
            lines.append((f"  - {h['ip']}{name}{detail}", "remove"))
        lines.append(("", "info"))

    if diff["changed_hosts"]:
        lines.append((f"CHANGED HOSTS ({len(diff['changed_hosts'])}):", "header"))
        for h in diff["changed_hosts"]:
            name = f" ({h['hostname']})" if h["hostname"] else ""
            lines.append((f"  ~ {h['ip']}{name}", "change"))
            if h["risk_before"] != h["risk_after"]:
                lines.append((f"      risk: {h['risk_before'].upper()} -> {h['risk_after'].upper()}", "change"))
            for p in h["opened_ports"]:
                svc = f" — {p['service']}" if p["service"] else ""
                lines.append((f"      + opened {p['port']}/{p['protocol']}{svc}", "add"))
            for p in h["closed_ports"]:
                svc = f" — was {p['service']}" if p["service"] else ""
                lines.append((f"      - closed {p['port']}/{p['protocol']}{svc}", "remove"))
            for c in h["changed_services"]:
                lines.append((f"      ~ {c['port']}/{c['protocol']}: "
                              f"{c['before'] or '(unidentified)'} -> {c['after'] or '(unidentified)'}", "change"))

    return lines


def format_diff_text(diff: Dict[str, Any]) -> str:
    """Plain-text rendering of a diff, for CLI output."""
    return "\n".join(line for line, _tag in format_diff_lines(diff))


def load_report(path: str) -> Dict[str, Any]:
    """
    Load and sanity-check a saved report JSON.

    Raises ValueError with a readable message when the file isn't one of our
    scan reports, so callers can show it to the user directly.
    """
    import json
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        raise ValueError(f"Report file not found: {path}")
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Not valid JSON: {path} ({e})")
    if not isinstance(data, dict) or "hosts" not in data or "scan_metadata" not in data:
        raise ValueError(f"Not a CybX scan report (missing scan_metadata/hosts): {path}")
    return data
