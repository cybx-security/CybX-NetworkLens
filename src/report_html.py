"""
A report people can hand over: one self-contained HTML file.

The JSON report is for machines and the NDJSON for Insights; this is for the
customer meeting - executive summary, a risk table, and every host's findings
and recommendations, with print styling so "Print > Save as PDF" in any
browser gives a PDF. No external assets, so the file can be emailed as is.
"""

import html
from datetime import datetime
from typing import Any, Dict, List

try:
    from parser import port_dict_is_open
    from version import __version__
except ImportError:
    from .parser import port_dict_is_open
    from .version import __version__


RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
RISK_COLORS = {"critical": "#b00020", "high": "#c65102", "medium": "#9a7400",
               "low": "#1c7c3b", "info": "#4a5568", "unknown": "#4a5568"}

_CSS = """
body { font: 14px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1a202c;
       margin: 0; padding: 32px; max-width: 1000px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 32px 0 8px; border-bottom: 2px solid #e2e8f0; padding-bottom: 4px; }
h3 { font-size: 16px; margin: 20px 0 6px; }
.meta { color: #4a5568; margin-bottom: 20px; } .meta span { margin-right: 18px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-weight: 600; font-size: 12px; letter-spacing: .03em; }
.summary { background: #f7fafc; border-left: 4px solid #2b6cb0; padding: 12px 16px; margin: 12px 0; }
.quality { background: #fff5f5; border-left: 4px solid #b00020; padding: 12px 16px; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
th { background: #edf2f7; } tr.hidden-row { display: none; }
ul { margin: 4px 0 8px 20px; } li { margin: 2px 0; }
.host { page-break-inside: avoid; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; margin: 12px 0; }
.muted { color: #718096; } .finding { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
.footer { margin-top: 40px; color: #718096; font-size: 12px; border-top: 1px solid #e2e8f0; padding-top: 8px; }
@media print { body { padding: 0; } .host { break-inside: avoid; } h2 { break-after: avoid; } }
"""


def _badge(risk: str) -> str:
    risk = (risk or "info").lower()
    return f'<span class="badge" style="background:{RISK_COLORS.get(risk, "#4a5568")}">{html.escape(risk.upper())}</span>'


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def render_report(report: Dict[str, Any], title: str = "Network Scan Report") -> str:
    """The complete HTML document for a report dict (the saved JSON's content)."""
    meta = report.get("scan_metadata", {})
    summary = report.get("ai_analysis_summary", {}) or {}
    hosts: List[Dict[str, Any]] = [h for h in report.get("hosts", []) if (h.get("status") or "up") == "up"]
    hosts.sort(key=lambda h: RISK_ORDER.get(((h.get("ai_analysis") or {}).get("risk_level") or "info").lower(), 9))
    overall = (summary.get("overall_risk") or "info").lower()
    quality = [o for o in summary.get("network_observations", []) if str(o).startswith("SCAN QUALITY")]
    observations = [o for o in summary.get("network_observations", []) if not str(o).startswith("SCAN QUALITY")]
    discovery = meta.get("scan_type") == "discovery"

    counts: Dict[str, int] = {}
    for h in hosts:
        r = ((h.get("ai_analysis") or {}).get("risk_level") or "info").lower()
        counts[r] = counts.get(r, 0) + 1

    out = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{_esc(title)}</title><style>{_CSS}</style></head><body>"]
    out.append(f"<h1>{_esc(title)}</h1>")
    out.append("<div class='meta'>"
               f"<span><b>Target:</b> {_esc(meta.get('target'))}</span>"
               f"<span><b>Scanned:</b> {_esc(meta.get('scan_start') or meta.get('timestamp'))}</span>"
               f"<span><b>Mode:</b> {'Discovery (hosts only)' if discovery else 'Full / Quick'}</span>"
               f"<span><b>Hosts up:</b> {_esc(meta.get('hosts_up', 0))}</span>"
               f"<span><b>Overall risk:</b> {_badge(overall)}</span>"
               + ("<span><b>PARTIAL SCAN</b> - stopped before it finished</span>" if meta.get("partial") else "")
               + "</div>")

    for q in quality:
        out.append(f"<div class='quality'><b>Scan quality warning:</b> {_esc(q[len('SCAN QUALITY:'):].strip())}</div>")

    out.append("<h2>Executive summary</h2>")
    out.append(f"<div class='summary'>{_esc(summary.get('executive_summary') or 'No analysis available.')}</div>")
    if counts:
        out.append("<p>" + " &nbsp; ".join(f"{_badge(r)} {counts[r]} host(s)" for r in sorted(counts, key=lambda k: RISK_ORDER.get(k, 9))) + "</p>")
    if summary.get("priority_actions"):
        out.append("<h3>Priority actions</h3><ol>" + "".join(f"<li>{_esc(a)}</li>" for a in summary["priority_actions"]) + "</ol>")
    if observations:
        out.append("<h3>Network observations</h3><ul>" + "".join(f"<li>{_esc(o)}</li>" for o in observations) + "</ul>")

    changes = report.get("changes_since_previous")
    if changes:
        out.append("<h2>Changes since the previous scan</h2>")
        out.append(f"<p class='muted'>Compared with the scan from {_esc(changes.get('previous', {}).get('timestamp'))}.</p>")
        if not changes.get("has_changes"):
            out.append("<p>No changes: same hosts, same open ports, same services.</p>")
        else:
            for label, key in (("New hosts", "new_hosts"), ("Missing hosts", "missing_hosts")):
                items = changes.get(key) or []
                if items:
                    out.append(f"<h3>{label} ({len(items)})</h3><ul>" + "".join(
                        f"<li>{_esc(h.get('ip'))}{' (' + _esc(h.get('hostname')) + ')' if h.get('hostname') else ''}</li>" for h in items) + "</ul>")
            changed = changes.get("changed_hosts") or []
            if changed:
                out.append(f"<h3>Changed hosts ({len(changed)})</h3><ul>")
                for h in changed:
                    bits = []
                    bits += [f"opened {p['port']}/{p['protocol']}" for p in h.get("opened_ports", [])]
                    bits += [f"closed {p['port']}/{p['protocol']}" for p in h.get("closed_ports", [])]
                    bits += [f"{c['port']}/{c['protocol']}: {c['before'] or '?'} → {c['after'] or '?'}" for c in h.get("changed_services", [])]
                    if h.get("risk_before") != h.get("risk_after"):
                        bits.append(f"risk {str(h.get('risk_before')).upper()} → {str(h.get('risk_after')).upper()}")
                    out.append(f"<li><b>{_esc(h.get('ip'))}</b>: {_esc('; '.join(bits))}</li>")
                out.append("</ul>")

    out.append("<h2>Device inventory</h2>")
    out.append("<table><tr><th>IP address</th><th>Hostname</th><th>Risk</th><th>Open ports</th><th>OS guess</th><th>MAC / vendor</th></tr>")
    for h in hosts:
        ai = h.get("ai_analysis") or {}
        ports = [p for p in h.get("ports", []) if port_dict_is_open(p)]
        port_text = ", ".join(f"{p.get('port')}/{p.get('protocol', 'tcp')}" + (f" {p.get('service')}" if p.get("service") and p.get("service") != "unknown" else "") for p in ports)
        if discovery:
            port_text = "<span class='muted'>not scanned</span>"
        os_name = (h.get("os") or {}).get("name", "")
        mac = h.get("mac_address", "")
        if mac and h.get("vendor"):
            mac += f" ({h['vendor']})"
        out.append(f"<tr><td>{_esc(h.get('ip'))}</td><td>{_esc(h.get('hostname'))}</td><td>{_badge(ai.get('risk_level') or 'info')}</td>"
                   f"<td>{port_text if discovery else _esc(port_text) or '<span class=muted>none</span>'}</td><td>{_esc(os_name)}</td><td>{_esc(mac)}</td></tr>")
    out.append("</table>")

    if not discovery:
        out.append("<h2>Findings by host</h2>")
        any_findings = False
        for h in hosts:
            ai = h.get("ai_analysis") or {}
            findings = ai.get("findings") or []
            recs = ai.get("recommendations") or []
            vulns = h.get("vulnerabilities") or []
            if not (findings or vulns):
                continue
            any_findings = True
            name = h.get("ip", "?") + (f" ({h['hostname']})" if h.get("hostname") else "")
            out.append(f"<div class='host'><h3>{_esc(name)} {_badge(ai.get('risk_level') or 'info')}</h3>")
            out.append(f"<p class='muted'>{_esc(ai.get('summary'))}</p>")
            if findings:
                out.append("<b>Findings</b><ul>" + "".join(f"<li class='finding'>{_esc(f)}</li>" for f in findings) + "</ul>")
            if vulns:
                out.append("<b>nmap vulnerability scripts</b><ul>" + "".join(
                    f"<li class='finding'>{_esc(v.get('script_id'))} on port {_esc(v.get('port'))}: "
                    f"{_esc(', '.join(v.get('cve_ids') or []) or v.get('severity'))}</li>" for v in vulns) + "</ul>")
            if recs:
                out.append("<b>Recommendations</b><ul>" + "".join(f"<li>{_esc(r)}</li>" for r in recs) + "</ul>")
            out.append("</div>")
        if not any_findings:
            out.append("<p>No findings were raised by the rule engine or nmap's vulnerability scripts.</p>")

    out.append(f"<div class='footer'>Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} by CybX NetworkLens {_esc(__version__)} "
               f"(nmap {_esc(meta.get('nmap_version'))}). Findings come from an offline rule engine and nmap scripts; "
               "they indicate exposure, not confirmed compromise. Verify before acting.</div>")
    out.append("</body></html>")
    return "\n".join(out)


def write_html_report(report: Dict[str, Any], path: str, title: str = "Network Scan Report") -> str:
    from pathlib import Path
    try:
        from paths import claim_for_owner
    except ImportError:
        from .paths import claim_for_owner
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_report(report, title), encoding="utf-8")
    claim_for_owner(p)
    return str(p.absolute())
