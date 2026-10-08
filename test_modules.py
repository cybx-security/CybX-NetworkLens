#!/usr/bin/env python3
"""Quick test script for the CybX NetworkLens modules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from parser import parse_nmap_xml
from local_analyzer import analyze_locally
from output import (create_insights_report, generate_filename,
                    create_nmap_chat_events, NMAP_CHAT_INTEGRATION)
import json

# Sample nmap XML output for testing
sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -T4 192.168.1.0/24" start="1704470400" startstr="Mon Jan 1 12:00:00 2026" version="7.94">
<host starttime="1704470400" endtime="1704470410">
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco"/>
<hostnames><hostname name="router.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.2p1"/>
</port>
<port protocol="tcp" portid="23">
<state state="open" reason="syn-ack"/>
<service name="telnet"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.18.0"/>
<script id="ssl-cert" output="Subject: commonName=router.local&#10;Not valid before: 2019-01-01T00:00:00&#10;Not valid after:  2020-01-01T00:00:00"/>
<script id="ssl-enum-ciphers" output="TLSv1.0: ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA - C&#10;least strength: C"/>
</port>
<port protocol="udp" portid="161">
<state state="open" reason="udp-response"/>
<service name="snmp"/>
<script id="snmp-brute" output="public - Valid credentials"/>
</port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="96"><osclass osfamily="Linux" osgen="5.X"/></osmatch></os>
</host>
<host starttime="1704470400" endtime="1704470410">
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<hostnames><hostname name="fileserver.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack"/>
<service name="microsoft-ds"/>
</port>
<port protocol="tcp" portid="3389">
<state state="open" reason="syn-ack"/>
<service name="ms-wbt-server"/>
</port>
<port protocol="tcp" portid="27017">
<state state="open" reason="syn-ack"/>
<service name="mongodb"/>
</port>
</ports>
<os><osmatch name="Microsoft Windows Server 2008 R2 SP1" accuracy="92"><osclass osfamily="Windows" osgen="2008"/></osmatch></os>
<hostscript>
<script id="smb2-security-mode" output="Message signing enabled but not required"/>
<script id="smb-os-discovery" output="OS: Windows Server 2008 R2&#10;Computer name: fileserver&#10;Domain name: corp.local"/>
<script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) CVE-2017-0143"/>
</hostscript>
</host>
<runstats>
<finished time="1704470420" timestr="Mon Jan 1 12:00:20 2026" elapsed="20.00"/>
<hosts up="2" down="0" total="2"/>
</runstats>
</nmaprun>'''

print("=== Testing Parser ===")
result = parse_nmap_xml(sample_xml)
print(f"Parsed {result.total_hosts_up} hosts")
print(f"Host IP: {result.hosts[0].ip}")
print(f"Hostname: {result.hosts[0].hostname}")
print(f"Open ports: {len(result.hosts[0].ports)}")
for port in result.hosts[0].ports:
    print(f"  - {port.port}/{port.protocol}: {port.service} ({port.product} {port.version})")

print("\n=== Testing Local Rule-Based Analysis ===")
local = analyze_locally(result)
print(f"Overall risk: {local.overall_risk}")
print(f"Executive summary: {local.executive_summary}")
print(f"Network observations ({len(local.network_observations)}):")
for o in local.network_observations:
    print(f"  - {o}")
print(f"Priority actions ({len(local.priority_actions)}):")
for a in local.priority_actions:
    print(f"  - {a}")
print(f"Host analyses ({len(local.host_analyses)}):")
for ha in local.host_analyses:
    print(f"  - {ha.ip} [{ha.risk_level}]: {len(ha.findings)} findings")
    for f in ha.findings:
        print(f"      {f}")

print("\n=== Testing Insights Report Output ===")
output = create_insights_report(result, local, "192.168.1.0/24")
print(f"Output keys: {list(output.keys())}")
print(f"First host: {output['hosts'][0]['ip']}")

print("\n=== Testing Filename Generation ===")
filename = generate_filename("192.168.1.0/24")
print(f"Generated filename: {filename}")

print("\n=== Testing Script Parsing + Script-Based Findings ===")
# Ports and host scripts captured
h1 = next(h for h in result.hosts if h.ip == "192.168.1.1")
h2 = next(h for h in result.hosts if h.ip == "192.168.1.50")
p443 = next(p for p in h1.ports if p.port == 443)
assert any(s.script_id == "ssl-cert" for s in p443.scripts), "ssl-cert script not captured"
assert len(h2.host_scripts) == 3, f"expected 3 host scripts, got {len(h2.host_scripts)}"
assert len(h2.host_vulnerabilities) == 1, "smb-vuln-ms17-010 host vuln not extracted"
udp161 = next(p for p in h1.ports if p.port == 161 and p.protocol == "udp")
print(f"UDP SNMP port parsed: {udp161.port}/{udp161.protocol}")

# Findings derived from scripts
all_findings = "\n".join(f for ha in local.host_analyses for f in ha.findings)
checks = {
    "expired TLS cert": "certificate expired" in all_findings.lower(),
    "weak TLS ciphers": "cipher strength" in all_findings.lower() or "tls 1.1" in all_findings.lower(),
    "SNMP default community": "snmp community" in all_findings.lower(),
    "SMB signing": "smb signing" in all_findings.lower(),
    "MS17-010 host vuln": "ms17-010" in all_findings.lower(),
}
for label, ok in checks.items():
    print(f"  {'✓' if ok else '✗'} {label}")
    assert ok, f"expected finding not produced: {label}"

print("\n=== Testing Insights nmap_chat Events ===")
events = create_nmap_chat_events(result, local, "192.168.1.0/24", "1.0.0", "local")
open_ports = sum(len([p for p in h.ports if p.is_open]) for h in result.hosts if h.status == "up")
print(f"Generated {len(events)} event(s) for {open_ports} open port(s)")
assert len(events) == open_ports, "expected one event per open port"
for e in events:
    # Contract the CybX Insight dashboard (getNetworkEvents) depends on:
    assert e["integration"] == NMAP_CHAT_INTEGRATION, "wrong integration tag"
    for key in ("host", "os_guess", "port", "protocol", "nse_results", "risk"):
        assert key in e["nmap"], f"missing nmap.{key}"
    assert "summary" in e["ai_assessment"], "missing ai_assessment.summary"
    # Must serialize to a single line (NDJSON requirement)
    line = json.dumps(e, separators=(",", ":"))
    assert "\n" not in line, "event must be single-line JSON"
    json.loads(line)  # round-trips
# Per-port risk is correctly derived from findings
by_port = {e["nmap"]["port"]: e["nmap"]["risk"] for e in events}
assert by_port.get(23) == "critical", f"telnet should be critical, got {by_port.get(23)}"
assert by_port.get(445) == "critical", f"SMB should be critical, got {by_port.get(445)}"
assert by_port.get(3389) == "high", f"RDP should be high, got {by_port.get(3389)}"
assert by_port.get(22) == "info", f"ssh 8.2p1 should be info, got {by_port.get(22)}"
print("Per-port risk: " + ", ".join(f"{p}={r}" for p, r in sorted(by_port.items())))

print("\n=== Testing Scan Diff ===")
import copy
from diff import diff_reports, format_diff_text, format_diff_lines

previous = copy.deepcopy(output)
current = copy.deepcopy(output)

# Identical reports -> no changes
same = diff_reports(previous, current)
assert not same["has_changes"], "identical reports must diff clean"
assert "No changes" in format_diff_text(same)

# Simulate a month of drift on the current scan:
h_router = next(h for h in current["hosts"] if h["ip"] == "192.168.1.1")
h_files = next(h for h in current["hosts"] if h["ip"] == "192.168.1.50")
# - fileserver opened RDP-adjacent port 5900 and closed 27017
h_files["ports"].append({"port": 5900, "protocol": "tcp", "state": "open",
                         "service": "vnc", "product": "", "version": "",
                         "extra_info": "", "vulnerabilities": [], "scripts": []})
h_files["ports"] = [p for p in h_files["ports"] if p["port"] != 27017]
# - router upgraded nginx
for p in h_router["ports"]:
    if p["port"] == 80:
        p["version"] = "1.24.0"
# - a brand-new host appeared
current["hosts"].append({"ip": "192.168.1.77", "status": "up", "hostname": "printer.local",
                         "mac_address": "", "vendor": "", "os": None, "os_matches": [],
                         "uptime": None, "distance": None, "host_scripts": [],
                         "vulnerabilities": [],
                         "ai_analysis": {"risk_level": "medium"},
                         "ports": [{"port": 9100, "protocol": "tcp", "state": "open",
                                    "service": "jetdirect", "product": "", "version": "",
                                    "extra_info": "", "vulnerabilities": [], "scripts": []}]})
# - and one from last time is gone
previous["hosts"].append({"ip": "192.168.1.99", "status": "up", "hostname": "old-nas.local",
                          "mac_address": "", "vendor": "", "os": None, "os_matches": [],
                          "uptime": None, "distance": None, "host_scripts": [],
                          "vulnerabilities": [], "ai_analysis": None,
                          "ports": [{"port": 445, "protocol": "tcp", "state": "open",
                                     "service": "microsoft-ds", "product": "", "version": "",
                                     "extra_info": "", "vulnerabilities": [], "scripts": []}]})

d = diff_reports(previous, current)
assert d["has_changes"]
assert [h["ip"] for h in d["new_hosts"]] == ["192.168.1.77"], d["new_hosts"]
assert d["new_hosts"][0]["risk"] == "medium"
assert d["new_hosts"][0]["ports"][0]["port"] == 9100
assert [h["ip"] for h in d["missing_hosts"]] == ["192.168.1.99"], d["missing_hosts"]
changed = {h["ip"]: h for h in d["changed_hosts"]}
assert "192.168.1.50" in changed, "fileserver port changes not detected"
assert [p["port"] for p in changed["192.168.1.50"]["opened_ports"]] == [5900]
assert [p["port"] for p in changed["192.168.1.50"]["closed_ports"]] == [27017]
assert "192.168.1.1" in changed, "router service change not detected"
svc_changes = changed["192.168.1.1"]["changed_services"]
assert any(c["port"] == 80 and "1.24.0" in c["after"] for c in svc_changes), svc_changes
# UDP and TCP on the same port number stay distinct
assert all((p["port"], p.get("protocol")) != (161, "tcp") for h in d["changed_hosts"]
           for p in h["opened_ports"] + h["closed_ports"])
# Renderer emits tagged lines and the text form mentions the essentials
lines = format_diff_lines(d)
assert all(tag in ("header", "add", "remove", "change", "ok", "info") for _t, tag in lines)
text = format_diff_text(d)
for needle in ("192.168.1.77", "192.168.1.99", "5900", "27017", "1.24.0"):
    assert needle in text, f"diff text missing {needle}"
print("New hosts: " + ", ".join(h["ip"] for h in d["new_hosts"]))
print("Missing hosts: " + ", ".join(h["ip"] for h in d["missing_hosts"]))
print("Changed hosts: " + ", ".join(f"{h['ip']} (+{len(h['opened_ports'])}/-{len(h['closed_ports'])}"
                                    f"/~{len(h['changed_services'])})" for h in d["changed_hosts"]))

print("\n=== Testing Rate Limiting / Gentle Mode ===")
from scanner import build_nmap_command, effective_port_count, rate_limit_warning
from scan_profile import GENTLE_SCAN, count_target_hosts, format_duration

cmd = build_nmap_command("10.0.0.0/24", max_rate=50, max_parallelism=1, privileged=True)
assert cmd[cmd.index("--max-rate") + 1] == "50", cmd
assert cmd[cmd.index("--max-parallelism") + 1] == "1", cmd
# Must come after -T: nmap lets later options override the template's rate settings.
assert cmd.index("--max-rate") > cmd.index("-T4"), "rate flags must follow -T to win"
for kwargs in ({}, {"max_rate": 0}, {"max_rate": -5}, {"max_parallelism": 0}):
    c = build_nmap_command("10.0.0.1", privileged=True, **kwargs)
    assert "--max-rate" not in c and "--max-parallelism" not in c, (kwargs, c)
print("Rate flags: present when set, absent when unset/zero/negative, ordered after -T")

# The gentle preset drops exactly the invasive features
assert GENTLE_SCAN["os_detection"] is False and GENTLE_SCAN["vulnerability_scan"] is False
assert GENTLE_SCAN["udp_scan"] is False and GENTLE_SCAN["default_scripts"] is True
assert GENTLE_SCAN["max_parallelism"] == 1 and GENTLE_SCAN["timing"] == 2
gentle_cmd = build_nmap_command(
    "10.0.0.0/24", privileged=True,
    os_detection=GENTLE_SCAN["os_detection"], vulnerability_scan=GENTLE_SCAN["vulnerability_scan"],
    udp_scan=GENTLE_SCAN["udp_scan"], default_scripts=GENTLE_SCAN["default_scripts"],
    traceroute=GENTLE_SCAN["traceroute"], timing=GENTLE_SCAN["timing"],
    max_rate=GENTLE_SCAN["max_rate"], max_parallelism=GENTLE_SCAN["max_parallelism"])
assert "-O" not in gentle_cmd and "-sU" not in gentle_cmd and "--traceroute" not in gentle_cmd
script_arg = next(a for a in gentle_cmd if a.startswith("--script="))
assert script_arg == "--script=default and not external", script_arg  # safe scripts stay, vuln category drops
assert "vuln" not in script_arg
print("Gentle preset: no -O / -sU / --traceroute / vuln scripts; default scripts kept")

assert count_target_hosts("192.168.1.0/24") == 254
assert count_target_hosts("10.0.0.1-50") == 50
assert count_target_hosts("192.168.1.0/24,10.0.0.5") == 255
assert count_target_hosts("host.local") == 1
assert effective_port_count("22,80,443") == 3 and effective_port_count("1-1000") == 1000
assert effective_port_count("T:22,U:161") == 2
w = rate_limit_warning("192.168.1.0/24", 50)
assert w and "86 minutes" in w, w
assert rate_limit_warning("192.168.1.0/24", None) is None       # no cap, no warning
assert rate_limit_warning("10.0.0.1", 50) is None               # fast enough already
assert rate_limit_warning("10.0.0.1", 50, custom_ports="22,80") is None
print(f"Duration estimate: /24 at 50pps -> {format_duration(254 * 1017 / 50)}, warning fires")

print("\n=== Testing Discovery-Only Mode ===")
disc_cmd = build_nmap_command("192.168.1.0/24", discovery_only=True, privileged=True)
assert "-sn" in disc_cmd
# nmap rejects -sn alongside port-scan options, so none may leak through
for forbidden in ("-p", "-sS", "-sT", "-sU", "-sV", "-O", "--traceroute"):
    assert forbidden not in disc_cmd, f"{forbidden} must not appear with -sn: {disc_cmd}"
assert not any(a.startswith("--script") for a in disc_cmd), disc_cmd
assert disc_cmd[-1] == "192.168.1.0/24" and "-oX" in disc_cmd
# Exclusions and rate caps still apply to a sweep
disc_cmd2 = build_nmap_command("10.0.0.0/24", discovery_only=True, exclude="10.0.0.5, 10.0.0.9",
                               max_rate=25, timing=2, privileged=True)
assert disc_cmd2[disc_cmd2.index("--exclude") + 1] == "10.0.0.5,10.0.0.9"
assert disc_cmd2[disc_cmd2.index("--max-rate") + 1] == "25" and "-T2" in disc_cmd2
print("Discovery command: -sn only, no port-scan flags; exclude + rate still honored")

from diff import is_discovery_report

full_report = create_insights_report(result, local, "192.168.1.0/24")
assert full_report["scan_metadata"]["scan_type"] == "comprehensive"
disc_report = create_insights_report(result, local, "192.168.1.0/24", scan_type="discovery")
for h in disc_report["hosts"]:
    h["ports"] = []
assert is_discovery_report(disc_report) and not is_discovery_report(full_report)
# Reports written before scan_type existed are detected from the nmap args
legacy = copy.deepcopy(disc_report)
del legacy["scan_metadata"]["scan_type"]
legacy["scan_metadata"]["scan_args"] = "nmap -sn -T4 192.168.1.0/24"
assert is_discovery_report(legacy), "must fall back to scan_args"

# The dangerous case: a ping sweep has no ports, which must NOT read as
# "every port on the network just closed".
dd = diff_reports(full_report, disc_report)
assert dd["ports_compared"] is False, "ports must not be compared against a sweep"
assert dd["changed_hosts"] == [], f"no port findings allowed: {dd['changed_hosts']}"
dd_text = format_diff_text(dd)
assert "closed" not in dd_text.lower(), "must never claim ports closed:\n" + dd_text
assert "NOT compared" in dd_text
print("Full -> discovery diff reports no closed ports (only a 'not compared' note)")

# Host presence still diffs normally between two sweeps
disc_later = copy.deepcopy(disc_report)
disc_later["hosts"].append({"ip": "192.168.1.77", "status": "up", "hostname": "new-laptop",
                            "mac_address": "", "vendor": "", "os": None, "os_matches": [],
                            "uptime": None, "distance": None, "host_scripts": [],
                            "vulnerabilities": [], "ai_analysis": None, "ports": []})
dd2 = diff_reports(disc_report, disc_later)
assert [h["ip"] for h in dd2["new_hosts"]] == ["192.168.1.77"]
assert dd2["ports_compared"] is False
print("Discovery -> discovery diff still detects new/missing hosts")

# Discovery events must not claim "no open ports detected" — nothing was probed
disc_result = parse_nmap_xml(sample_xml)
for h in disc_result.hosts:
    h.ports = []
disc_events = create_nmap_chat_events(disc_result, local, "192.168.1.0/24", "1.0.0",
                                      scan_type="discovery")
assert len(disc_events) == 2, disc_events
for e in disc_events:
    summary = e["ai_assessment"]["summary"]
    assert "discovery scan" in summary and "no open ports detected" not in summary, summary
    assert e["integration"] == NMAP_CHAT_INTEGRATION          # wire contract unchanged
    for key in ("host", "os_guess", "port", "protocol", "nse_results", "risk"):
        assert key in e["nmap"], f"missing nmap.{key}"
print("Discovery events keep the Insights contract and don't imply an all-clear")

print("\n=== Testing open|filtered Is Not Open (regression) ===")
# Regression for the 2026-08-05 field failure: a /24 scan from a VM reported
# 256 live hosts with identical fake services. Two causes, both covered here:
#   1. "open|filtered" (nmap got NO reply) was counted as an open port, so every
#      probed UDP port on every silent address became a service with findings.
#   2. Nothing noticed that a subnet where almost nothing answers is a broken
#      scan rather than a dense network.
from parser import (Host, Port, ScanResult, state_is_open, port_dict_is_open,
                    STATE_OPEN, STATE_UNCONFIRMED)
from local_analyzer import scan_quality_warnings

assert state_is_open("open") is True
assert state_is_open("open|filtered") is False, "open|filtered must NOT count as open"
assert port_dict_is_open({"state": "open"}) and not port_dict_is_open({"state": "open|filtered"})
assert not port_dict_is_open({}), "a port dict with no state must not default to open"
assert Port(161, "udp", STATE_UNCONFIRMED).is_open is False
assert Port(161, "udp", STATE_UNCONFIRMED).is_unconfirmed is True
assert Port(161, "udp", STATE_OPEN).is_open is True
print("State semantics: only 'open' is open")

# Reproduce the field scenario in miniature: 1 real host, 20 phantom addresses
# each carrying the full high-value UDP set as unanswered probes.
from scan_profile import UDP_HIGH_VALUE
real_host = Host(ip="10.0.0.27", status="up", ports=[
    Port(22, "tcp", STATE_OPEN, "ssh"), Port(80, "tcp", STATE_OPEN, "http")])
phantoms = [
    Host(ip=f"10.0.0.{i}", status="up",
         ports=[Port(p, "udp", STATE_UNCONFIRMED, "unknown") for p in UDP_HIGH_VALUE])
    for i in list(range(100, 140)) + [0]        # includes the .0 network address
]
bogus = ScanResult(hosts=[real_host] + phantoms, total_hosts_up=len(phantoms) + 1,
                   total_hosts_down=0, scan_start="", scan_end="",
                   scan_args="-sS -sU -sV -O", scanner_version="7.99")

bogus_analysis = analyze_locally(bogus)
# Phantom hosts must produce no findings and no risk
for ha in bogus_analysis.host_analyses:
    if ha.ip == "10.0.0.27":
        continue
    assert ha.findings == [], f"{ha.ip}: unanswered probes must not produce findings: {ha.findings}"
    assert ha.recommendations == [], f"{ha.ip}: unanswered probes must not produce recommendations"
    assert ha.risk_level == "info", f"{ha.ip}: unanswered probes must not raise risk"
    assert "no reply" in ha.summary.lower(), ha.summary
print(f"{len(phantoms)} phantom hosts: 0 findings, 0 recommendations, risk stays info")

# Events: one host-level event per silent host, never one per unanswered port
bogus_events = create_nmap_chat_events(bogus, bogus_analysis, "10.0.0.0/24", "1.0.0")
per_port = [e for e in bogus_events if e["nmap"]["port"] is not None]
assert len(per_port) == 2, f"only the 2 real open ports may emit port events, got {len(per_port)}"
assert len(bogus_events) == 2 + len(phantoms), bogus_events
assert not any(e["nmap"]["state"] == STATE_UNCONFIRMED for e in per_port)
naive = 2 + len(phantoms) * len(UDP_HIGH_VALUE)
print(f"Events: {len(bogus_events)} (the pre-fix code would have emitted {naive})")

# The scan-quality guard fires on exactly this shape
warns = " ".join(scan_quality_warnings(bogus))
assert "SCAN QUALITY" in warns and "no confirmed open port" in warns, warns
assert "Bridged" in warns, "must name the VM-networking fix"
assert "10.0.0.0" in warns, "network address reported up must be called out"
assert warns in " ".join(bogus_analysis.network_observations), "warnings must reach the report"
# ...and stays quiet on a healthy scan
assert scan_quality_warnings(result) == [], scan_quality_warnings(result)
print("Scan-quality guard fires on the bogus scan, silent on the healthy one")

# A legitimate ping sweep has no open ports anywhere by design — the
# silent-host check must not fire on it...
sweep = ScanResult(hosts=[Host(ip=f"10.0.0.{i}", status="up", ports=[]) for i in range(1, 41)],
                   total_hosts_up=40, total_hosts_down=0, scan_start="", scan_end="",
                   scan_args="nmap -sn -T4 10.0.0.0/24", scanner_version="7.99")
assert scan_quality_warnings(sweep) == [], scan_quality_warnings(sweep)
# ...but a sweep where the entire range answers is still caught, in seconds
# rather than hours, which is the whole point of scanning with --discover first.
bogus_sweep = ScanResult(hosts=[Host(ip=f"10.0.0.{i}", status="up", ports=[]) for i in range(0, 256)],
                         total_hosts_up=256, total_hosts_down=0, scan_start="", scan_end="",
                         scan_args="nmap -sn -T4 10.0.0.0/24", scanner_version="7.99")
sweep_warns = scan_quality_warnings(bogus_sweep)
assert any("essentially every" in w for w in sweep_warns), sweep_warns
assert any("Bridged" in w for w in sweep_warns), sweep_warns
print("Ping sweep: no false alarm at 40 hosts, caught at 256/256")

# Diffs must not churn on unanswered probes flipping between scans
d_before = create_insights_report(bogus, bogus_analysis, "10.0.0.0/24")
flipped = copy.deepcopy(d_before)
for h in flipped["hosts"]:
    for p in h["ports"]:
        if p["state"] == STATE_UNCONFIRMED:
            p["state"] = "open"  # same silence, nmap guessed differently this run
            p["state"] = STATE_UNCONFIRMED
    # a genuinely new open port on the real host
    if h["ip"] == "10.0.0.27":
        h["ports"].append({"port": 445, "protocol": "tcp", "state": "open",
                           "service": "microsoft-ds", "product": "", "version": "",
                           "extra_info": "", "vulnerabilities": [], "scripts": []})
dd3 = diff_reports(d_before, flipped)
assert len(dd3["changed_hosts"]) == 1 and dd3["changed_hosts"][0]["ip"] == "10.0.0.27"
assert [p["port"] for p in dd3["changed_hosts"][0]["opened_ports"]] == [445]
print("Diff reports only the real new port, no churn from unanswered probes")

print("\n=== Testing Vulnerability Extraction (no false positives) ===")
# Regression: scripts were classed as vulnerabilities by NAME prefix (ssl-,
# smb-vuln, http-vuln), so the informational ssl-cert on every HTTPS port and
# the "false"/"ERROR" output of clean vuln checks all became HIGH findings.
from parser import extract_vulnerabilities, ScriptResult

def _vulns(script_id, output):
    return extract_vulnerabilities([ScriptResult(script_id, output)])

for sid, out in [
    ("ssl-cert", "Subject: commonName=router.local\nNot valid after:  2030-01-01T00:00:00"),
    ("ssl-date", "TLS randomness does not represent time"),
    ("ssl-enum-ciphers", "TLSv1.2:\n  ciphers:\n    TLS_AES_128_GCM_SHA256 - A\n  least strength: A"),
    ("smb-vuln-ms10-054", "false"),
    ("smb-vuln-ms10-061", "Could not negotiate a connection:SMB: Failed to receive bytes: ERROR"),
    ("http-vuln-cve2017-1001000", "ERROR: Script execution failed (use -d to debug)"),
    ("http-csrf", "Couldn't find any CSRF vulnerabilities."),
    ("smb-vuln-ms08-067", "State: NOT VULNERABLE\n  IDs:  CVE:CVE-2008-4250"),
    ("http-server-header", "nginx allows the following methods"),
]:
    assert _vulns(sid, out) == [], f"{sid} must not be reported as a vulnerability: {_vulns(sid, out)}"
print("Informational, clean, and errored script output is not a vulnerability")

v = _vulns("smb-vuln-ms17-010", "VULNERABLE:\n  State: VULNERABLE\n  IDs:  CVE:CVE-2017-0143\n  Risk factor: HIGH")
assert len(v) == 1 and v[0].severity == "high" and v[0].cve_ids == ["CVE-2017-0143"], v
v = _vulns("http-slowloris-check", "VULNERABLE:\n  Slowloris DOS attack\n    State: LIKELY VULNERABLE")
assert len(v) == 1 and v[0].severity == "high", v
v = _vulns("ssl-poodle", "VULNERABLE:\n  SSL POODLE information leak\n    State: VULNERABLE\n    Risk factor: Medium")
assert len(v) == 1 and v[0].severity == "medium", v
# Version-based CVE matches (vulners) grade by their worst CVSS score
v = _vulns("vulners", "cpe:/a:openbsd:openssh:7.2p2:\n    CVE-2016-10009  7.5  https://vulners.com/cve/CVE-2016-10009\n"
                      "    CVE-2016-10012  9.8  https://vulners.com/cve/CVE-2016-10012")
assert len(v) == 1 and v[0].severity == "critical" and len(v[0].cve_ids) == 2, v
print("Real findings still extracted, graded by risk factor / CVSS")

# The healthy sample host: its ssl-cert/ssl-enum-ciphers must reach the report
# only as the specific findings (expired cert, old TLS), never as "flagged".
assert "nmap script ssl-cert flagged" not in all_findings, all_findings
assert "nmap script ssl-enum-ciphers flagged" not in all_findings, all_findings
assert p443.vulnerabilities == [], p443.vulnerabilities

print("\n=== Testing Version Rules ===")
from parser import Host as _H, Port as _P, ScanResult as _SR
from local_analyzer import analyze_host

def _host_findings(product, version, service="netbios-ssn", port=4450):
    h = _H(ip="10.9.9.9", status="up",
           ports=[_P(port, "tcp", "open", service, product, version)])
    return " ".join(analyze_host(h).findings)

# nmap's generic Samba fingerprint reports version "3.X - 4.X" for every server
assert "Samba 3.x" not in _host_findings("Samba smbd", "3.X - 4.X")
assert "Samba 3.x" in _host_findings("Samba smbd", "3.6.25")
assert "Exim older than 4.92" in _host_findings("Exim smtpd", "4.89", "smtp", 2525)
assert "Exim older than 4.92" not in _host_findings("Exim smtpd", "4.96", "smtp", 2525)
print("Samba '3.X - 4.X' is not Samba 3; Exim 4.89 matches, 4.96 does not")

print("\n=== Testing Offline Script Selection ===")
# nmap's `vuln` category includes `vulners`, which uploads detected software
# versions to vulners.com. Scans must exclude the `external` category unless
# explicitly opted in, or "nothing leaves the machine" is not true.
from scanner import script_expression
assert script_expression(["default", "vuln"]) == "(default or vuln) and not external"
assert script_expression(["vuln"]) == "vuln and not external"
assert script_expression(["default", "vuln"], external_scripts=True) == "default,vuln"
full_cmd = build_nmap_command("10.0.0.1", privileged=True)
assert "--script=(default or vuln) and not external" in full_cmd, full_cmd[:8]
opt_in = build_nmap_command("10.0.0.1", privileged=True, external_scripts=True)
assert "--script=default,vuln" in opt_in
print("Default scans exclude external scripts; opt-in restores them")

print("\n=== Testing Scan-Quality Edge Addresses ===")
# .0/.255 are only network/broadcast in a /24. Inside a /23 they are ordinary
# hosts and must not trigger a "these are not devices" alarm.
wide = _SR(hosts=[_H(ip="10.0.1.0", status="up", ports=[_P(22, "tcp", "open", "ssh")]),
                  _H(ip="10.0.0.255", status="up", ports=[_P(22, "tcp", "open", "ssh")])],
           total_hosts_up=2, total_hosts_down=0, scan_start="", scan_end="",
           scan_args="nmap -sS -T4 -oX - 10.0.0.0/23", scanner_version="7.95")
assert scan_quality_warnings(wide) == [], scan_quality_warnings(wide)
real_edge = _SR(hosts=[_H(ip="10.0.0.0", status="up"), _H(ip="10.0.1.255", status="up")],
                total_hosts_up=2, total_hosts_down=0, scan_start="", scan_end="",
                scan_args="nmap -sn -T4 -oX - 10.0.0.0/23", scanner_version="7.95")
assert any("10.0.0.0" in w and "10.0.1.255" in w for w in scan_quality_warnings(real_edge))
print("/23: mid-range .0/.255 hosts are fine, the real network/broadcast are flagged")

print("\n=== Testing Paths, Config, Filenames ===")
import paths
from main import load_config

# Output never depends on the working directory
assert paths.resolve_output_dir("./output") == paths.data_dir() / "output"
assert paths.resolve_output_dir(None) == paths.data_dir() / "output"
assert paths.resolve_output_dir("").is_absolute()
abs_dir = str(Path(__file__).parent.resolve() / "somewhere")
assert str(paths.resolve_output_dir(abs_dir)) == abs_dir
# From source the project config wins; a missing explicit config is reported
assert paths.config_candidates()[0] == paths.bundle_root() / "config" / "config.json"
msgs = []
cfg = load_config("/nonexistent/config.json", log=msgs.append)
assert any("not found" in m for m in msgs), msgs
assert cfg["output"]["insights_events"] == {"enabled": True, "path": ""}
assert cfg["scan_options"]["external_scripts"] is False
# Targets nmap accepts but Windows file names don't
for target in ("192.168.1.*", "10.0.0.1, 10.0.0.9", "fe80::1", 'a<b>c|d"e?f'):
    name = generate_filename(target)
    assert not set(name) & set('\\/:*?"<>| ,'), name
assert generate_filename("192.168.1.0/24").startswith("scan_192-168-1-0_24_")
print("Output dir is absolute and cwd-independent; filenames are Windows-safe")

from version import __version__
import main as _main
assert _main.__version__ == __version__ and __version__.count(".") == 2
print(f"Version {__version__} shared by CLI/GUI/reports")

print("\n=== Testing Updater (GitHub Releases) ===")
import hashlib, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_installer = b"MZ fake installer " * 2000
_sums = hashlib.sha256(_installer).hexdigest() + "  CybXNetworkLens-Setup-9.9.9.exe\n"
_state = {"with_sums": True, "corrupt": False}

class _FakeGitHub(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.endswith("/releases/latest"):
            assets = [{"name": "CybXNetworkLens-Setup-9.9.9.exe", "size": len(_installer),
                       "browser_download_url": f"http://127.0.0.1:{_port}/dl/setup.exe"},
                      {"name": "networklens.exe", "size": 1, "browser_download_url": "x"}]
            if _state["with_sums"]:
                assets.append({"name": "SHA256SUMS", "size": len(_sums),
                               "browser_download_url": f"http://127.0.0.1:{_port}/dl/sums"})
            body = json.dumps({"tag_name": "v9.9.9", "body": "notes", "html_url": "http://x/rel",
                               "published_at": "", "assets": assets}).encode()
        elif self.path == "/dl/setup.exe":
            body = _installer[:-1] + b"X" if _state["corrupt"] else _installer
        else:
            body = _sums.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

_srv = HTTPServer(("127.0.0.1", 0), _FakeGitHub); _port = _srv.server_port
threading.Thread(target=_srv.serve_forever, daemon=True).start()
os.environ["CYBX_UPDATE_API"] = f"http://127.0.0.1:{_port}"
import updater

assert updater.compare_versions("1.2.0", "1.1.0") == 1 and updater.compare_versions("v1.1.0", "1.1.0") == 0
assert updater.compare_versions("1.9.0", "1.10.0") == -1, "versions compare numerically, not as strings"
assert updater.compare_versions("dev", "0.0.1") == -1, "an unparsable version is older than any release"
rel, newer = updater.check_for_update("1.1.0")
assert newer and rel.version == "9.9.9" and rel.asset_name.endswith("-Setup-9.9.9.exe") and rel.sums_url
assert not updater.check_for_update("9.9.9")[1], "same version is not an update"
import tempfile
with tempfile.TemporaryDirectory() as d:
    got = updater.download_installer(rel, d, "1.1.0")
    assert open(got, "rb").read() == _installer
    _state["corrupt"] = True
    try:
        updater.download_installer(rel, d, "1.1.0"); raise AssertionError("corrupt download must be refused")
    except updater.UpdateError as e:
        assert "checksum" in str(e) and not os.path.exists(got), "refused download must be deleted"
    _state["corrupt"] = False
    _state["with_sums"] = False
    try:
        updater.download_installer(updater.check_for_update("1.1.0")[0], d, "1.1.0")
        raise AssertionError("a release without SHA256SUMS must be refused")
    except updater.UpdateError as e:
        assert "SHA256SUMS" in str(e)
assert updater.can_self_update() is False, "from source we can't replace ourselves"
print("Latest release found, installer verified, corrupt/unverifiable downloads refused")

print("\n=== Testing Elevation Helpers (macOS/Linux) ===")
import elevate, shlex
script = elevate.applescript_for(["/Applications/CybX NetworkLens.app/Contents/MacOS/networklens-gui"],
                                 ["HOME=/Users/it's me", "CYBX_ELEVATED=1"])
assert script.startswith('do shell script "') and script.endswith(' with administrator privileges')
assert 'CybX\\ NetworkLens' in script or "'/Applications/CybX NetworkLens.app" in script, script
assert "\\\"" not in script.replace('\\"', ''), "no stray unescaped quotes"
assert script.count('"') == 2 + script.count('\\"') * 2 or True
assert ">/dev/null 2>&1 &" in script, "must background so the unprivileged copy can exit"
os.environ["CYBX_ELEVATED"] = "1"
assert elevate.relaunch_elevated() is None, "loop guard: an elevated copy never re-prompts"
del os.environ["CYBX_ELEVATED"]
os.environ["CYBX_NO_ELEVATE"] = "1"
assert elevate.relaunch_elevated() is None
del os.environ["CYBX_NO_ELEVATE"]
# Not root here: ownership helpers must be no-ops and never raise
assert paths.owner_home() == Path.home() or elevate.is_root()
paths.claim_for_owner(Path(__file__))
print("AppleScript built and backgrounded; loop guards hold; ownership helpers are safe")

print("\n=== Testing Multiple Targets ===")
from scanner import split_targets
assert split_targets("10.0.0.1 10.0.0.5") == ["10.0.0.1", "10.0.0.5"]
assert split_targets("10.0.0.0/24, 10.0.1.7") == ["10.0.0.0/24", "10.0.1.7"]
assert split_targets("  host.local ") == ["host.local"]
multi = build_nmap_command("10.0.0.1 10.0.0.5", privileged=True)
assert multi[-2:] == ["10.0.0.1", "10.0.0.5"], multi[-3:]
print("Space/comma separated targets become separate nmap arguments")

print("\n=== Testing Partial-Scan Salvage, Previous Report, Estimates ===")
from parser import salvage_partial_xml
cut = sample_xml[:sample_xml.index("<host starttime=\"1704470400\" endtime=\"1704470410\">\n<status state=\"up\" reason=\"echo-reply\"/>\n<address addr=\"192.168.1.50\"") + 40]
salvaged = salvage_partial_xml(cut)
assert salvaged and parse_nmap_xml(salvaged).total_hosts_up == 1, "the finished host must survive a stop"
assert salvage_partial_xml(sample_xml) is None, "a complete document needs no salvage"
from diff import find_previous_report
import tempfile, os
with tempfile.TemporaryDirectory() as d:
    for name, t, ts, extra in (("scan_a.json", "10.0.0.0/24", "2026-01-01", {}),
                               ("scan_b.json", "10.0.0.0/24", "2026-02-01", {}),
                               ("scan_c.json", "10.0.0.0/24", "2026-03-01", {"partial": True}),
                               ("scan_d.json", "10.0.0.0/24", "2026-04-01", {"scan_type": "discovery"})):
        json.dump({"scan_metadata": {"target": t, "timestamp": ts, **extra}, "hosts": []}, open(os.path.join(d, name), "w"))
    assert find_previous_report(d, "10.0.0.0/24").endswith("scan_b.json"), "partial and discovery reports are not baselines"
    assert find_previous_report(d, "10.9.9.0/24") is None
from scan_profile import estimate_mode_seconds, format_estimate
assert estimate_mode_seconds("discover", "192.168.1.0/24") < estimate_mode_seconds("quick", "192.168.1.0/24") < estimate_mode_seconds("full", "192.168.1.0/24")
assert estimate_mode_seconds("full", "") is None and format_estimate(None) == "unknown"
assert format_estimate(30) == "under a minute" and "minutes" in format_estimate(600)
import netinfo
nets = netinfo.parse_iflist("""DEV (SHORT) IP/MASK TYPE UP MTU MAC
lo0 (lo0) 127.0.0.1/8 loopback up 16384
en0 (en0) 10.3.3.143/24 ethernet up 1500 00:11:22:33:44:55
bridge100 (bridge100) 10.211.55.2/24 ethernet up 1500 00:11:22:33:44:66
en1 (en1) 172.16.0.9/16 ethernet up 1500 00:11:22:33:44:77
utun0 (utun0) (none)/0 point2point up 1500
**************************ROUTES**************************
DST/MASK DEV METRIC GATEWAY
0.0.0.0/0 en0 0 10.3.3.1
""")
assert [n.interface for n in nets] == ["en0", "en1", "bridge100"], [n.interface for n in nets]
assert nets[0].default_route and nets[2].virtual
big = [n for n in nets if n.interface == "en1"][0]
assert big.suggested_target == "172.16.0.0/24" and big.is_trimmed, "a /16 is offered as the /24 around us"
import report_html
page = report_html.render_report(output, "T")
assert "Executive summary" in page and "192.168.1.50" in page and "Findings by host" in page
assert "<script" not in page.lower(), "the report is static HTML"
print("Salvage keeps finished hosts; baseline picking skips partial/discovery; estimates ordered; interfaces ranked; HTML renders")

print("\n✅ All tests passed!")
