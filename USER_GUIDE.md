# CybX NetworkLens — User Guide

This guide explains how to run a scan and how to read the results. It's written for
the person running the scan and for anyone reviewing the findings with a customer.

- New to the tool? Start at [Running a scan](#running-a-scan).
- Handed a set of results? Jump to [Understanding the results](#understanding-the-results)
  and [What the findings mean](#what-the-findings-mean).

For install/build steps and the CybX Insight setup, see the
[README](README.md) and [`insights/README.md`](insights/README.md).

---

## What the scanner does

It looks at a network the way an attacker's first pass would: it finds live hosts,
lists the open ports, identifies the software behind them, and flags the ones that are
risky — exposed databases, remote-access services, cleartext protocols, out-of-date
software, expiring certificates, and known vulnerabilities. Everything runs **offline
on your machine**; nothing about the customer's network is sent to any outside service.

Each scan produces two things:

1. A **report** you can read or hand over (a JSON file, summarized on screen).
2. A stream of **events for CybX Insight** (one per open port) that flow into the
   dashboard, so the network view sits alongside the customer's other data.

---

## Before you start

- **Only scan networks you're authorized to scan.** This tool actively probes hosts.
- **Run it with administrator / root privileges** for the best results:
  - **Windows:** the GUI auto-elevates (approve the prompt); for the CLI, use an
    Administrator command prompt.
  - **macOS / Linux:** run with `sudo`.
  - Without privileges the scan still works but quietly drops to a lighter TCP-only
    mode — you'll miss UDP services (SNMP, IPMI), OS detection, and network path info.
- **First run on Windows** may offer to install Npcap (a packet driver). Approve it
  once and click through the Npcap setup window that opens.

### Installing (Windows)

Double-click `CybXNetworkLens-Setup-<version>.exe`, approve the Windows permission
prompt, and click through the wizard. You get a **CybX NetworkLens** icon on the
Desktop and in the Start Menu. If Windows shows "Windows protected your PC", click
**More info > Run anyway**.

To remove it: Settings > Apps > Installed apps > CybX NetworkLens > Uninstall.
Your saved scan reports are kept.

### Updating

Click **Check for Updates...** at the bottom right of the window. If there is a newer
version you'll see what changed and can click **Yes** to install it: the scanner
downloads the update, closes, installs, and reopens on the new version — your settings
and saved reports are kept. If you're already current it just says so. The scanner also
checks once when it starts and mentions an available update in the status bar; it never
installs anything until you say yes.

---

## Running a scan

### The graphical app (easiest)

1. Launch the scanner — the **CybX NetworkLens** Desktop icon (or
   `networklens-gui` if you're using the portable version). On Windows, approve the
   elevation prompt.
2. Enter a **Target**. This can be:
   - a single host — `192.168.1.10`
   - a range — `192.168.1.1-50`
   - a whole subnet — `192.168.1.0/24`
3. Choose a **Scan mode**:

   | Mode | Speed | What it does | Use it when |
   |------|-------|--------------|-------------|
   | **Discover** | Seconds | Finds which devices are alive. No ports are checked. | You want to confirm the target range is right before a real scan. |
   | **Gentle** | Very slow | A careful, rate-limited scan with the riskiest checks left out. | The network has fragile equipment (PLCs, medical devices, old printers). |
   | **Quick** | Fast | Finds open ports and identifies services. Flags exposed services (Redis, RDP, telnet, ...) but skips deep checks. | You want a fast inventory, or you're scanning a large subnet. |
   | **Full** | Slower | Everything Quick does **plus** OS detection, UDP services (SNMP/IPMI/TFTP), certificate/SMB/CVE checks, and network path. | You want the complete, most actionable picture. *(default)* |

   You can fine-tune the individual toggles (OS Detection, Vulnerability Scripts, UDP,
   Timing) after picking a mode.
4. Click **Start Scan**. The progress bar and **Live Log** show what's happening.
5. When it finishes, the app opens the **Inventory** tab — one row per live device
   showing its **IP address, hostname, MAC address, hardware vendor, open ports, and
   OS guess**. This is the view to use on-site for spotting what's on the network,
   avoiding IP conflicts, and deciding which ports should be closed.

   > MAC addresses only appear when you scan from the **same subnet** as the devices
   > and run with root/administrator privileges. Scanning across a router hides them.

   For the deeper security picture, review the **Results** tab (per-host tree of
   findings) and the **Raw JSON** tab.
6. Save what you need:
   - **Export Inventory CSV...** — the device inventory as a spreadsheet-ready CSV
     (IP, hostname, MAC, vendor, open ports, OS) for handoff or ticketing.
   - **Save Report...** — the full JSON report.
   - **Save Insights Events...** — the per-port events for CybX Insight.
   - **Open Output Folder** — every finished scan is saved here automatically
     (`Documents\CybX NetworkLens\output`), so nothing is lost if you forget to save.

   **Stop** ends a scan early. A stopped scan is not saved.

### The command line

```bash
# Full scan of a subnet (run with sudo / as Administrator for best results)
sudo networklens --target 192.168.1.0/24

# Quick sweep (ports + services only, fast)
sudo networklens --target 192.168.1.0/24 --quick

# Just a few ports
sudo networklens --target 192.168.1.10 -p 22,80,443

# Write the report to a specific file
sudo networklens --target 10.0.0.0/24 -o customer_scan.json
```

Common options: `--quick` (fast mode), `--no-udp` / `--no-vuln` (drop the slow parts),
`-T 0..5` (speed, higher is faster/noisier), `-p` (specific ports). Run
`networklens --help` for the full list.

### How long does it take?

A single host is quick. A **Full** scan of a whole `/24` can take a while (UDP and the
script checks are the slow parts). If you need it faster: use **Quick** mode, scan
fewer hosts at a time, or raise the timing (e.g. `-T5` on a healthy local network).

---

## Understanding the results

### Risk levels

Every host and every finding gets a risk level. This is what drives triage — work top
to bottom.

| Level | Plain meaning | Typical examples |
|-------|---------------|------------------|
| **Critical** | Fix now. Often exploitable without a password, or a wide-open door. | Exposed Redis/MongoDB with no auth, SMB (EternalBlue), telnet, unsupported Windows. |
| **High** | Serious exposure; schedule promptly. | RDP exposed to the network, SNMP with default community, exposed database, end-of-life server OS, expired TLS certificate. |
| **Medium** | Real weakness; fix in normal cycles. | Weak/old TLS, SMB signing not required, older software versions, information leaks. |
| **Low** | Hardening opportunity. | Chatty legacy services, minor exposure. |
| **Info** | For awareness; no direct risk. | A normal web service, general service detail. |

The overall risk for a host (and for the scan) is the **highest** level found on it.

### The two output files

- **`scan_<target>_<time>.json`** — the human report: scan details, an executive summary,
  and a per-host breakdown of open ports, findings, and recommendations. This is the file
  to read or attach to a customer report.
- **`scan_<target>_<time>.ndjson`** — the machine feed for CybX Insight, one line per open
  port. You normally don't read this directly; it's what the Insights collector ingests so
  the ports and risks show up in the dashboard. See [`insights/README.md`](insights/README.md)
  for the one-time setup that connects the two.

### How a finding is written

Findings read like:

> **[CRITICAL] Port 6379/tcp (redis): Redis is exposed. Redis defaults to no
> authentication and is routinely abused for RCE via config rewrite.**

That's the **severity**, the **port/service**, **what was found**, and (in the
recommendations) **what to do about it**. The sections below explain the categories in
plain language.

---

## What the findings mean

These are the kinds of findings the scanner produces, grouped by theme. Each one lists
what it means, why it matters, and the usual fix. Exact wording in a report may vary.

### Cleartext & legacy protocols

Old protocols that send data — often including passwords — with no encryption, or that
have no business being on a modern network.

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **Telnet (23)** | Critical | Passwords and all traffic travel in the clear; trivially sniffed. | Disable telnet; use SSH (22). |
| **FTP (21)** | High | Cleartext credentials; often allows anonymous login. | Use SFTP/FTPS; disable anonymous access. |
| **TFTP (69)** | High | No authentication at all; commonly used to steal device configs. | Disable unless required for device provisioning; firewall it off. |
| **rsh / rlogin / rexec (512–514)** | High | Ancient remote-shell tools, cleartext, weak trust model. | Remove them; use SSH. |
| **POP3 / IMAP / SMTP without TLS (110/143/25)** | Medium | Mail credentials/content can be read in transit. | Enforce STARTTLS or the TLS ports (993/995). |
| **Finger (79), NetBIOS name service (137)** | Low–Medium | Leak user names, host names, and workgroup info that help an attacker. | Disable / block at the perimeter. |

### Remote access & administration exposed

Services that let someone control or manage a machine. They're fine on a locked-down
management network, but dangerous when reachable broadly.

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **SMB / file sharing (445, 139)** | Critical | The path for EternalBlue/WannaCry-style worms and ransomware spread. | Block 445 at the perimeter, disable SMBv1, patch, require SMB signing. |
| **RDP — Remote Desktop (3389)** | High | Top target for password-guessing and exploits (e.g. BlueKeep). | Put behind a VPN/jump host, enable Network Level Authentication, patch. |
| **VNC (5900)** | High | Remote desktop that's often set up with a weak or no password. | Tunnel over SSH, require a strong password, restrict who can reach it. |
| **SNMP (161)** | High | Network management protocol frequently left on default community strings (`public`/`private`) that reveal device internals. | Move to SNMPv3, change community strings, block UDP/161 from untrusted networks. |
| **IPMI / server management (623)** | High | Baseboard management controllers have auth-bypass bugs and default passwords — full hardware control. | Restrict to a dedicated out-of-band management network. |
| **WinRM (5985/5986)** | Low–Medium | Windows remote management; risk depends on exposure and HTTP vs HTTPS. | Prefer HTTPS (5986), restrict to management networks. |
| **Webmin / other admin panels (10000)** | Medium | Web admin consoles with a history of serious bugs. | Patch, restrict by source IP. |

### Databases & datastores exposed

A database reachable from the network — especially one that defaults to **no
password** — is one of the most common serious findings. Several are Critical because an
attacker can often read or destroy all the data (and sometimes run code) with no login.

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **Redis (6379)** | Critical | Defaults to no authentication; widely abused to gain remote code execution. | Bind to localhost or require AUTH; block at the perimeter. |
| **MongoDB (27017/27018)** | Critical | Older/default setups have no auth — full data exposure. | Enable authentication; restrict to app subnet. |
| **Elasticsearch (9200)** | Critical | Defaults to no auth; a top source of leaked data. | Enable security (auth + TLS); block at the perimeter. |
| **Memcached (11211)** | High | No auth; also abused for denial-of-service amplification. | Bind to localhost; disable UDP; block the port. |
| **MySQL / PostgreSQL / MSSQL / Oracle (3306/5432/1433/1521)** | High | Direct network access to production data. | Bind to app subnets only, require strong credentials + TLS. |
| **CouchDB / Kibana / RabbitMQ (5984/5601/15672)** | Medium–High | Data stores / dashboards, some with unauthenticated-access history or default logins. | Put behind authentication, restrict by source IP, change default creds. |

### Containers & orchestration exposed

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **Docker API without TLS (2375)** | Critical | Unauthenticated remote control of the Docker host = root-level code execution. | Bind Docker to localhost, or require TLS client certificates (2376). |
| **Kubernetes API (6443)** | Medium | Cluster control plane; needs strong access control. | Restrict to operator networks, enforce RBAC and audit logging. |

### Out-of-date & end-of-life software

Software or operating systems no longer receiving security patches. Anything found here
will keep accumulating unfixable vulnerabilities.

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **Unsupported Windows (XP, 2000, Server 2003)** | Critical | No patches since years ago; trivially exploitable. | Decommission or fully isolate. |
| **End-of-life Windows (7, 8, Server 2008/2012)** | Medium–High | Support ended; growing exposure. | Upgrade to a supported release. |
| **Old/vulnerable service versions** (e.g. vsftpd 2.3.4 backdoor, Apache 2.4.49/50, end-of-life Samba/nginx/Exim) | High–Critical | Specific versions with known, often exploitable, bugs. | Upgrade to a current, supported version. |

### Encryption & certificate problems

From the certificate and cipher checks (Full scan).

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **TLS certificate expired** | High | Browsers/clients reject it; often a sign of an unmanaged or forgotten service. | Renew/replace the certificate now. |
| **TLS certificate expiring soon** (≤30 days) | Medium | Heads-up before an outage or scramble. | Renew before it lapses. |
| **Weak TLS (SSLv3 / TLS 1.0 / 1.1, or weak ciphers)** | Medium | Deprecated protocols/ciphers that can be downgraded or broken. | Offer TLS 1.2+ only; remove weak ciphers. |
| **SMB signing not required** | Medium | Lets an attacker relay/tamper with SMB sessions (NTLM relay). | Require SMB signing via group policy. |

### Known vulnerabilities (CVEs)

When the **Full** scan runs vulnerability scripts, confirmed issues appear as findings
that reference a CVE, for example:

> **[HIGH] nmap host script smb-vuln-ms17-010 flagged this host (CVE-2017-0143).**

These are specific, published vulnerabilities (here, the EternalBlue SMB flaw). Treat any
CVE finding as a priority: look it up, confirm it applies, and apply the vendor's patch.

### Weak or default credentials

| Finding | Level | Why it matters | Fix |
|---------|-------|----------------|-----|
| **SNMP default community string guessed** | High | The device answers to `public`/`private` — anyone can read its configuration. | Change the community strings; move to SNMPv3. |
| **Default application credentials found** | High | A service still uses its shipped username/password. | Change all default credentials immediately. |

### Informational

Not every open port is a problem. A normal web server, or a service with no rule match,
shows as **Info** — it's there so you have the complete inventory, and it's still worth a
human glance.

---

## Tuning: speed vs. depth

| You want... | Do this |
|-------------|---------|
| A fast inventory | **Quick** mode (GUI) or `--quick` (CLI). |
| The most thorough picture | **Full** mode (the default). Run with sudo/admin. |
| To skip the slow UDP checks | `--no-udp`, or untick **UDP** in the GUI. |
| To skip CVE/vuln scripts | `--no-vuln`, or untick **Vulnerability Scripts**. |
| To scan specific ports only | `-p 22,80,443` (CLI) or the **Ports** box (GUI). |
| To go faster/slower | Timing `-T 0..5` — higher is faster and noisier. |

Remember: **Quick** still finds and flags exposed services (Redis, RDP, telnet, ...). What
you give up in Quick is the deeper stuff — UDP services, OS detection, certificate/SMB
checks, and CVEs.

---

## Quick troubleshooting

| Symptom | What to do |
|---------|-----------|
| Very few results, or "limited" results | You're not running as admin/root. Re-run with sudo (macOS/Linux) or elevated (Windows). |
| "nmap not found" | The nmap binary isn't bundled/installed. See the README build steps. |
| Windows: scan fails even as admin | Npcap isn't installed — approve the install prompt, or get it from npcap.com. |
| Findings aren't showing in CybX Insight | The Insights collector needs one-time setup — see [`insights/README.md`](insights/README.md). |
| Scan is taking too long | Use **Quick** mode, scan fewer hosts, drop `--no-udp`/`--no-vuln`, or raise `-T`. |

---

## A note for customer conversations

The value of a scan is turning a port list into a decision. When you walk a customer
through results:

- **Lead with Critical and High.** Those are the "someone could do real harm today" items.
- **Explain in terms of exposure, not jargon:** "This database is reachable from the
  network with no password" lands better than "6379/tcp open."
- **Pair every finding with the fix** — the report already includes recommendations.
- **Info-level items aren't failures** — they're the inventory that proves you looked
  everywhere.
