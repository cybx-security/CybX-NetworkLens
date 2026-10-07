# CybX NetworkLens

A portable, cross-platform network scanner with both a **graphical interface** and a
**command-line interface**. It runs nmap scans, parses the results, applies an offline
rule-based analysis, and writes events for ingestion into **CybX Insight**.

The scanner is deliberately **analysis-light and fully offline** — it discovers what is
on the network and flags the obvious exposures. Any AI/LLM enrichment happens downstream
in the reporter (CybX Insight), not here, so no scan data ever leaves the machine.

> 📖 **Just want to run scans and read the results?** See the
> **[User Guide](USER_GUIDE.md)** — how to scan, and what every finding means in plain
> language. This README covers install, build, and the CybX Insight integration.

## Features

- **GUI and CLI** — double-click the GUI to scan visually with a live progress bar, or script it from the command line
- **Windows installer** — one `Setup.exe` anyone can run: Desktop and Start Menu icons, and an uninstaller
- **Cross-Platform** — runs on Windows, macOS, and Linux
- **Portable** — or skip the install: bundle nmap and run from a USB stick; no Python needed on target machines
- **Comprehensive Scanning** — port scan, service detection, OS detection, and vulnerability scripts
- **Local rule-based analysis** — deterministic, offline security scoring (no network calls, no API key)
- **Insights integration** — writes per-port `nmap_chat` events for CybX Insight
- **Npcap handled for you** (Windows) — the installer and the GUI both offer to run Npcap's setup if it's missing
- **Self-updating** — *Check for Updates...* fetches the latest release from GitHub, verifies it, installs it, and reopens the app

---

## How analysis works

Every scan is analyzed by a **local rule engine** that runs entirely offline. It flags
industry-standard exposures — cleartext protocols (telnet, FTP), exposed admin surfaces
(RDP, SMB, WinRM, IPMI), unauthenticated datastores (Redis, MongoDB, Elasticsearch),
end-of-life service/OS versions, and CVEs surfaced by nmap's vuln scripts — and produces
a risk score, executive summary, and prioritized recommendations.

That analysis is what ships in the output. **Nothing about the scanned network is sent
to any external service** — the scanner makes no network calls beyond the nmap scan
itself, with one exception: the update check, which asks GitHub for the latest release
and sends nothing else (see [Updates](#updates); it can be turned off). Deeper AI/LLM
assessment is done in the reporter (CybX Insight), which reads these events and can
enrich them there.

This includes nmap's own scripts: the scan excludes nmap's `external` script category,
because scripts in it talk to third parties — notably `vulners` (part of the `vuln`
category), which uploads every detected product and version to vulners.com. If you
want those version-based CVE lookups and accept that trade-off, set
`scan_options.external_scripts` to `true` in the config (needs internet access).

---

## What the scan covers

The default "balanced" scan is tuned to surface the most actionable findings per minute:

- **TCP ports** — nmap's top-1000 **plus every port the rule engine can score**, so
  services that sit outside the default top-1000 (Redis 6379, MongoDB 27017/27018,
  exposed Docker 2375, Memcached 11211, Elasticsearch 9300, IPMI, Hadoop, ...) are
  actually reached. Adding a rule to the engine automatically widens the scan.
- **Targeted UDP** — a small, high-signal set (SNMP 161, IPMI 623, TFTP 69, NetBIOS 137,
  NTP, SSDP, mDNS, ...). SNMP with default community strings and IPMI are classic internal
  findings a TCP-only scan never sees. Disable with `--no-udp` if you need speed.
- **Service + OS detection** — `-sV` version detection and `-O` OS fingerprinting.
- **Scripts** — nmap's `default` set for context (TLS cert expiry, weak ciphers, SMB
  signing, HTTP methods/titles, SMB OS discovery, SNMP info) plus the `vuln` category for
  CVEs. The scanner turns these into concrete findings (e.g. *"TLS certificate expired"*,
  *"SMB signing not required"*, *"SNMP default community"*), not just raw script text.
- **Traceroute** — network path, for topology / landscape.

**Speed trade-off:** breadth costs time. A single host is quick; a full `/24` with UDP and
scripts can take a while. Tune it per engagement:

- Faster: **Quick mode** (GUI) / `--quick` (CLI) for a ports+services sweep, or
  selectively `--no-udp` / `--no-vuln`, or a higher `-T` (e.g. `-T5` on a healthy LAN).
- Narrower: pass `-p` to scan a specific set (this overrides the balanced port list).
- Privileges: SYN scan, UDP, and OS detection need root/Administrator — otherwise nmap
  falls back to a limited TCP-connect scan and results are thinner.

---

## What gets built

On Windows, `build\build_windows.bat` produces all of these in `dist\`:

| Output | What it is | Notes |
|---|---|---|
| `CybXNetworkLens-Setup-<version>.exe` | **The installer** | Give this to users. See [Installing on Windows](#installing-on-windows-for-users). |
| `networklens-gui.exe` | Portable GUI | Single file, no install. Double-click; **auto-elevates via UAC.** |
| `networklens.exe` | Portable CLI | Single file. Run from an Administrator prompt. |
| `CybXNetworkLens\` | Installed-app folder | What the installer packages. Not for handing out directly. |

The macOS and Linux build scripts produce the two portable executables only
(`networklens` and `networklens-gui`); there is no installer for those platforms.

---

## Installing on Windows (for users)

1. Double-click **`CybXNetworkLens-Setup-<version>.exe`** and approve the Windows
   permission prompt.
2. Click through the wizard. It installs the scanner for everyone on the computer,
   adds a **Desktop icon** and a **Start Menu** entry, and — if Npcap isn't already on
   the machine — opens Npcap's own setup window (click Next / Install in it).
3. Launch **CybX NetworkLens** from the Desktop icon. Windows asks for permission
   each time it starts, because scanning needs administrator rights.

**Uninstalling:** Settings > Apps > Installed apps > CybX NetworkLens > Uninstall
(or run `Uninstall.exe` in the install folder). It removes the program and its
shortcuts. It asks whether to also delete the settings file, and it never deletes
saved scan reports. Npcap is left installed, since other tools may use it.

| What | Where |
|---|---|
| Program | `C:\Program Files\CybX NetworkLens\` |
| Settings | `C:\ProgramData\CybX\NetworkLens\config.json` (kept across upgrades) |
| Scan reports | `Documents\CybX NetworkLens\output\` |
| Command line | `"C:\Program Files\CybX NetworkLens\networklens.exe" --target ...` (Administrator prompt) |

Installing a newer version over an older one upgrades in place and keeps settings and
reports. (Before 1.2.0 the product was called *CybX Network Scanner*; installing
NetworkLens over it removes the old entry and carries its settings across. Reports it
saved stay in `Documents\CybX Network Scanner`.) For unattended deployment: `CybXNetworkLens-Setup-<version>.exe /S`
(add `/NODESKTOP` to skip the Desktop icon), and `Uninstall.exe /S` (add `/PURGE` to
also remove settings). A silent install cannot install Npcap — its free installer has
no silent mode — so the scanner offers it on first launch instead.

**Updating:** click **Check for Updates...** in the app — see [Updates](#updates).

> **"Windows protected your PC" (SmartScreen).** The installer is not code-signed, so
> Windows shows this warning the first time. Click **More info > Run anyway**. Signing
> the installer with a code-signing certificate is what removes the warning.

---

## Windows Setup (First Time - Complete Guide)

Follow these steps **once** on a Windows computer to create standalone `.exe` files that
work forever without needing to install anything again.

### Step 1: Install Python and NSIS (one-time only, for building)

1. Download Python from https://www.python.org/downloads/
2. **IMPORTANT**: During installation, check ✅ "Add Python to PATH"
3. Click "Install Now"
4. Install **NSIS**, the free tool that builds the installer — either run
   `winget install NSIS.NSIS` in a terminal, or download it from
   https://nsis.sourceforge.io/Download and accept the defaults.

Without NSIS the build still produces the portable executables, then stops with
`INSTALLER NOT BUILT` and tells you to install it.

### Step 2: Get the Nmap files

nmap.org no longer offers a portable zip, so either install Nmap or unpack its
installer:

1. Go to https://nmap.org/download.html and download the Windows installer
   (`nmap-X.XX-setup.exe`)
2. **Either** run it (you can untick Npcap and Zenmap) and copy the install directory:

   ```cmd
   xcopy /E /I /Y "C:\Program Files (x86)\Nmap" "binaries\windows"
   ```

   **or**, with [7-Zip](https://www.7-zip.org/) installed, unpack the installer
   without running it (this is what the GitHub release build does):

   ```cmd
   7z x nmap-X.XX-setup.exe -onmap-unpacked -y
   rmdir /S /Q nmap-unpacked\zenmap "nmap-unpacked\$PLUGINSDIR"
   del nmap-unpacked\Uninstall.exe
   xcopy /E /I /Y nmap-unpacked "binaries\windows"
   ```

   Either way, copy the **entire** folder into `binaries\windows\` — every file and
   every subfolder, not just `nmap.exe`.

**Copy everything — cherry-picking files will break the scan.** Nmap loads its
data files from the directory holding `nmap.exe`, and a missing one is a hard
failure, not a skipped feature. The `nselib\` folder is the usual casualty:
without it, every scan dies at startup with `failed to initialize the script
engine: module 'lpeg-utility' not found` instead of merely running without
scripts. `scripts\`, `nse_main.lua`, `nmap-os-db`, `nmap-services`,
`nmap-service-probes`, and all the `.dll` files matter for the same reason.

The scanner checks for these at launch and warns you if any are missing, so run
the built `.exe` once and read the first few lines of output before shipping it.

### Step 2b: Copy the Visual C++ runtime DLLs (also required!)

`nmap.exe` depends on Microsoft's Visual C++ runtime, and those DLLs are **not
in the nmap download**. Windows normally finds them in System32 — your build
machine has them there (Visual Studio or some installer put them there), but a
clean target machine does not, and on it the app fails with:

> The code execution cannot proceed because MSVCP140.dll was not found.

**This failure is invisible on the build machine** — scans work fine there
because the runtime is installed system-wide. Copy the two DLLs next to
`nmap.exe` so the bundle carries its own. Official nmap Windows builds are
32-bit, so take the 32-bit copies, which on 64-bit Windows live in `SysWOW64`
(the naming is backwards, that's correct):

From **Command Prompt** (cmd):

```cmd
copy /Y "C:\Windows\SysWOW64\msvcp140.dll"     "binaries\windows"
copy /Y "C:\Windows\SysWOW64\vcruntime140.dll" "binaries\windows"
```

From **PowerShell** (the default shell in Windows Terminal), use this instead —
in PowerShell `copy` means `Copy-Item`, which rejects the `/Y` flag with
"a positional parameter cannot be found that accepts argument 'binaries\windows'":

```powershell
Copy-Item "C:\Windows\SysWOW64\msvcp140.dll"     -Destination "binaries\windows" -Force
Copy-Item "C:\Windows\SysWOW64\vcruntime140.dll" -Destination "binaries\windows" -Force
```

Run either version from the repo root so `binaries\windows` resolves correctly.

The build self-test **fails** if these are missing, so a forgotten copy stops
the build instead of failing in the field. The full authoritative checklist of
every file `binaries\windows\` must contain is in
[binaries/windows/README.txt](binaries/windows/README.txt).

### Step 3: Build the Standalone Executables

1. Open **Command Prompt** (search "cmd" in Start menu)
2. Navigate to this folder:
   ```cmd
   cd C:\path\to\CybXNetworkLens
   ```
3. Install build dependencies:
   ```cmd
   pip install -r requirements.txt
   ```
4. Run the build script:
   ```cmd
   build\build_windows.bat
   ```
   The script automatically downloads the Npcap installer and bundles it into the
   executables (see [Npcap](#npcap-windows-only) below). If the download fails, the
   script tells you how to add it manually.
5. Wait for it to complete (10 minutes or so — it builds the two portable
   executables, the installed-app folder, and the installer)

The build runs what it just built against localhost — once for the portable
executable and once for the installed-app folder the installer ships. **If either
self-test fails, the build fails** and tells you what's missing, and no installer is
produced. A build that ends with `Build Complete - self-tests PASSED` can scan.

### Step 3b: Verifying a build yourself

You never have to guess whether a build works. Run it:

```cmd
dist\networklens.exe --self-test
```

It scans localhost through the real pipeline — the bundled nmap, the script
engine, the parser, the rule engine, and both report writers — and exits non-zero
if anything is missing. Run it any time you change what gets bundled, or on a
build someone handed you.

To check the GUI executable too (this one triggers a UAC prompt and writes
`dist\selftest_gui_log.txt`):

```cmd
dist\networklens-gui.exe --self-test
```

What the self-test proves: the bundle is complete and a scan runs end to end.
What it can't prove: raw-socket scanning works on the *target* machine, since that
depends on Npcap and Administrator rights there. The app checks those at startup.

### Step 4: Done! Hand out the installer, or go portable

Everything is now in `dist\`:
- `dist\CybXNetworkLens-Setup-<version>.exe` — **the installer**; see
  [Installing on Windows](#installing-on-windows-for-users)
- `dist\networklens-gui.exe` — the portable graphical scanner
- `dist\networklens.exe` — the portable command-line scanner

**To use the portable GUI instead of installing:**
1. Copy `dist\networklens-gui.exe` to your USB stick
2. On any Windows computer, double-click it
3. Approve the **UAC prompt** (the GUI auto-elevates to Administrator)
4. If Npcap isn't installed, approve the **"Install Npcap?"** dialog and click through
   the Npcap setup window that opens (one-time)
5. Enter a target and click **Start Scan**

**No Python or installation needed on target computers!**

---

## macOS Setup

```bash
# One-time: nmap is bundled from Homebrew
brew install nmap

# Build (bundles nmap + its data files + its libraries, then builds the CLI
# binary and the GUI .app and self-tests them)
chmod +x build/*.sh
./build/build_macos.sh
```

The build script fills `binaries/macos/` itself by running
`build/bundle_nmap_macos.sh`. Don't copy `nmap` there by hand: the binary alone is
not enough. nmap needs its data directory (`nselib/`, `scripts/`, `nmap-services`, ...)
or it aborts at startup, and the Homebrew binary links against Homebrew's OpenSSL,
libssh2, Lua, PCRE2 and liblinear by absolute path, so it won't start on a Mac
without Homebrew. The bundler copies all of it, rewrites the library paths to load
from the bundle, re-signs it, and refuses to leave an incomplete bundle. To refresh
after upgrading nmap, empty `binaries/macos/` (keep `README.txt`) and rebuild.

The result matches the CPU of the Mac you build on — a build from an Apple Silicon Mac
does not run on an Intel Mac. The app is unsigned, so on another Mac the first launch
needs right-click > Open (or allowing it under System Settings > Privacy & Security).

### Run

```bash
# CLI (needs sudo for SYN scan / OS detection)
sudo ./dist/networklens --target 192.168.1.0/24

# GUI
open ./dist/networklens-gui.app
# For full scan capabilities, launch the GUI with sudo from Terminal:
sudo ./dist/networklens-gui.app/Contents/MacOS/networklens-gui
```

macOS uses the built-in libpcap, so there is no Npcap-equivalent step. macOS does not
support UAC-style auto-elevation — use `sudo` for full scan features.

---

## Linux Setup

### Quick Build
```bash
# Install dependencies
pip3 install -r requirements.txt

# Copy nmap binary and data files
cp $(which nmap) binaries/linux/
cp -r /usr/share/nmap/* binaries/linux/

# Build (produces both CLI and GUI binaries)
chmod +x build/build_linux.sh
./build/build_linux.sh
```

### Run
```bash
# CLI
sudo ./dist/networklens --target 192.168.1.0/24

# GUI
sudo ./dist/networklens-gui
```

Linux uses the system libpcap. Linux does not auto-elevate — run with `sudo`, or wire up
a `.desktop` launcher with `pkexec` if you want a graphical elevation prompt.

---

## Npcap (Windows only)

Nmap on Windows needs **Npcap** — a packet-capture driver — for SYN scans, OS detection,
and most vulnerability scripts. Npcap installs a signed Windows kernel driver, so it
**cannot be packed inside the `.exe`**; it has to run its own installer once per machine.

To make this painless:

- **At build time**, `build_windows.bat` downloads the Npcap installer into
  `installers\windows\` and bundles it into both executables.
- **During install**, the setup wizard offers Npcap as a component when the machine
  doesn't have it, and opens Npcap's setup window.
- **At first launch on a new machine** (portable builds, or if it was skipped during
  install), the scanner detects that Npcap is missing and offers to install it:
  - **GUI** — a dialog appears; click **Yes**, then click through the Npcap setup
    window that opens (no extra UAC prompt, since the GUI is already elevated).
  - **CLI** — you're prompted at the terminal (needs an Administrator prompt).
- On every later launch, Npcap is detected and this step is skipped.

Npcap's setup window always appears: the free Npcap installer has no silent mode
(that is an Npcap OEM feature), so it cannot be installed invisibly.

If the build-time download fails, download the installer manually from
https://npcap.com/#download and drop `npcap-X.XX.exe` into `installers\windows\`, then
re-run the build. To pin a different version, edit `NPCAP_VERSION` near the top of
`build\build_windows.bat`.

### ⚠️ Npcap licensing

Npcap's free OEM redistribution license permits **up to 5 installations per organization
or site**. If you plan to distribute this scanner more broadly (e.g. shipping it to many
customers), you must purchase an Npcap OEM license: https://npcap.com/oem

---

## Updates

Releases are published on GitHub at
https://github.com/cybx-security/CybX-NetworkLens/releases, and the app updates itself
from there.

**For users:** click **Check for Updates...** (bottom right of the main window). If a
newer version exists you see what's new and can choose **Yes** to install it: the
installer downloads (about 50 MB), is verified against the release's checksums, the
app closes, the update installs silently, and the app reopens on the new version.
Settings and saved reports are kept. The app also checks once at startup and shows a
note in the status bar if an update exists; it never installs anything without being
asked. The portable exe, macOS and Linux builds can't replace themselves, so there the
button opens the download page instead. `networklens --check-update` does the same
check from the command line (exit code 10 = update available).

**Privacy:** the check is one request to `api.github.com` for the latest release. It
carries no information about you or any scanned network, only the app's version in the
User-Agent. Turn it off with `"updates": {"check_on_startup": false}` in the config;
the button still works on demand.

**Publishing a release (maintainers):**

1. Set the new version in `src/version.py` and commit.
2. Tag and push: `git tag v1.2.0 && git push origin main v1.2.0`.
3. GitHub Actions ([`release.yml`](.github/workflows/release.yml)) builds the Windows
   installer on a Windows runner — bundling nmap from nmap.org and running the same
   self-tests as a local build — and attaches `CybXNetworkLens-Setup-1.2.0.exe`,
   the portable exes and `SHA256SUMS` to a **draft** release.
4. Review the draft on the Releases page and click **Publish**. From that moment
   every installed copy's *Check for Updates* offers it. Nothing reaches customers
   while it is a draft.

A release **must** carry `SHA256SUMS` next to the installer: the updater refuses to
install anything it can't verify. Releases are unsigned, so integrity rests on HTTPS
plus those checksums — anyone who can publish a release to the repository can update
every customer machine. Guard that access accordingly. The CI build does not bundle
Npcap (its free licence doesn't allow redistribution); a release built locally with
`build\build_windows.bat` does, so prefer the CI builds for anything public.

---

## Usage (CLI)

```
networklens --target 192.168.1.0/24            # Scan a subnet
networklens --target 192.168.1.1 -p 22,80,443  # Specific ports
networklens --target 192.168.1.0/24 -T 5       # Fast scan
networklens --target 192.168.1.0/24 --no-vuln  # Skip vuln scripts (faster)
networklens --target 192.168.1.0/24 -o out.json # Custom output path
networklens --gui                              # Launch the GUI
networklens                                    # No args = launch the GUI
```

Each run writes two files next to each other: the JSON report and the `.ndjson`
Insights events (see [Output](#output)).

### All Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target IP, subnet, or range (required in CLI mode) |
| `--gui` | Launch the graphical interface instead of the CLI |
| `--output`, `-o` | Output file path |
| `--config`, `-c` | Custom config file path |
| `--ports`, `-p` | Specific ports to scan (overrides the balanced port set) |
| `--timing`, `-T` | Speed (0=slow/quiet, 5=fast/loud) |
| `--quick` | Quick scan: ports + service detection only (no scripts/UDP/OS). Fast sweep; port-exposure rules still fire |
| `--discover` | Ping sweep only: which hosts are alive, no ports. Seconds — use it to check a target range first |
| `--gentle` | For fragile gear (PLCs, medical devices, old printers): rate-capped, one probe at a time, no OS/vuln/UDP. Much slower |
| `--max-rate`, `--max-parallelism` | Cap packets per second / probes in flight on any mode |
| `--exclude`, `-x` | Comma-separated hosts to skip within the target |
| `--compare` | Previous report JSON to diff against: new/missing hosts, opened/closed ports, changed services |
| `--self-test` | Verify this build can scan (see Step 3b) |
| `--check-update` | Report whether a newer release is published (exit 10 if so) |
| `--no-vuln` | Skip vulnerability scripts (faster) |
| `--no-udp` | Skip the targeted UDP scan (faster; misses SNMP/IPMI/TFTP/NetBIOS) |
| `--quiet`, `-q` | Minimal output |

---

## Usage (GUI)

1. Launch **CybX NetworkLens** from the Desktop icon (or `networklens-gui` for
   the portable build). On Windows it auto-elevates.
2. Enter a **Target** (IP, range, or CIDR) and optionally specific **Ports**.
3. Pick a **Scan mode**:
   - **Discover** — ping sweep: which hosts are alive, in seconds. No ports probed.
   - **Gentle** — rate-capped, one probe at a time, no OS/vuln/UDP. For networks with
     fragile gear; much slower.
   - **Quick** — ports + service detection only. Fast sweep; exposed-service rules
     still fire (Redis, telnet, RDP, ...), but no scripts, UDP, or OS detection.
   - **Full** — the comprehensive scan: OS detection, targeted UDP, default + vuln
     scripts, traceroute, and all the script-based findings (TLS certs, SMB signing,
     SNMP defaults, CVEs). *(default)*

   The mode presets the detailed toggles below it (**OS Detection**, **Vulnerability
   Scripts**, **UDP**), which you can still fine-tune, along with **Timing**.
4. Click **Start Scan**. Watch the progress bar and the **Live Log** tab.
   **Stop** ends a scan early; a stopped scan saves nothing.
5. Review the **Inventory** tab (one row per device), the **Results** tab (per-host tree
   with risk levels, findings, recommendations) and the **Raw JSON** tab.
6. Every finished scan is saved automatically — **Open Output Folder** shows the files.
   **Save Report...** / **Save Insights Events...** / **Export Inventory CSV...** write
   extra copies wherever you choose; **Compare with Previous...** diffs against an older
   report.

---

## Configuration

Which config file is used:

- **Installed (Windows):** `C:\ProgramData\CybX\NetworkLens\config.json`. The
  installer creates it and upgrades never overwrite it. Edit it as Administrator.
- **Portable exe:** a `config.json` placed next to the exe, if there is one; otherwise
  the installed one above; otherwise the defaults built into the exe.
- **From source:** `config/config.json` in the repo.
- **Any of them:** `--config <path>` on the command line wins.

The GUI's Live Log shows which file was loaded at startup. The format:

```json
{
    "scan_options": {
        "port_scan": true,
        "service_detection": true,
        "os_detection": true,
        "vulnerability_scan": true,
        "udp_scan": true,
        "external_scripts": false,
        "timing": 4
    },
    "output": {
        "directory": "./output",
        "include_raw_nmap": false,
        "insights_events": {
            "enabled": true,
            "path": ""
        }
    },
    "updates": {
        "check_on_startup": true
    }
}
```

In a Windows path, double every backslash (`"C:\\Scans"`) or use forward slashes
(`"C:/Scans"`) — a single backslash is not valid JSON and the file will be ignored
with a warning.

- `scan_options` — defaults for the scan (overridable per-run by CLI flags / GUI toggles).
- `scan_options.udp_scan` — also scan the targeted high-value UDP ports (SNMP, IPMI, TFTP, NetBIOS, ...).
- `scan_options.external_scripts` — allow nmap scripts that contact third-party services
  (see [How analysis works](#how-analysis-works)). Off by default.
- `updates.check_on_startup` — look for a new release when the app starts (see [Updates](#updates)).
- `output.directory` — where reports and event files are written. An absolute path is
  used as-is. A relative one (like the default) is placed under
  `Documents\CybX NetworkLens\` for an installed or portable build, and under the
  repo folder when running from source — never under whatever folder the app happened
  to be started from.
- `output.include_raw_nmap` — embed the raw nmap XML in the JSON report.
- `output.insights_events.enabled` — write the per-port NDJSON events for Insights.
- `output.insights_events.path` — fixed file the Insights collector tails (appended each
  run). Empty = fresh per-scan `.ndjson` next to the report. See [`insights/`](insights/README.md).

The scanner makes **no external network calls** and needs no API keys — it only runs the
nmap scan and writes files locally.

---

## Output

Every scan writes **two** files:

1. **`scan_<target>_<time>.json`** — a full, human-readable report (one document
   with scan metadata, an overall summary, and a per-host breakdown). Good for
   review, archiving, and the GUI's *Save Report* button.
2. **`scan_<target>_<time>.ndjson`** — **per-port events for CybX Insight**, one
   compact JSON object per line (NDJSON). This is the file the Insights collector
   ingests to surface the ports in the dashboard.

### 1. Report JSON

```json
{
  "scan_metadata": { "timestamp": "2026-01-13T15:30:00Z", "target": "192.168.1.0/24", "hosts_up": 5 },
  "ai_analysis_summary": { "overall_risk": "medium", "executive_summary": "...", "priority_actions": ["..."] },
  "hosts": [
    { "ip": "192.168.1.1", "hostname": "router.local", "ports": [...], "os": {...},
      "vulnerabilities": [...],
      "ai_analysis": { "risk_level": "medium", "findings": ["..."], "recommendations": ["..."] } }
  ]
}
```

The `ai_analysis_summary` / `ai_analysis` field names are kept for compatibility with
CybX Insight, but the scanner only ever fills them with the **local rule-based** analysis.
The reporter is where any AI enrichment happens.

### 2. Insights events (NDJSON)

One event per open port, tagged `integration: "nmap_chat"` — the exact shape the
CybX Insight dashboard reads (`data.integration: "nmap_chat"`, one row per port).
Example line:

```json
{"integration":"nmap_chat","nmap":{"host":"192.168.1.50","os_guess":"Windows Server 2008 R2","port":445,"protocol":"tcp","service":"microsoft-ds","risk":"critical","cve_ids":[],"nse_results":""},"ai_assessment":{"summary":"SMB is exposed...","risk_level":"critical","findings":["..."],"recommendations":["..."],"source":"local"},"scan":{"target":"192.168.1.0/24","scanner_version":"1.0.0"}}
```

The `ai_assessment` field carries the local analysis (note `"source":"local"`). It keeps
that field name because it is the key CybX Insight reads (`data.ai_assessment`); the
reporter can enrich or replace it with an AI assessment on its side.

To get these into Insights, install the collector rules and config in
[`insights/`](insights/README.md) (a one-time setup done by a CybX engineer). In
short: the Insights collector tails the NDJSON file, classifies each event by risk,
and surfaces the ports per host. Set a fixed path so it tails one rolling file:

```json
"output": { "insights_events": { "enabled": true, "path": "/var/log/insights/nmap_chat.ndjson" } }
```

Combined with the other CybX data sources in Insights, these per-port events give
a clear picture of what is actually listening across a customer's internal network.

---

## Directory Structure

```
CybXNetworkLens/
├── src/                 # Python source code
│   ├── main.py          # CLI entry point (and GUI launcher)
│   ├── gui.py           # Tkinter GUI
│   ├── scanner.py       # nmap execution + balanced command builder
│   ├── scan_profile.py  # port coverage (top-1000 TCP + analyzer ports, UDP set)
│   ├── parser.py        # nmap XML parsing (ports, scripts, host scripts)
│   ├── local_analyzer.py# Offline rule-based analysis + result data types
│   ├── npcap.py         # Npcap detection + install (Windows)
│   ├── diff.py          # Scan-to-scan comparison
│   ├── selftest.py      # Build self-test (--self-test)
│   ├── paths.py         # Where config, reports and bundled files live
│   ├── version.py       # The version number (one place)
│   ├── updater.py       # Check for Updates: GitHub Releases, verify, install, relaunch
│   └── output.py        # Report JSON + Insights nmap_chat NDJSON events
├── config/config.json   # Scan + output settings (no secrets)
├── insights/            # CybX Insight collector rules + config for ingest
├── binaries/
│   ├── windows/         # Put nmap.exe + DLLs here
│   ├── macos/           # Filled by build/bundle_nmap_macos.sh (nmap + data + libs)
│   └── linux/           # Put nmap binary here
├── installers/
│   └── windows/         # Npcap installer (auto-downloaded at build time)
├── packaging/
│   ├── icon/            # App icon (.ico/.icns/.png) — regenerate with make_icon.py
│   ├── installed_app.spec   # PyInstaller build of the folder the installer ships
│   └── windows/installer.nsi # The Windows installer / uninstaller (NSIS)
├── .github/workflows/   # CI tests + the release build that feeds the updater
├── build/               # Build scripts
├── dist/                # Installer + executables (after build)
└── output/              # Scan results when running from source
```

---

## Privilege Requirements

**Administrator/root access is required** for the full balanced scan:
- SYN scan, UDP scan, OS detection, and traceroute all need raw sockets.

- **Windows GUI** — auto-elevates via UAC; just approve the prompt.
- **Windows CLI** — run from an Administrator Command Prompt / PowerShell.
- **macOS / Linux** — run with `sudo`.

**Run it with privileges for the best results.** Without them, the scanner detects
the lack of privileges and **degrades gracefully** rather than failing: it switches
to a TCP-connect scan (`-sT`) and drops UDP, OS detection, and traceroute, but still
does version detection and scripts. You get thinner (TCP-only) results instead of
nothing — but you'll miss SNMP/IPMI/TFTP (UDP), OS fingerprints, and topology.

---

## Security Notes

- Only scan networks you have permission to scan.
- The scanner runs entirely offline — nothing leaves the machine except the nmap probes
  themselves. The output files are written locally; the Insights collector is what
  forwards them.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "nmap not found" | Put nmap files in `binaries\windows\` (or `macos\` / `linux\`) before building |
| "Access denied" / limited results | Run as Administrator (Windows) or with `sudo` (macOS/Linux) |
| Scan fails on Windows even as Admin | Npcap isn't installed — approve the install prompt, or install from https://npcap.com |
| GUI says "Npcap not installed" with no installer | Build-time download failed; add `npcap-X.XX.exe` to `installers\windows\` and rebuild |
| Events not showing in Insights | Confirm the Insights collector tails the `.ndjson` path and the rules from `insights/` are installed — see [`insights/README.md`](insights/README.md) |
| Build fails | Make sure Python and pip are on PATH; run `pip install -r requirements.txt` |
| Build ends with `INSTALLER NOT BUILT` | NSIS isn't installed — `winget install NSIS.NSIS`, then re-run the build |
| Windows SmartScreen / antivirus blocks the installer or .exe | Unsigned PyInstaller binaries often trip heuristics on first run — **More info > Run anyway**, or whitelist it |
| Slow startup of the portable GUI | A single-file exe unpacks to temp on each launch. The installed version doesn't — use the installer |
| Can't find my scan reports | Click **Open Output Folder**; installed and portable builds save to `Documents\CybX NetworkLens\output` |
| Settings changes are ignored | The Live Log names the config file in use at startup, and warns if it couldn't be read (usually an unescaped `\` in a path) |
