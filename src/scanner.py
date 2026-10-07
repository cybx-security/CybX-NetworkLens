"""
Nmap execution module - handles running nmap with appropriate flags
and capturing output for parsing.
"""

import os
import shutil
import sys
import subprocess
import platform
from pathlib import Path
from typing import List, Optional, Tuple


# nmap.exe is a console-subsystem program, so on Windows every launch from the
# windowed GUI build flashes a black console window unless the spawn suppresses
# console creation. Pass this as creationflags= on every subprocess that runs
# nmap; it is 0 (no effect) on other platforms.
NO_WINDOW_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

# Data files nmap loads from its data directory at runtime. Bundling nmap.exe
# alone is not enough: nmap resolves these relative to the binary, and a missing
# one is not a soft failure. nse_main.lua in particular require()s modules out
# of nselib/ the moment any --script runs, so a bundle carrying the script
# engine but not its library aborts the entire scan during startup
# ("failed to initialize the script engine") instead of just skipping scripts.
_SERVICE_DATA = ('nmap-services', 'nmap-service-probes')
_OS_DATA = ('nmap-os-db',)
_NSE_DATA = ('nse_main.lua', 'nselib', 'scripts')
_REQUIRED_DATA = _SERVICE_DATA + _OS_DATA + _NSE_DATA

# The Microsoft Visual C++ runtime nmap.exe is linked against. These are NOT in
# the nmap zip or install directory — Windows normally resolves them from
# System32, where Visual Studio, the nmap installer, or some other app put them.
# That makes this the one bundling mistake no amount of testing on a dev machine
# can surface: a bundle without these DLLs runs fine anywhere the runtime is
# installed (every build machine) and dies on a clean machine with "the code
# execution cannot proceed because MSVCP140.dll was not found" before nmap
# executes a single instruction. Windows searches the exe's own directory before
# System32, so app-local copies beside nmap.exe make the bundle truly portable.
# Official nmap Windows builds are 32-bit: the matching DLLs live in
# C:\Windows\SysWOW64 on a 64-bit build machine.
_WIN_RUNTIME_DLLS = ('msvcp140.dll', 'vcruntime140.dll')

# Windows NTSTATUS for "a DLL the exe links against was not found"
# (STATUS_DLL_NOT_FOUND, 0xC0000135). The process exits with it before main()
# ever runs. subprocess reports it unsigned; the signed form shows up too.
_STATUS_DLL_NOT_FOUND = {0xC0000135, 0xC0000135 - 2**32}


def _system_nmap() -> Optional[str]:
    """Full path to an nmap on PATH, or None if there isn't one."""
    return shutil.which('nmap.exe' if platform.system().lower() == 'windows' else 'nmap')


def get_bundled_nmap_path() -> Path:
    """
    Where the bundled nmap binary lives for this OS, whether or not it exists.
    Works both from source and from a PyInstaller build (which unpacks into a
    temp _MEIPASS directory).
    """
    if getattr(sys, 'frozen', False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).parent.parent

    system = platform.system().lower()

    if system == 'windows':
        return base_path / 'binaries' / 'windows' / 'nmap.exe'
    elif system == 'darwin':
        return base_path / 'binaries' / 'macos' / 'nmap'
    elif system == 'linux':
        return base_path / 'binaries' / 'linux' / 'nmap'
    else:
        raise OSError(f"Unsupported operating system: {system}")


def resolve_nmap() -> Tuple[str, Optional[str], List[str]]:
    """
    Pick which nmap to run, and report which of its data files are missing.

    Returns (nmap_path, datadir, missing):
      - datadir is the --datadir to pass, set only for the bundled copy. Nmap
        would otherwise guess it from argv[0], which an NMAPDIR environment
        variable or a stray ~/.nmap can silently shadow.
      - missing lists the data files absent from that directory, so
        build_nmap_command can drop the flags they'd break.

    A bundled nmap only wins while its data directory is complete. An incomplete
    bundle is worse than no bundle — it looks installed and then fails at scan
    time — so a system-wide nmap install takes priority over one. The incomplete
    bundle is used only when the system has no nmap at all, and the scan then
    degrades to whatever those files still support.
    """
    bundled = get_bundled_nmap_path()

    if bundled.exists():
        datadir = bundled.parent
        missing = [name for name in _REQUIRED_DATA if not (datadir / name).exists()]

        # Ensure executable permission on Unix systems. Best effort: an
        # installed copy can be owned by root and already executable, and a
        # failed chmod there must not stop the scan.
        if platform.system().lower() != 'windows':
            try:
                os.chmod(bundled, 0o755)
            except OSError:
                pass

        if not missing:
            return str(bundled), str(datadir), []

        system_nmap = _system_nmap()
        if system_nmap:
            return system_nmap, None, []

        return str(bundled), str(datadir), missing

    system_nmap = _system_nmap()
    if system_nmap:
        return system_nmap, None, []

    system = platform.system().lower()
    raise FileNotFoundError(
        f"Nmap binary not found. Expected at: {bundled}\n"
        f"Please ensure nmap is bundled in the binaries/{system}/ directory "
        "or install nmap on the system."
    )


def get_nmap_binary_path() -> str:
    """Path of the nmap binary that will be used for scans."""
    return resolve_nmap()[0]


def missing_runtime_dlls() -> List[str]:
    """
    VC++ runtime DLLs absent from the Windows bundle.

    Empty on non-Windows, when no nmap is bundled, or when the bundle is
    complete. A non-empty result means the bundle only works on machines that
    already have the VC++ runtime installed — which includes every build
    machine, so this can never be caught by running the bundle locally; it has
    to be a file check.
    """
    if platform.system().lower() != 'windows':
        return []
    bundled = get_bundled_nmap_path()
    if not bundled.exists():
        return []
    return [name for name in _WIN_RUNTIME_DLLS
            if not (bundled.parent / name).exists()]


def exit_code_hint(returncode: int) -> Optional[str]:
    """
    Plain-language explanation for nmap exit codes that would otherwise surface
    as a bare number in the field, or None if the code has no special meaning.
    """
    if returncode in _STATUS_DLL_NOT_FOUND:
        return (
            "nmap.exe could not start: a DLL it depends on was not found "
            "(Windows STATUS_DLL_NOT_FOUND). This machine does not have the "
            "Microsoft Visual C++ runtime installed and the bundle does not "
            "carry its own copy. Fix the build: copy "
            + " and ".join(_WIN_RUNTIME_DLLS) +
            " from C:\\Windows\\SysWOW64 into binaries\\windows\\ next to "
            "nmap.exe and rebuild. Workaround on this machine only: install "
            "the Microsoft Visual C++ Redistributable (x86) from "
            "https://aka.ms/vs/17/release/vc_redist.x86.exe"
        )
    return None


def nmap_environment_warnings() -> List[str]:
    """
    Warnings about the nmap install that will be used, for the CLI/GUI to show
    before a scan. An incomplete bundle silently narrows what the scan covers,
    so it needs to be visible rather than showing up as thin results.
    """
    try:
        nmap_path, _datadir, missing = resolve_nmap()
    except (FileNotFoundError, OSError) as e:
        return [str(e)]

    # Warn even though scans work here: they work because THIS machine has the
    # VC++ runtime installed. The same bundle handed to a machine without it
    # fails with "MSVCP140.dll was not found" before nmap starts.
    runtime_missing = missing_runtime_dlls()
    warnings = []
    if runtime_missing:
        warnings.append(
            "This bundle is not portable: " + ", ".join(runtime_missing) +
            " missing next to nmap.exe. It will only run on machines that "
            "already have the Microsoft Visual C++ runtime. Copy the DLL(s) "
            "from C:\\Windows\\SysWOW64 into binaries\\windows\\ and rebuild."
        )

    if not missing:
        return warnings

    datadir = Path(nmap_path).parent
    warnings += [
        f"Bundled nmap is missing data files in {datadir}: {', '.join(missing)}",
        "Copy the ENTIRE nmap install directory into binaries/<os>/, not just "
        "nmap.exe — nmap needs its data files beside the binary.",
    ]
    if any(name in missing for name in _NSE_DATA):
        warnings.append("Scripts are disabled for this scan: no vuln/CVE checks "
                        "and no service script output.")
    if any(name in missing for name in _OS_DATA):
        warnings.append("OS detection is disabled for this scan (nmap-os-db missing).")
    if any(name in missing for name in _SERVICE_DATA):
        warnings.append("Service/version detection is disabled for this scan "
                        "(nmap-services / nmap-service-probes missing).")
    return warnings


def _balanced_port_arg(udp_scan: bool) -> str:
    """
    Build the -p spec for a balanced scan: top-1000 TCP unioned with every port
    the analyzer scores, plus (optionally) a targeted high-value UDP set. Kept as
    an explicit list because nmap forbids mixing --top-ports with -p, and a
    targeted UDP scan needs a per-protocol spec.
    """
    try:
        from scan_profile import balanced_tcp_ports, UDP_HIGH_VALUE
    except ImportError:
        from .scan_profile import balanced_tcp_ports, UDP_HIGH_VALUE
    tcp = ','.join(str(p) for p in balanced_tcp_ports())
    if udp_scan:
        udp = ','.join(str(p) for p in UDP_HIGH_VALUE)
        return f'T:{tcp},U:{udp}'
    return tcp


def script_expression(categories: List[str], external_scripts: bool = False) -> str:
    """
    The --script value for the given nmap script categories.

    Unless external_scripts is set this is a boolean expression that removes
    the `external` category, e.g. "(default or vuln) and not external", so the
    scan stays offline. See build_nmap_command for why.
    """
    if external_scripts:
        return ','.join(categories)
    selected = ' or '.join(categories)
    if len(categories) > 1:
        selected = f'({selected})'
    return f'{selected} and not external'


def normalize_exclude(exclude: Optional[str]) -> Optional[str]:
    """
    Clean a user-supplied exclude list into what nmap's --exclude expects:
    comma-separated with no whitespace. Users naturally type "10.0.0.5, 10.0.0.9"
    and nmap treats a spec with spaces as multiple arguments, so strip them and
    drop empty entries (trailing commas). Returns None if nothing remains.
    """
    if not exclude:
        return None
    parts = [p.strip() for p in exclude.split(',')]
    cleaned = ','.join(p for p in parts if p)
    return cleaned or None


def effective_port_count(custom_ports: Optional[str] = None, udp_scan: bool = False) -> int:
    """
    How many ports per host a scan will probe, for scan-duration estimates.

    Counts a custom -p spec if one is given (handling "22,80,443", "1-1000",
    and per-protocol "T:...,U:..." forms), otherwise the balanced profile.
    """
    try:
        from scan_profile import balanced_tcp_ports, UDP_HIGH_VALUE
    except ImportError:
        from .scan_profile import balanced_tcp_ports, UDP_HIGH_VALUE

    if not custom_ports:
        return len(balanced_tcp_ports()) + (len(UDP_HIGH_VALUE) if udp_scan else 0)

    count = 0
    for chunk in custom_ports.split(','):
        chunk = chunk.strip()
        # Strip a leading protocol selector ("T:80" / "U:161"); a bare "T:" that
        # prefixes a run of ports applies to the rest of the list, and either way
        # we only care about how many ports it names.
        if len(chunk) > 1 and chunk[1] == ':':
            chunk = chunk[2:]
        if not chunk:
            continue
        if '-' in chunk:
            lo, _, hi = chunk.partition('-')
            try:
                count += max(1, int(hi) - int(lo) + 1)
            except ValueError:
                count += 1
        else:
            count += 1
    return count or 1


def rate_limit_warning(target: str, max_rate: Optional[int],
                       custom_ports: Optional[str] = None,
                       udp_scan: bool = False) -> Optional[str]:
    """
    Warning text when a rate cap will make this scan take a long time, else None.

    A 50 pps cap across a /24 is hours of wall clock. That is the correct
    trade-off on fragile gear, but it has to be stated up front rather than
    discovered an hour in.
    """
    if not max_rate:
        return None
    try:
        from scan_profile import estimate_scan_seconds, format_duration
    except ImportError:
        from .scan_profile import estimate_scan_seconds, format_duration

    seconds = estimate_scan_seconds(target, effective_port_count(custom_ports, udp_scan), max_rate)
    if seconds is None or seconds < 1800:  # under 30 min needs no warning
        return None
    return (f"At {max_rate} packets/sec this scan will take at least "
            f"{format_duration(seconds)} (probably longer — the estimate ignores "
            f"retransmits, service detection, and scripts). Narrow the target or "
            f"the port list if that is too slow.")


def build_nmap_command(
    target: str,
    port_scan: bool = True,
    service_detection: bool = True,
    os_detection: bool = True,
    vulnerability_scan: bool = True,
    udp_scan: bool = True,
    default_scripts: bool = True,
    traceroute: bool = True,
    timing: int = 4,
    custom_ports: Optional[str] = None,
    exclude: Optional[str] = None,
    max_rate: Optional[int] = None,
    max_parallelism: Optional[int] = None,
    discovery_only: bool = False,
    xml_output_path: Optional[str] = None,
    privileged: Optional[bool] = None,
    external_scripts: bool = False,
) -> list:
    """
    Build the nmap command for a "balanced" scan.

    Beyond a basic SYN + version + OS scan, this widens coverage and adds the
    context that makes results actionable:
      - Port coverage: top-1000 TCP plus every port the analyzer can score, so
        the scan reaches services like Redis/MongoDB/Docker that sit outside the
        default top-1000.
      - Targeted UDP: a small high-value UDP set (SNMP, IPMI, TFTP, NetBIOS, ...)
        that a TCP-only scan would miss entirely.
      - Scripts: nmap's `default` set (service context — SSL certs, SMB signing,
        HTTP titles, SNMP info) plus, optionally, the `vuln` category (CVEs).
      - Traceroute: network path, for topology / landscape.

    Args:
        target: IP address, hostname, or CIDR subnet to scan.
        port_scan: Enable TCP SYN scan.
        service_detection: Enable service/version detection.
        os_detection: Enable OS detection (requires root).
        vulnerability_scan: Include the nmap `vuln` script category.
        udp_scan: Also scan the targeted high-value UDP ports (requires root).
        default_scripts: Run nmap's `default` (-sC) scripts for service context
            (TLS certs, SMB signing, HTTP titles, ...). Turn off for a quick scan.
        timing: Timing template (0-5, higher = faster/noisier).
        custom_ports: Explicit port spec (e.g. "22,80,443" or "T:22,U:161"). When
            set, it overrides the balanced port set and UDP is only added if the
            spec itself contains a "U:" section.
        exclude: Comma-separated hosts to skip within the target range
            (e.g. "192.168.1.5,192.168.1.10"). Accepts anything nmap's
            --exclude does: IPs, hostnames, or CIDR blocks.
        max_rate: Cap on packets per second across the whole scan. The main
            brake for fragile networks — nmap otherwise sends as fast as the
            timing template allows, which is what knocks embedded gear offline.
        max_parallelism: Cap on outstanding probes. 1 means strictly one probe
            in flight at a time, the gentlest setting nmap offers.
        discovery_only: Ping sweep (-sn): find which hosts are alive and stop
            there — no port scan, services, OS, or scripts. Seconds instead of
            minutes, and the fastest way to confirm a target range is right
            before committing to a real scan. Overrides the feature flags above,
            since nmap rejects -sn combined with port-scan options.
        external_scripts: Allow nmap scripts in the `external` category. Off by
            default because they talk to third parties: `vulners` (part of
            `vuln`) uploads every detected product and version to vulners.com,
            which breaks the promise that nothing about the scanned network
            leaves the machine. Turning this on trades that for version-based
            CVE lookups, and needs internet access to do anything.
        privileged: Whether the process has root/admin. Defaults to auto-detect.
            SYN scan, UDP scan, OS detection, and traceroute all require raw
            sockets; without them nmap QUITS rather than skipping. So when not
            privileged we degrade gracefully to a TCP-connect scan (still with
            version detection and scripts) instead of returning nothing.

    Returns:
        List of command arguments for subprocess.
    """
    if privileged is None:
        privileged = check_privileges()

    nmap_path, datadir, missing = resolve_nmap()
    cmd = [nmap_path]

    # Point the bundled nmap at its own data files explicitly rather than
    # letting it infer the location from argv[0].
    if datadir:
        cmd.extend(['--datadir', datadir])

    # Discovery-only: a ping sweep and nothing else. Handled before every other
    # option because nmap refuses -sn alongside port-scan flags, so this is a
    # different command shape rather than a variation on one.
    if discovery_only:
        cmd.append('-sn')
        cmd.append(f'-T{timing}')
        if max_rate and max_rate > 0:
            cmd.extend(['--max-rate', str(max_rate)])
        if max_parallelism and max_parallelism > 0:
            cmd.extend(['--max-parallelism', str(max_parallelism)])
        exclude_spec = normalize_exclude(exclude)
        if exclude_spec:
            cmd.extend(['--exclude', exclude_spec])
        cmd.extend(['-oX', xml_output_path if xml_output_path else '-'])
        cmd.append(target)
        return cmd

    # Any data file nmap needs but doesn't have turns its feature into a hard
    # startup failure, so drop the corresponding flag instead. Same reasoning as
    # the unprivileged degradation below: a narrower scan beats no scan.
    can_script = not any(name in missing for name in _NSE_DATA)
    can_detect_os = not any(name in missing for name in _OS_DATA)
    can_detect_services = not any(name in missing for name in _SERVICE_DATA)

    # Port scan: SYN when privileged (fast, stealthy), else TCP connect so an
    # unprivileged run still returns results instead of quitting.
    if port_scan:
        cmd.append('-sS' if privileged else '-sT')

    # UDP scan of the targeted high-value ports — raw sockets, root only. With a
    # custom port spec we honor exactly what the user asked (only add -sU if the
    # spec includes a UDP section).
    do_udp = udp_scan and privileged and (not custom_ports or 'U:' in custom_ports.upper())
    if do_udp:
        cmd.append('-sU')

    # Service/version detection (works unprivileged)
    if service_detection and can_detect_services:
        cmd.append('-sV')

    # OS detection (requires root)
    if os_detection and privileged and can_detect_os:
        cmd.append('-O')

    # Scripts: default set (informative service context) and/or the vuln category
    # (CVE/exploit checks). Most run unprivileged; the few that need raw sockets
    # skip themselves rather than aborting the scan. A quick scan runs neither.
    script_cats = []
    if default_scripts:
        script_cats.append('default')
    if vulnerability_scan:
        script_cats.append('vuln')
    if script_cats and can_script:
        cmd.append('--script=' + script_expression(script_cats, external_scripts))

    # Network path for topology / landscape (traceroute needs root; adding it
    # unprivileged makes nmap quit outright, so only include it when privileged)
    if traceroute and privileged:
        cmd.append('--traceroute')

    # Timing template
    cmd.append(f'-T{timing}')

    # Rate limiting. These come after -T deliberately: nmap lets later options
    # override the template's rate settings, so an explicit cap wins over
    # whatever -T implies rather than being silently ignored.
    if max_rate and max_rate > 0:
        cmd.extend(['--max-rate', str(max_rate)])
    if max_parallelism and max_parallelism > 0:
        cmd.extend(['--max-parallelism', str(max_parallelism)])

    # Ports: explicit user spec, or the balanced top-1000+analyzer(+UDP) set
    if custom_ports:
        cmd.extend(['-p', custom_ports])
    else:
        cmd.extend(['-p', _balanced_port_arg(do_udp)])

    # Hosts to skip within the target range (printers, fragile gear, ...)
    exclude_spec = normalize_exclude(exclude)
    if exclude_spec:
        cmd.extend(['--exclude', exclude_spec])

    # XML output: stdout (default) or a file path (used by the GUI so progress
    # can stream on stdout without conflicting with the XML payload).
    cmd.extend(['-oX', xml_output_path if xml_output_path else '-'])

    # Add target
    cmd.append(target)

    return cmd


def format_command(cmd: List[str]) -> str:
    """A command line for display, quoted so it can be pasted into a shell."""
    return ' '.join(f'"{arg}"' if (' ' in arg or '(' in arg) else arg for arg in cmd)


def run_scan(
    target: str,
    port_scan: bool = True,
    service_detection: bool = True,
    os_detection: bool = True,
    vulnerability_scan: bool = True,
    udp_scan: bool = True,
    default_scripts: bool = True,
    traceroute: bool = True,
    timing: int = 4,
    custom_ports: Optional[str] = None,
    exclude: Optional[str] = None,
    max_rate: Optional[int] = None,
    max_parallelism: Optional[int] = None,
    discovery_only: bool = False,
    external_scripts: bool = False,
    timeout: Optional[int] = None
) -> Tuple[str, str, int]:
    """
    Execute an nmap scan and return the results.

    Args:
        target: IP address, hostname, or CIDR subnet to scan
        port_scan: Enable TCP SYN scan
        service_detection: Enable service/version detection
        os_detection: Enable OS detection (requires root)
        vulnerability_scan: Run vulnerability scripts
        udp_scan: Also scan the targeted high-value UDP ports (requires root)
        timing: Timing template (0-5)
        custom_ports: Custom port specification
        exclude: Comma-separated hosts to skip within the target range
        max_rate: Cap on packets per second (fragile networks)
        max_parallelism: Cap on outstanding probes (fragile networks)
        discovery_only: Ping sweep only — which hosts are alive, no port scan
        timeout: Maximum time to wait for scan completion (seconds). None
            (the default) waits as long as the scan takes: a full /24 or a
            rate-capped gentle scan legitimately runs for hours, and a fixed
            cap throws the whole result away at the deadline.

    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    cmd = build_nmap_command(
        target=target,
        port_scan=port_scan,
        service_detection=service_detection,
        os_detection=os_detection,
        vulnerability_scan=vulnerability_scan,
        udp_scan=udp_scan,
        default_scripts=default_scripts,
        traceroute=traceroute,
        timing=timing,
        custom_ports=custom_ports,
        exclude=exclude,
        max_rate=max_rate,
        max_parallelism=max_parallelism,
        discovery_only=discovery_only,
        external_scripts=external_scripts
    )

    print(f"[*] Running scan: {format_command(cmd)}")
    print(f"[*] Target: {target}")
    excluded = normalize_exclude(exclude)
    if excluded:
        print(f"[*] Excluding: {excluded}")
    if max_rate:
        print(f"[*] Rate limited to {max_rate} packets/sec")
    if discovery_only:
        print("[*] Discovery only: finding live hosts, not scanning ports.")
    else:
        print(f"[*] This may take several minutes for large subnets...")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            # nmap writes its XML as UTF-8. Decoding with the Windows locale
            # codepage instead garbles non-ASCII banners and can raise
            # outright on bytes that codepage doesn't define.
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            creationflags=NO_WINDOW_FLAGS
        )
        
        if result.returncode != 0 and result.stderr:
            # Check for common errors
            if "requires root privileges" in result.stderr.lower():
                print("[!] Error: This scan requires root/administrator privileges.")
                print("[!] Please run with sudo (Linux/macOS) or as Administrator (Windows).")
            elif "failed to open" in result.stderr.lower():
                print("[!] Error: Network interface issue. Check your network connection.")
        
        return result.stdout, result.stderr, result.returncode
        
    except subprocess.TimeoutExpired:
        print(f"[!] Scan timed out after {timeout} seconds")
        raise
    except Exception as e:
        print(f"[!] Error running nmap: {e}")
        raise


def check_privileges() -> bool:
    """
    Check if the current process has root/administrator privileges.
    """
    system = platform.system().lower()
    
    if system == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def get_nmap_version() -> Optional[str]:
    """
    Get the version of the nmap binary.
    """
    try:
        nmap_path = get_nmap_binary_path()
        result = subprocess.run(
            [nmap_path, '--version'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=60,
            creationflags=NO_WINDOW_FLAGS
        )
        if result.returncode == 0:
            # Extract version from first line
            first_line = result.stdout.split('\n')[0]
            return first_line
    except Exception:
        pass
    return None
