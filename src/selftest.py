"""
Post-build self-test - proves a built binary can actually complete a scan.

This exists because of a specific failure: a Windows build shipped with
nmap.exe but without nselib/, so every scan died at startup with "failed to
initialize the script engine". Checking a list of expected files would not have
prevented it in general, because the list only ever covers the files someone
thought to write down, and nselib/ wasn't one of them. The check that
generalizes is to stop inspecting the bundle and just use it: run a real scan
through the real pipeline and see whether it works.

So this runs an actual localhost scan with scripts enabled, then feeds the
result through the parser, analyzer, and both report writers. Anything missing
from the bundle - an nmap data file, an NSE library, a Python module PyInstaller
failed to pick up - fails here, at build time, instead of on a user's machine.

Deliberately NOT covered: privileged networking. The self-test forces an
unprivileged TCP connect scan, because raw sockets on the loopback adapter
behave inconsistently on Windows and the build machine's Npcap state says
nothing about the target machine's anyway. Npcap is checked at app startup
instead. What this proves is bundle integrity, not network capability.
"""

import platform
import subprocess
import sys
import tempfile
import os
from typing import Callable, List, Tuple

try:
    from scanner import (build_nmap_command, resolve_nmap, get_nmap_version,
                         missing_runtime_dlls, exit_code_hint, format_command,
                         NO_WINDOW_FLAGS)
    from parser import parse_nmap_xml, nmap_run_error
    from local_analyzer import analyze_locally
    from output import create_insights_report, create_nmap_chat_events
    from paths import icon_path
    from version import __version__
except ImportError:
    from .scanner import (build_nmap_command, resolve_nmap, get_nmap_version,
                          missing_runtime_dlls, exit_code_hint, format_command,
                         NO_WINDOW_FLAGS)
    from .parser import parse_nmap_xml, nmap_run_error
    from .local_analyzer import analyze_locally
    from .output import create_insights_report, create_nmap_chat_events
    from .paths import icon_path
    from .version import __version__


SELF_TEST_TARGET = "127.0.0.1"
SELF_TEST_PORTS = "80,443"
SELF_TEST_TIMEOUT = 300


def run_self_test(log: Callable[[str], None] = print) -> Tuple[bool, List[str]]:
    """
    Run the full scan pipeline against localhost.

    Returns (passed, failures). Each failure is a human-readable description of
    what is wrong with this build and, where possible, how to fix it.
    """
    failures: List[str] = []

    log("=" * 60)
    log(f"  CybX Network Scanner {__version__} - build self-test")
    log("=" * 60)
    log("")

    # ---- 1. Is there an nmap at all, and which one won? ----
    try:
        nmap_path, datadir, missing = resolve_nmap()
    except (FileNotFoundError, OSError) as e:
        failures.append(f"No usable nmap: {e}")
        _report(log, failures)
        return False, failures

    log(f"[*] nmap binary : {nmap_path}")
    log(f"[*] data dir    : {datadir or '(system default)'}")
    log(f"[*] version     : {get_nmap_version() or 'unknown'}")

    frozen = getattr(sys, "frozen", False)

    if datadir is None:
        # Falling back to the machine's own nmap is fine when running from
        # source, and fatal for a built executable meant to be handed to someone
        # who won't have nmap installed.
        msg = ("Using the machine's own nmap install, not a bundled copy. This "
               "will not scan on a machine without nmap installed. Copy the "
               "entire nmap directory into binaries/<os>/ and rebuild.")
        if frozen:
            failures.append(msg)
        else:
            log(f"[!] {msg}")
            log("    (only a warning here - this is running from source, not a build)")
    elif missing:
        failures.append(
            "Bundled nmap is missing data files: " + ", ".join(missing) +
            ". Copy the ENTIRE nmap install directory into binaries/<os>/."
        )

    # ---- 1b. Windows: is the C++ runtime bundled next to nmap.exe? ----
    # This is the one dependency the run-based test below CANNOT catch: nmap.exe
    # needs the VC++ runtime (msvcp140.dll etc.), and every build machine has it
    # installed system-wide, so the test scan succeeds here even when the bundle
    # lacks the DLLs — and then fails on a clean machine with "MSVCP140.dll was
    # not found". Always a failure, not a warning: a bundle without these DLLs
    # is broken as shipped content regardless of how it's being run right now.
    runtime_missing = missing_runtime_dlls()
    if runtime_missing:
        failures.append(
            "The Visual C++ runtime is not bundled: " +
            ", ".join(runtime_missing) + " missing next to nmap.exe. "
            "The test scan below may still pass because THIS machine has the "
            "runtime installed system-wide, but the build will fail on any "
            "machine that doesn't, before nmap even starts. Copy the DLL(s) "
            "from C:\\Windows\\SysWOW64 into binaries\\windows\\ and rebuild."
        )
    elif platform.system().lower() == "windows" and datadir is not None:
        log("[+] VC++ runtime DLLs are bundled next to nmap.exe.")

    # ---- 1c. Is the app icon in the bundle? ----
    # The window and taskbar icon is loaded from this file at startup. Only a
    # built executable is held to it: from source the file is simply in the repo.
    if frozen and platform.system().lower() == "windows" and icon_path("ico") is None:
        failures.append(
            "The app icon is not bundled (packaging\\icon\\icon.ico). The build "
            "must pass --add-data \"packaging\\icon;packaging\\icon\"."
        )

    log("")

    # ---- 2. Run a real scan, with scripts on ----
    # Scripts are forced on regardless of missing files: this step has to
    # actually attempt NSE startup, since that is the failure being guarded
    # against. privileged=False keeps it to a TCP connect scan.
    tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    tmp.close()
    xml = ""
    try:
        cmd = build_nmap_command(
            target=SELF_TEST_TARGET,
            port_scan=True,
            service_detection=True,
            os_detection=False,
            vulnerability_scan=True,
            udp_scan=False,
            default_scripts=True,
            traceroute=False,
            timing=4,
            custom_ports=SELF_TEST_PORTS,
            xml_output_path=tmp.name,
            privileged=False,
        )
        cmd.append("-Pn")  # skip host discovery so the test can't hang on it

        if "--script" not in " ".join(cmd):
            failures.append(
                "The script engine was disabled before the scan even started, "
                "so this build cannot run vuln/CVE checks."
            )

        log(f"[*] Test scan   : {SELF_TEST_TARGET} ports {SELF_TEST_PORTS}")
        log(f"$ {format_command(cmd)}")
        log("")

        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=SELF_TEST_TIMEOUT,
                                creationflags=NO_WINDOW_FLAGS)

        if os.path.exists(tmp.name):
            with open(tmp.name, "r", encoding="utf-8", errors="replace") as f:
                xml = f.read()

        run_error = nmap_run_error(xml)
        if run_error:
            failures.append("nmap aborted instead of scanning:\n    " +
                            run_error.strip().replace("\n", "\n    "))
        elif not xml:
            # No XML at all means nmap never got far enough to write results,
            # whatever it claimed in its exit code.
            failures.append(
                f"nmap produced no scan output (exit code {result.returncode}).\n"
                f"    {(result.stderr or result.stdout or '').strip()[:500]}"
            )
        elif result.returncode != 0:
            hint = exit_code_hint(result.returncode)
            failures.append(
                f"nmap exited with code {result.returncode}."
                + (f"\n    {hint}" if hint else "") +
                f"\n    {(result.stderr or result.stdout or '').strip()[:500]}"
            )
        else:
            log("[+] nmap completed the scan.")

    except subprocess.TimeoutExpired:
        failures.append(f"The test scan did not finish within {SELF_TEST_TIMEOUT}s.")
    except Exception as e:
        failures.append(f"Could not run the test scan: {e}")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    # ---- 3. Push it through the rest of the pipeline ----
    # Catches Python modules PyInstaller failed to bundle, which fail the same
    # way as missing nmap data: fine from source, broken in dist/.
    if xml and not any("aborted" in f for f in failures):
        try:
            scan_result = parse_nmap_xml(xml)
            log(f"[+] Parsed results ({scan_result.total_hosts_up} host(s) up).")
        except Exception as e:
            failures.append(f"Could not parse nmap output: {e}")
            scan_result = None

        if scan_result is not None:
            try:
                analysis = analyze_locally(scan_result)
                log(f"[+] Rule engine ran (risk: {analysis.overall_risk.upper()}).")
                create_insights_report(scan_result, analysis, SELF_TEST_TARGET, __version__)
                create_nmap_chat_events(scan_result, analysis, SELF_TEST_TARGET, __version__)
                log("[+] Report and Insights events generated.")
            except Exception as e:
                failures.append(f"Report generation failed: {e}")

    _report(log, failures)
    return not failures, failures


def _report(log: Callable[[str], None], failures: List[str]) -> None:
    log("")
    log("=" * 60)
    if failures:
        log(f"  SELF-TEST FAILED - {len(failures)} problem(s)")
        log("=" * 60)
        for i, f in enumerate(failures, 1):
            log(f"  {i}. {f}")
        log("")
        log("  This build will NOT work correctly. Fix the above and rebuild.")
    else:
        log("  SELF-TEST PASSED - this build can scan.")
        log("=" * 60)
        log("")
        log("  Verified: bundled nmap runs, script engine initializes,")
        log("  results parse, and reports generate.")
        log("  Not verified: raw-socket scanning (needs Npcap + admin on the")
        log("  target machine; the app checks this at startup).")
    log("")


def main() -> int:
    passed, _ = run_self_test()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
