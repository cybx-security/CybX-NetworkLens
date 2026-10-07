#!/usr/bin/env python3
"""
CybX NetworkLens - Portable Network Scanner

A cross-platform tool that runs nmap scans, parses the results, and analyzes
them with an offline rule engine. Output is written two ways: a full JSON
report, and per-port Insights events (NDJSON) for ingestion into CybX Insight,
where any AI enrichment happens.

Usage:
    python main.py --target 192.168.1.0/24 --output ./results.json
    python main.py --target 10.0.0.1 --config ./config.json
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Optional

# Handle imports for both development and packaged execution
try:
    from scanner import (run_scan, check_privileges, get_nmap_version,
                         nmap_environment_warnings, rate_limit_warning)
    from scan_profile import GENTLE_SCAN, GENTLE_MAX_RATE
    from parser import parse_nmap_xml, nmap_run_error
    from local_analyzer import analyze_locally
    from output import (create_insights_report, write_json_output, generate_filename,
                        print_summary, create_nmap_chat_events, write_ndjson_events)
    from npcap import is_windows, is_npcap_installed, find_bundled_installer, install_npcap
    from paths import config_candidates, resolve_output_dir
    from version import __version__
except ImportError:
    from .scanner import (run_scan, check_privileges, get_nmap_version,
                          nmap_environment_warnings, rate_limit_warning)
    from .scan_profile import GENTLE_SCAN, GENTLE_MAX_RATE
    from .parser import parse_nmap_xml, nmap_run_error
    from .local_analyzer import analyze_locally
    from .output import (create_insights_report, write_json_output, generate_filename,
                         print_summary, create_nmap_chat_events, write_ndjson_events)
    from .npcap import is_windows, is_npcap_installed, find_bundled_installer, install_npcap
    from .paths import config_candidates, resolve_output_dir
    from .version import __version__


def load_config(config_path: Optional[str] = None, log=print) -> dict:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to config file, or None for default
        log: Where status lines go. The GUI passes its own so a config that
            failed to load shows up in the log instead of vanishing with the
            console a windowed build doesn't have.
    
    Returns:
        Configuration dictionary
    """
    # Default configuration
    default_config = {
        "scan_options": {
            "port_scan": True,
            "service_detection": True,
            "os_detection": True,
            "vulnerability_scan": True,
            "udp_scan": True,
            "external_scripts": False,
            "timing": 4
        },
        "output": {
            "directory": "./output",
            "include_raw_nmap": False,
            "insights_events": {"enabled": True, "path": ""}
        },
        "updates": {
            "check_on_startup": True
        }
    }

    if config_path:
        config_file = Path(config_path)
        if not config_file.exists():
            # Asked for by name, so say so: silently scanning with defaults
            # would look like the settings in that file had been applied.
            log(f"[!] Warning: config file not found: {config_file} - using defaults")
            return default_config
    else:
        # Standard locations - see paths.config_candidates for the order.
        config_file = next((p for p in config_candidates() if p.exists()), None)

    if config_file:
        try:
            with open(config_file, 'r', encoding='utf-8-sig') as f:
                user_config = json.load(f)

            # Merge with defaults
            for key, value in user_config.items():
                if isinstance(value, dict) and isinstance(default_config.get(key), dict):
                    default_config[key].update(value)
                else:
                    default_config[key] = value

            log(f"[*] Loaded configuration from: {config_file}")
        except Exception as e:
            log(f"[!] Warning: Could not load config file {config_file}: {e}")
    else:
        log("[*] Using default configuration")

    return default_config


def _positive_int(value: str) -> int:
    """argparse type for options where zero or a negative number is a typo."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}")
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than zero, got {number}")
    return number


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CybX NetworkLens - portable nmap scanner with local analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.0/24
  %(prog)s --target 192.168.1.0/24 --exclude 192.168.1.5,192.168.1.10
  %(prog)s --target 10.0.0.1-50 --output ./scan_results.json
  %(prog)s --target 192.168.1.0/24 --compare ./output/last_month.json
  %(prog)s --target 192.168.1.0/24 --discover      (fast: who is alive, no port scan)
  %(prog)s --target 10.10.0.0/24 --gentle          (fragile gear: PLCs, medical, printers)
  %(prog)s --target 10.10.0.0/24 --max-rate 20     (custom rate cap on any mode)
  %(prog)s --target 192.168.1.1 --no-vuln --output ./quick_scan.json

Note: This tool requires root/administrator privileges for full scan functionality.
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        required=False,
        help='Target IP, hostname, or CIDR subnet to scan (e.g., 192.168.1.0/24). Required for CLI mode.'
    )

    parser.add_argument(
        '--self-test',
        action='store_true',
        help='Verify this build can actually scan: runs a localhost scan through '
             'the full pipeline and exits non-zero if anything is missing. Run '
             'this on the built executable before shipping it.'
    )

    parser.add_argument(
        '--check-update',
        action='store_true',
        help='Ask GitHub Releases whether a newer version is published, print it, and exit.'
    )

    parser.add_argument(
        '--gui',
        action='store_true',
        help='Launch the graphical interface instead of running on the command line.'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: auto-generated in output directory)'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file (default: the installed config.json)'
    )
    
    parser.add_argument(
        '--ports', '-p',
        help='Custom port specification (e.g., "22,80,443" or "1-1000")'
    )

    parser.add_argument(
        '--exclude', '-x',
        help='Comma-separated hosts to skip within the target range '
             '(e.g., "192.168.1.5,192.168.1.10"). Accepts IPs, hostnames, or CIDR blocks.'
    )
    
    parser.add_argument(
        '--compare',
        metavar='PREVIOUS_REPORT',
        help='Path to a previous scan report (JSON) to compare against. After '
             'the scan, prints what changed: new/missing hosts, opened/closed '
             'ports, and changed services.'
    )

    parser.add_argument(
        '--timing', '-T',
        type=int,
        choices=[0, 1, 2, 3, 4, 5],
        help='Timing template (0=paranoid, 5=insane). Overrides config.'
    )
    
    parser.add_argument(
        '--no-vuln',
        action='store_true',
        help='Skip vulnerability scanning (faster but less comprehensive)'
    )

    parser.add_argument(
        '--no-udp',
        action='store_true',
        help='Skip the targeted UDP scan (faster; misses SNMP/IPMI/TFTP/NetBIOS)'
    )

    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan: ports + service detection only (no scripts, UDP, or OS '
             'detection). Fast sweep; port-exposure rules still fire.'
    )

    parser.add_argument(
        '--discover',
        action='store_true',
        help='Discovery only: ping sweep to find which hosts are alive, no port '
             'scanning. Takes seconds instead of minutes — use it to confirm a '
             'target range is right before committing to a full scan.'
    )

    parser.add_argument(
        '--gentle',
        action='store_true',
        help='Gentle scan for fragile networks (PLCs, medical devices, old '
             f'printers): rate-capped to {GENTLE_MAX_RATE} packets/sec, one probe at a time, '
             'T2 timing, and no OS detection, vuln scripts, or UDP — the parts '
             'most likely to knock delicate gear offline. Much slower.'
    )

    parser.add_argument(
        '--max-rate',
        type=_positive_int,
        metavar='PPS',
        help='Cap the scan at this many packets per second. Overrides the '
             '--gentle default. Use on any network you need to tread lightly on.'
    )

    parser.add_argument(
        '--max-parallelism',
        type=_positive_int,
        metavar='N',
        help='Cap outstanding probes (1 = strictly one probe in flight). '
             'Overrides the --gentle default.'
    )

    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output (only errors and final result path)'
    )
    
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    # If the user double-clicked the executable (no CLI args) or asked for it
    # explicitly with --gui, launch the GUI and skip the CLI flow entirely.
    bare_invocation = len(sys.argv) == 1
    wants_gui = bare_invocation or '--gui' in sys.argv
    if wants_gui:
        try:
            try:
                from gui import launch as launch_gui
            except ImportError:
                from .gui import launch as launch_gui
        except Exception as e:
            print(f"[!] Failed to load GUI: {e}")
            print("[!] If you meant to run on the command line, pass --target.")
            return 1
        return launch_gui()

    args = parse_arguments()

    if args.self_test:
        try:
            from selftest import run_self_test
        except ImportError:
            from .selftest import run_self_test
        passed, _ = run_self_test()
        return 0 if passed else 1

    if args.check_update:
        try:
            from updater import check_for_update, UpdateError, RELEASES_PAGE
        except ImportError:
            from .updater import check_for_update, UpdateError, RELEASES_PAGE
        try:
            release, newer = check_for_update(__version__)
        except UpdateError as e:
            print(f"[!] {e}")
            return 1
        if newer:
            print(f"[!] Version {release.version} is available (you have {__version__}).")
            print(f"    {release.url}")
            if release.has_installer:
                print(f"    Windows installer: {release.asset_url}")
            return 10
        print(f"[+] {__version__} is the latest version.")
        return 0

    if not args.target:
        print("[!] --target is required for CLI mode. Use --gui to launch the graphical interface.")
        return 2

    # Validate the comparison report up front: a typo'd path should fail now,
    # not after a 30-minute scan has already run.
    previous_report = None
    if args.compare:
        try:
            from diff import load_report
        except ImportError:
            from .diff import load_report
        try:
            previous_report = load_report(args.compare)
        except ValueError as e:
            print(f"[!] --compare: {e}")
            return 2

    # Print banner
    if not args.quiet:
        print("""
╔══════════════════════════════════════════════════════════╗
║         CybX NETWORK SCANNER v{:<25}║
║   Portable nmap scanner · local analysis · Insights feed ║
╚══════════════════════════════════════════════════════════╝
        """.format(__version__))
    
    # Load configuration
    config = load_config(args.config)

    # Check privileges
    if not check_privileges():
        print("[!] WARNING: Not running with root/administrator privileges.")
        print("[!] Some scan features (OS detection, SYN scan) may not work.")
        print("[!] For full functionality, run with sudo (Linux/macOS) or as Administrator (Windows).")
        print()

    # On Windows, prompt to install Npcap if missing
    if is_windows() and not is_npcap_installed():
        print("[!] Npcap is not installed on this machine.")
        print("[!] Npcap is required for SYN scan, OS detection, and most vuln scripts.")
        installer = find_bundled_installer()
        if installer is not None and sys.stdin.isatty():
            try:
                ans = input(f"[?] Install Npcap now from bundled installer ({installer.name})? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = "n"
            if ans in ("", "y", "yes"):
                print("[*] Opening the Npcap setup window - click through it to finish...")
                ok, msg = install_npcap(installer, on_log=lambda m: print(f"    {m}"))
                print(("[+] " if ok else "[!] ") + msg)
                if not ok:
                    print("[!] Install Npcap manually from https://npcap.com")
        elif installer is None:
            print("[!] No bundled installer found. Install manually from https://npcap.com")
        else:
            print("[!] Non-interactive shell. Install Npcap manually from https://npcap.com")
        print()
    
    # Get nmap version
    if not args.quiet:
        nmap_version = get_nmap_version()
        if nmap_version:
            print(f"[*] {nmap_version}")
        for warning in nmap_environment_warnings():
            print(f"[!] {warning}")
        print()
    
    # Prepare scan options
    scan_opts = config.get('scan_options', {})
    
    # Override with command-line arguments
    if args.timing is not None:
        scan_opts['timing'] = args.timing
    if args.no_vuln:
        scan_opts['vulnerability_scan'] = False
    if args.no_udp:
        scan_opts['udp_scan'] = False
    # Quick scan: fast sweep — no scripts, UDP, or OS detection.
    if args.quick:
        scan_opts['vulnerability_scan'] = False
        scan_opts['udp_scan'] = False
        scan_opts['os_detection'] = False
        scan_opts['default_scripts'] = False
        scan_opts['traceroute'] = False

    # Gentle scan: everything the preset dictates, applied before the explicit
    # rate flags below so those still win.
    if args.gentle:
        scan_opts.update(GENTLE_SCAN)
        if args.timing is not None:
            scan_opts['timing'] = args.timing  # an explicit -T still overrides

    # Explicit rate caps override whatever the preset chose.
    if args.max_rate is not None:
        scan_opts['max_rate'] = args.max_rate
    if args.max_parallelism is not None:
        scan_opts['max_parallelism'] = args.max_parallelism

    if args.gentle and not args.quiet:
        print(f"[*] Gentle mode: {scan_opts.get('max_rate')} pkts/sec, one probe at a time, "
              f"T{scan_opts.get('timing')}, no OS detection / vuln scripts / UDP.")

    # Discovery is a ping sweep: no ports probed, so the rate estimate below
    # (which is driven by port count) doesn't apply.
    if args.discover and not args.quiet:
        print("[*] Discovery mode: ping sweep only — no ports, services, OS, or scripts.")

    rate_warning = None if args.discover else rate_limit_warning(
        args.target, scan_opts.get('max_rate'), args.ports, scan_opts.get('udp_scan', True))
    if rate_warning:
        print(f"[!] {rate_warning}")
        print()

    # Run the scan
    try:
        stdout, stderr, returncode = run_scan(
            target=args.target,
            port_scan=scan_opts.get('port_scan', True),
            service_detection=scan_opts.get('service_detection', True),
            os_detection=scan_opts.get('os_detection', True),
            vulnerability_scan=scan_opts.get('vulnerability_scan', True),
            udp_scan=scan_opts.get('udp_scan', True),
            default_scripts=scan_opts.get('default_scripts', True),
            traceroute=scan_opts.get('traceroute', True),
            timing=scan_opts.get('timing', 4),
            custom_ports=args.ports,
            exclude=args.exclude,
            max_rate=scan_opts.get('max_rate'),
            max_parallelism=scan_opts.get('max_parallelism'),
            discovery_only=args.discover,
            external_scripts=scan_opts.get('external_scripts', False)
        )
        
        if returncode != 0:
            print(f"[!] Nmap returned non-zero exit code: {returncode}")
            if stderr:
                print(f"[!] Error output: {stderr[:500]}")
            if not stdout:
                return 1
    
    except KeyboardInterrupt:
        # subprocess.run has already stopped nmap by the time this arrives.
        print("\n[!] Scan cancelled.")
        return 130
    except FileNotFoundError as e:
        print(f"[!] {e}")
        return 1
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        return 1
    
    # Parse results
    if not args.quiet:
        print("[*] Parsing scan results...")
    
    # An aborted run still leaves parseable XML, which would otherwise be
    # reported as a successful scan that simply found nothing.
    run_error = nmap_run_error(stdout)
    if run_error:
        print(f"[!] nmap aborted before scanning anything: {run_error}")
        return 1

    try:
        scan_result = parse_nmap_xml(stdout)
    except Exception as e:
        print(f"[!] Failed to parse nmap output: {e}")
        return 1
    
    if not args.quiet:
        print(f"[*] Found {scan_result.total_hosts_up} hosts up, {scan_result.total_hosts_down} hosts down")
    
    # Local rule-based analysis (deterministic, offline). AI enrichment, if any,
    # happens downstream in the reporter — the scanner only ships scan data.
    if not args.quiet:
        print("[*] Running local rule-based analysis...")
    analysis = analyze_locally(scan_result)
    if not args.quiet:
        print(f"[*] Local analysis complete. Overall risk: {analysis.overall_risk.upper()}")

    # Scan-quality problems invalidate everything below them, so they are
    # printed loudly here rather than left to be noticed in the report body.
    quality_warnings = [o for o in analysis.network_observations if o.startswith("SCAN QUALITY")]
    if quality_warnings:
        print()
        print("!" * 60)
        for w in quality_warnings:
            print(f"[!] {w}")
        print("!" * 60)
        print()

    # Create output
    output_config = config.get('output', {})
    
    scan_type = "discovery" if args.discover else "comprehensive"

    output_data = create_insights_report(
        scan_result=scan_result,
        analysis=analysis,
        target=args.target,
        scanner_version=__version__,
        include_raw_nmap=output_config.get('include_raw_nmap', False),
        raw_xml=stdout if output_config.get('include_raw_nmap', False) else "",
        scan_type=scan_type
    )
    
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        output_dir = resolve_output_dir(output_config.get('directory'))
        filename = generate_filename(args.target)
        output_path = str(output_dir / filename)
    
    # Write output
    try:
        final_path = write_json_output(output_data, output_path)
        print(f"\n[+] Results saved to: {final_path}")
    except Exception as e:
        print(f"[!] Failed to write output: {e}")
        return 1

    # Write per-port Insights events (NDJSON) for CybX Insight ingestion.
    insights_cfg = output_config.get('insights_events', {})
    if insights_cfg.get('enabled', True):
        try:
            events = create_nmap_chat_events(
                scan_result=scan_result,
                analysis=analysis,
                target=args.target,
                scanner_version=__version__,
                scan_type=scan_type,
            )
            # A configured fixed path is the collector-watched file: append so the
            # Insights collector tails new lines. No configured path -> fresh
            # per-scan file next to the JSON report.
            configured_path = insights_cfg.get('path')
            events_path = configured_path or str(Path(final_path).with_suffix('.ndjson'))
            events_final = write_ndjson_events(events, events_path, append=bool(configured_path))
            print(f"[+] Insights events ({len(events)}) saved to: {events_final}")
        except Exception as e:
            print(f"[!] Failed to write Insights events: {e}")

    # Print summary
    if not args.quiet:
        print_summary(output_data)

    # Compare against the previous report, if one was given. Printed even in
    # quiet mode — the user explicitly asked for the diff.
    if previous_report is not None:
        try:
            from diff import diff_reports, format_diff_text
        except ImportError:
            from .diff import diff_reports, format_diff_text
        comparison = diff_reports(previous_report, output_data)
        print("=" * 60)
        print("CHANGES SINCE PREVIOUS SCAN")
        print("=" * 60)
        print(format_diff_text(comparison))
        print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
