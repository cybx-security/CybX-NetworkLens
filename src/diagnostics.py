"""
"Save support info": one zip with everything needed to understand a problem
report - the app's version and environment, the config in use, nmap's
version and bundle state, the launch log, and the metadata of recent scans
(never the scan results themselves: those describe a customer's network).
"""

import json
import os
import platform
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

try:
    from paths import (config_candidates, resolve_output_dir, is_frozen, app_dir,
                       bundle_root, claim_for_owner)
    from scanner import get_nmap_version, nmap_environment_warnings, check_privileges, resolve_nmap
    from npcap import is_windows, is_npcap_installed
    from version import __version__
except ImportError:
    from .paths import (config_candidates, resolve_output_dir, is_frozen, app_dir,
                        bundle_root, claim_for_owner)
    from .scanner import get_nmap_version, nmap_environment_warnings, check_privileges, resolve_nmap
    from .npcap import is_windows, is_npcap_installed
    from .version import __version__


def environment_summary(config: Optional[dict] = None) -> str:
    lines = [
        f"CybX NetworkLens {__version__}",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"OS: {platform.platform()}  ({platform.machine()})",
        f"Python: {sys.version.split()[0]}  frozen={is_frozen()}",
        f"App folder: {app_dir()}",
        f"Bundle root: {bundle_root()}",
        f"Elevated: {check_privileges()}",
    ]
    if is_windows():
        lines.append(f"Npcap installed: {is_npcap_installed()}")
    try:
        nmap_path, datadir, missing = resolve_nmap()
        lines.append(f"nmap: {nmap_path}  datadir={datadir or '(system)'}  missing={missing or 'none'}")
    except Exception as e:
        lines.append(f"nmap: NOT FOUND ({e})")
    lines.append(f"nmap version: {get_nmap_version() or 'unknown'}")
    for w in nmap_environment_warnings():
        lines.append(f"WARNING: {w}")
    lines.append("Config candidates:")
    for c in config_candidates():
        lines.append(f"  {'[x]' if c.exists() else '[ ]'} {c}")
    out_dir = resolve_output_dir((config or {}).get("output", {}).get("directory"))
    lines.append(f"Output folder: {out_dir}  exists={out_dir.exists()}")
    return "\n".join(lines) + "\n"


def write_bundle(path: str, config: Optional[dict] = None,
                 extra_text: Optional[dict] = None) -> str:
    """Write the support zip to `path` and return it."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("environment.txt", environment_summary(config))
        if config is not None:
            z.writestr("config_in_use.json", json.dumps(config, indent=2))
        for c in config_candidates():
            if c.exists():
                try:
                    z.write(c, f"config_files/{c.name}")
                except OSError:
                    pass
                break
        log = Path.home() / "Library" / "Logs" / "CybX NetworkLens" / "elevated-launch.log"
        if log.exists():
            try:
                z.write(log, "elevated-launch.log")
            except OSError:
                pass
        for name in ("selftest_gui_log.txt",):
            f = app_dir() / name
            if f.exists():
                try:
                    z.write(f, name)
                except OSError:
                    pass
        # Recent scans: metadata only.
        out_dir = resolve_output_dir((config or {}).get("output", {}).get("directory"))
        recent = []
        if out_dir.is_dir():
            for rp in sorted(out_dir.glob("scan_*.json"), key=lambda x: x.stat().st_mtime)[-10:]:
                try:
                    with open(rp, "r", encoding="utf-8") as f:
                        meta = json.load(f).get("scan_metadata", {})
                    recent.append({"file": rp.name, **{k: meta.get(k) for k in
                                   ("target", "scan_type", "timestamp", "hosts_up", "hosts_down",
                                    "scanner_version", "nmap_version", "partial")}})
                except (OSError, ValueError):
                    recent.append({"file": rp.name, "error": "unreadable"})
        z.writestr("recent_scans.json", json.dumps(recent, indent=2))
        for name, text in (extra_text or {}).items():
            z.writestr(name, text)
    claim_for_owner(p)
    return str(p)
