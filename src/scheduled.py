"""
Scheduled scans: one recurring job per installed copy, run by the OS.

The point is "what changed since last week" without anyone remembering to
run it: the job runs the CLI with --compare-latest, which diffs against the
previous report of the same target, writes the report, the Insights events
and a <report>_changes.txt into the user's output folder.

One mechanism per platform, all driven by the same ScanJob description:
  Windows  Task Scheduler (schtasks), running as SYSTEM so it has the rights
           a full scan needs and runs whether or not anyone is logged in
  macOS    a launchd daemon in /Library/LaunchDaemons (root)
  Linux    a root cron entry in /etc/cron.d

All three need administrator rights to create, which the GUI already has.
"""

import json
import os
import platform
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from paths import is_frozen, app_dir, resolve_output_dir, machine_config_path
    from scanner import NO_WINDOW_FLAGS
except ImportError:
    from .paths import is_frozen, app_dir, resolve_output_dir, machine_config_path
    from .scanner import NO_WINDOW_FLAGS


JOB_NAME = "CybX NetworkLens Scan"
_WIN_TASK = JOB_NAME
_MAC_LABEL = "com.cybx.networklens.scan"
_LINUX_CRON = Path("/etc/cron.d/cybx-networklens")
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MODES = ("quick", "full", "gentle")


@dataclass
class ScanJob:
    target: str
    mode: str = "full"          # quick | full | gentle
    weekday: int = 6            # 0 = Monday ... 6 = Sunday; -1 = every day
    hour: int = 2
    minute: int = 0
    output_dir: str = ""        # where the reports go (the user's, not SYSTEM's)

    def describe(self) -> str:
        when = "every day" if self.weekday < 0 else f"every {WEEKDAYS[self.weekday]}"
        return f"{self.mode.capitalize()} scan of {self.target} {when} at {self.hour:02d}:{self.minute:02d}"


def cli_executable() -> Optional[str]:
    """The command-line scanner next to this build, or None from source."""
    if not is_frozen():
        return None
    here = app_dir()
    if platform.system() == "Windows":
        for name in ("networklens.exe",):
            if (here / name).exists():
                return str(here / name)
        return None
    for name in ("networklens",):
        if (here / name).exists():
            return str(here / name)
    # The macOS .app: the CLI sits beside the GUI inside Contents/MacOS when
    # the DMG's networklens was dropped there; otherwise next to the .app.
    app_bundle = str(here)
    if ".app/Contents/MacOS" in app_bundle:
        outside = Path(app_bundle.split(".app/Contents/MacOS")[0]).parent / "networklens"
        if outside.exists():
            return str(outside)
    return None


def _command(job: ScanJob, exe: str) -> List[str]:
    cmd = [exe, "--target", job.target, "--compare-latest", "--quiet",
           "--output-dir", job.output_dir or str(resolve_output_dir(None))]
    if job.mode == "quick":
        cmd.append("--quick")
    elif job.mode == "gentle":
        cmd.append("--gentle")
    if machine_config_path().exists():
        cmd += ["--config", str(machine_config_path())]
    return cmd


def _quote_win(args: List[str]) -> str:
    return " ".join(f'"{a}"' if (" " in a or not a) else a for a in args)


# ---------------------------------------------------------------- Windows --

def _win_create(job: ScanJob, exe: str) -> Tuple[bool, str]:
    tr = _quote_win(_command(job, exe))
    base = ["schtasks", "/Create", "/F", "/TN", _WIN_TASK, "/TR", tr,
            "/RU", "SYSTEM", "/RL", "HIGHEST",
            "/ST", f"{job.hour:02d}:{job.minute:02d}"]
    if job.weekday < 0:
        base += ["/SC", "DAILY"]
    else:
        base += ["/SC", "WEEKLY", "/D", ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"][job.weekday]]
    r = subprocess.run(base, capture_output=True, text=True, creationflags=NO_WINDOW_FLAGS)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()
    _save_job(job)
    return True, f"Scheduled: {job.describe()} (Task Scheduler: {_WIN_TASK})"


def _win_remove() -> Tuple[bool, str]:
    r = subprocess.run(["schtasks", "/Delete", "/F", "/TN", _WIN_TASK],
                       capture_output=True, text=True, creationflags=NO_WINDOW_FLAGS)
    if r.returncode != 0 and "cannot find" not in (r.stderr + r.stdout).lower():
        return False, (r.stderr or r.stdout).strip()
    return True, "Scheduled scan removed."


def _win_exists() -> bool:
    r = subprocess.run(["schtasks", "/Query", "/TN", _WIN_TASK], capture_output=True,
                       text=True, creationflags=NO_WINDOW_FLAGS)
    return r.returncode == 0


# ------------------------------------------------------------------ macOS --

def _mac_plist() -> Path:
    return Path("/Library/LaunchDaemons") / f"{_MAC_LABEL}.plist"


def _mac_create(job: ScanJob, exe: str) -> Tuple[bool, str]:
    cal = {"Hour": job.hour, "Minute": job.minute}
    if job.weekday >= 0:
        cal["Weekday"] = (job.weekday + 1) % 7  # launchd: 0 = Sunday
    plist = {
        "Label": _MAC_LABEL,
        "ProgramArguments": _command(job, exe),
        "StartCalendarInterval": cal,
        "StandardOutPath": "/var/log/cybx-networklens-scan.log",
        "StandardErrorPath": "/var/log/cybx-networklens-scan.log",
    }
    path = _mac_plist()
    try:
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
        with open(path, "wb") as f:
            plistlib.dump(plist, f)
        os.chmod(path, 0o644)
        r = subprocess.run(["launchctl", "load", "-w", str(path)], capture_output=True, text=True)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()
    except OSError as e:
        return False, f"Could not write {path}: {e} (administrator rights are needed)"
    _save_job(job)
    return True, f"Scheduled: {job.describe()} (launchd: {_MAC_LABEL})"


def _mac_remove() -> Tuple[bool, str]:
    path = _mac_plist()
    if path.exists():
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
        try:
            path.unlink()
        except OSError as e:
            return False, f"Could not remove {path}: {e}"
    return True, "Scheduled scan removed."


# ------------------------------------------------------------------ Linux --

def _linux_create(job: ScanJob, exe: str) -> Tuple[bool, str]:
    dow = "*" if job.weekday < 0 else str((job.weekday + 1) % 7)  # cron: 0 = Sunday
    line = f"{job.minute} {job.hour} * * {dow} root " + " ".join(
        "'" + a.replace("'", "'\\''") + "'" for a in _command(job, exe))
    try:
        _LINUX_CRON.write_text("# Installed by CybX NetworkLens (Scheduled scan). Remove with the app or delete this file.\n"
                               f"{line} >> /var/log/cybx-networklens-scan.log 2>&1\n", encoding="utf-8")
        os.chmod(_LINUX_CRON, 0o644)
    except OSError as e:
        return False, f"Could not write {_LINUX_CRON}: {e} (root is needed)"
    _save_job(job)
    return True, f"Scheduled: {job.describe()} (cron: {_LINUX_CRON})"


def _linux_remove() -> Tuple[bool, str]:
    try:
        if _LINUX_CRON.exists():
            _LINUX_CRON.unlink()
    except OSError as e:
        return False, f"Could not remove {_LINUX_CRON}: {e}"
    return True, "Scheduled scan removed."


# ------------------------------------------------------------- common API --

def _job_file() -> Path:
    """Where the job's description is remembered, so the dialog can show it."""
    return machine_config_path().parent / "scheduled_scan.json"


def _save_job(job: ScanJob) -> None:
    try:
        _job_file().parent.mkdir(parents=True, exist_ok=True)
        _job_file().write_text(json.dumps(asdict(job), indent=2), encoding="utf-8")
    except OSError:
        pass


def current_job() -> Optional[ScanJob]:
    """The scheduled scan as last set up here, or None if there isn't one."""
    system = platform.system()
    exists = (_win_exists() if system == "Windows" else
              _mac_plist().exists() if system == "Darwin" else _LINUX_CRON.exists())
    if not exists:
        return None
    try:
        data = json.loads(_job_file().read_text(encoding="utf-8"))
        return ScanJob(**{k: data[k] for k in ScanJob.__dataclass_fields__ if k in data})
    except (OSError, ValueError, TypeError):
        return ScanJob(target="(unknown)")


def create(job: ScanJob) -> Tuple[bool, str]:
    """Install (or replace) the scheduled scan. Needs administrator rights."""
    exe = cli_executable()
    if not exe:
        return False, ("Scheduling needs the installed command-line scanner (networklens) next "
                       "to this app; it isn't available when running from source.")
    if not re.match(r"^[\w.:/,\- ]+$", job.target or ""):
        return False, "Target contains characters that can't be scheduled."
    job.mode = job.mode if job.mode in MODES else "full"
    if not job.output_dir:
        job.output_dir = str(resolve_output_dir(None))
    system = platform.system()
    if system == "Windows":
        return _win_create(job, exe)
    if system == "Darwin":
        return _mac_create(job, exe)
    if system == "Linux":
        return _linux_create(job, exe)
    return False, f"Scheduling is not supported on {system}."


def remove() -> Tuple[bool, str]:
    system = platform.system()
    ok, msg = ((_win_remove() if system == "Windows" else
                _mac_remove() if system == "Darwin" else
                _linux_remove() if system == "Linux" else (False, "unsupported")))
    if ok:
        try:
            _job_file().unlink()
        except OSError:
            pass
    return ok, msg
