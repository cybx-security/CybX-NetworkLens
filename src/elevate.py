"""
Ask for administrator rights at launch on macOS and Linux.

Windows gets this for free: the GUI exe carries a UAC manifest, so Windows
shows its permission prompt and starts the app elevated. macOS and Linux have
no such manifest, so the app does it itself: if it is not root, it shows the
system's own password dialog (macOS: the "administrator privileges" sheet via
osascript; Linux: polkit via pkexec) and starts a second, elevated copy of
itself, then quits. If the user cancels, the app carries on unprivileged -
scans still work, as TCP-connect scans without OS detection or UDP.

The elevated copy keeps the user's HOME (so reports land in their Documents,
not root's) and learns who launched it through CYBX_OWNER_* so files it
writes can be handed back to that user (see paths.claim_for_owner).
"""

import os
import platform
import shlex
import shutil
import subprocess
import sys
from typing import List, Optional


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _self_command() -> List[str]:
    """How to start this program again: the frozen exe, or python + script."""
    if getattr(sys, "frozen", False):
        return [sys.executable] + sys.argv[1:]
    return [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:]


# Variables a PyInstaller one-file build sets so that a child copy of itself
# reuses the parent's unpacked temp folder. The elevated copy must NOT reuse
# ours: this unprivileged process exits as soon as the elevated one is up,
# and on exit the bootloader deletes that folder - under the running app.
_PYINSTALLER_VARS = ("_MEIPASS2", "_PYI_APPLICATION_HOME_DIR", "_PYI_ARCHIVE_FILE",
                     "_PYI_PARENT_PROCESS_LEVEL", "_PYI_SPLASH_IPC", "_PYI_LINUX_PROCESS_NAME")


def _env_command(env_pairs: List[str]) -> List[str]:
    """`env` invocation that drops PyInstaller's inherited state and sets ours."""
    cmd = ["env"]
    for var in _PYINSTALLER_VARS:
        cmd += ["-u", var]
    return cmd + env_pairs


def _owner_env() -> List[str]:
    """KEY=VALUE pairs the elevated copy needs to behave like the user's own."""
    pairs = {
        "CYBX_ELEVATED": "1",  # loop guard
        "CYBX_OWNER_UID": str(os.getuid()),
        "CYBX_OWNER_GID": str(os.getgid()),
        "CYBX_OWNER_HOME": os.path.expanduser("~"),
        "HOME": os.path.expanduser("~"),
    }
    for key in ("USER", "LOGNAME", "LANG", "LC_ALL", "DISPLAY", "XAUTHORITY",
                "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "TMPDIR"):
        if os.environ.get(key):
            pairs[key] = os.environ[key]
    return [f"{k}={v}" for k, v in pairs.items()]


def launch_log_path() -> str:
    """Where the elevated copy's output goes on macOS (readable in Console.app)."""
    return os.path.join(os.path.expanduser("~"), "Library", "Logs", "CybX NetworkLens", "elevated-launch.log")


def applescript_for(command: List[str], env_pairs: List[str], log_path: Optional[str] = None) -> str:
    """
    The osascript program that runs `command` as administrator.

    The shell line is backgrounded, with its output sent to a log file, so the
    dialog closes and this (unprivileged) process can exit straight away
    instead of sitting behind the elevated window for the whole session. The
    log is the only trace left if the elevated copy fails to open a window.
    """
    run = " ".join(shlex.quote(p) for p in _env_command(env_pairs)) + " " \
          + " ".join(shlex.quote(a) for a in command)
    if log_path:
        shell = ("{ echo \"=== elevated launch $(date)\"; " + run +
                 "; echo \"=== exited with $?\"; } >>" + shlex.quote(log_path) + " 2>&1 &")
    else:
        shell = run + " >/dev/null 2>&1 &"
    escaped = shell.replace("\\", "\\\\").replace('"', '\\"')
    return f'do shell script "{escaped}" with administrator privileges'


def relaunch_elevated() -> Optional[int]:
    """
    Start an elevated copy of this program if we are not root.

    Returns None when the caller should just keep running (already root, on
    Windows, elevation declined or unavailable), or an exit code the caller
    should exit with because the elevated copy has taken over.
    """
    if platform.system() == "Windows" or is_root():
        return None
    if os.environ.get("CYBX_ELEVATED") or os.environ.get("CYBX_NO_ELEVATE"):
        return None

    command = _self_command()
    env_pairs = _owner_env()

    if platform.system() == "Darwin":
        log_path = launch_log_path()
        try:
            # Created now, as the user, so the file root writes lands in a
            # folder the user owns and can read.
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
        except OSError:
            log_path = None
        try:
            result = subprocess.run(
                ["osascript", "-e", applescript_for(command, env_pairs, log_path)],
                capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired):
            return None
        # -128 is "User canceled" - run unprivileged instead.
        return 0 if result.returncode == 0 else None

    if platform.system() == "Linux" and shutil.which("pkexec") and os.environ.get("DISPLAY"):
        try:
            # pkexec runs the app in the foreground; this process waits so a
            # launcher or terminal sees the app's exit, not an instant return.
            result = subprocess.run(["pkexec"] + _env_command(env_pairs) + command)
        except OSError:
            return None
        # 126 = dismissed, 127 = authentication failed: carry on unprivileged.
        if result.returncode in (126, 127):
            return None
        return result.returncode

    return None
