"""
Put text on the clipboard the person can actually paste from.

Tk's clipboard is fine on Windows and X11, but on macOS the app runs as root
(it asks for the password at launch) and a root process gets its own
pasteboard - nothing copied there is visible to the signed-in user, so the
Copy button and Cmd+C both appeared to do nothing. pbcopy run inside the
user's launchd session (launchctl asuser <uid>) writes to the user's
pasteboard regardless of who runs it.
"""

import os
import platform
import subprocess
from typing import Optional

try:
    from paths import _owner
except ImportError:
    from .paths import _owner


def _mac_pbcopy(text: str) -> bool:
    uid, _gid, _home = _owner()
    if uid is None:
        uid = os.getuid()
    for cmd in (["launchctl", "asuser", str(uid), "pbcopy"], ["pbcopy"]):
        try:
            r = subprocess.run(cmd, input=text.encode("utf-8"), capture_output=True, timeout=5)
            if r.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def copy_text(root, text: str) -> bool:
    """Copy `text`; True when at least one route succeeded."""
    ok = False
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update_idletasks()
        ok = True
    except Exception:
        pass
    if platform.system() == "Darwin":
        ok = _mac_pbcopy(text) or ok
    return ok


def selected_text(widget) -> Optional[str]:
    """The widget's current selection, or None."""
    try:
        return widget.selection_get()
    except Exception:
        return None
