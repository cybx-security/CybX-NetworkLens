"""
Npcap detection and install for Windows.

Npcap is required on the *running* Windows machine for SYN scans, OS
detection, and most vulnerability scripts. It cannot be packed into the
PyInstaller binary because it installs a signed kernel driver — it must
run its own installer once per machine.

We ship the Npcap installer alongside the binary (under `installers/windows/`)
and offer to run it the first time the scanner sees a machine without Npcap.
The user clicks through Npcap's own setup window: the free Npcap installer has
no silent mode (that is an Npcap OEM feature), so passing /S to it does not
install anything. Subsequent launches detect Npcap and skip this entirely.
"""

import platform
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional, Tuple


# Where users get Npcap when no installer is bundled (the free licence does
# not allow redistributing it in a public download).
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"

WPCAP_PATHS = [
    Path(r"C:\Windows\System32\wpcap.dll"),
    Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
    Path(r"C:\Windows\SysWOW64\wpcap.dll"),
]


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_npcap_installed() -> bool:
    """Return True if Npcap (or WinPcap-compat) is available on this machine."""
    if not is_windows():
        return True
    return any(p.exists() for p in WPCAP_PATHS)


def _base_path() -> Path:
    """Return the project / bundle root, working in both dev and PyInstaller modes."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).parent.parent


def find_bundled_installer() -> Optional[Path]:
    """Locate the bundled Npcap installer, if one was packed at build time."""
    installers_dir = _base_path() / "installers" / "windows"
    if not installers_dir.exists():
        return None
    candidates = sorted(installers_dir.glob("npcap-*.exe"))
    return candidates[-1] if candidates else None


def install_npcap(
    installer_path: Path,
    on_log: Optional[Callable[[str], None]] = None,
    timeout: int = 1800,
) -> Tuple[bool, str]:
    """
    Run the Npcap installer and wait for the user to finish it.

    Npcap's setup window opens and the user clicks through it (Next, Next,
    Install). Blocks until that window closes, so GUI callers must run this
    off the UI thread. Requires the calling process to already be elevated
    (the GUI binary is built with --uac-admin so this is true).
    """
    log = on_log or (lambda _msg: None)

    if not is_windows():
        return False, "Npcap install is only applicable on Windows."
    if not installer_path.exists():
        return False, f"Installer not found at {installer_path}"

    log(f"Opening {installer_path.name} - follow the Npcap setup window to finish...")
    try:
        # /winpcap_mode only pre-ticks that option in the setup window.
        result = subprocess.run(
            [str(installer_path), "/winpcap_mode=yes"],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, (f"The Npcap setup window was still open after "
                       f"{timeout // 60} minutes. Finish or close it, then restart the scanner.")
    except OSError as e:
        # 740 = ERROR_ELEVATION_REQUIRED: the installer needs admin and this
        # process isn't elevated, so Windows refuses to start it from here.
        if getattr(e, "winerror", None) == 740:
            return False, ("The Npcap installer needs administrator rights. Re-run the "
                           f"scanner as Administrator, or run it yourself: {installer_path}")
        return False, f"Failed to launch Npcap installer: {e}"
    except Exception as e:
        return False, f"Failed to launch Npcap installer: {e}"

    if not is_npcap_installed():
        return False, (
            f"Npcap is still not installed (setup exited with code {result.returncode}). "
            "If you cancelled it, restart the scanner to be asked again, or "
            "install manually from https://npcap.com."
        )
    return True, "Npcap installed successfully."
