"""
Where the scanner reads and writes files.

This exists because "relative to the current directory" stops meaning anything
once the app is installed. A program started from a Desktop or Start Menu
shortcut - and especially one that elevates through UAC - can have any working
directory, including C:\\Windows\\System32, and its own folder under Program
Files is not somewhere scan reports belong (or survive an uninstall). So every
location is derived from something stable instead:

  bundle_root()  read-only files shipped inside the build (default config,
                 nmap, the Npcap installer, the icon)
  app_dir()      the folder holding the executable
  data_dir()     where the user's scan reports go
"""

import os
import sys
from pathlib import Path
from typing import List, Optional


APP_NAME = "CybX NetworkLens"


def is_frozen() -> bool:
    """True when running as a PyInstaller build rather than from source."""
    return bool(getattr(sys, "frozen", False))


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def bundle_root() -> Path:
    """Root of the files shipped with the app (the project root from source)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return _project_root()


def app_dir() -> Path:
    """Folder holding the executable (the project root from source)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return _project_root()


def _windows_documents() -> Optional[Path]:
    """The signed-in user's Documents folder, honouring OneDrive/redirection."""
    try:
        import ctypes
        from ctypes import wintypes
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        # CSIDL_PERSONAL (5) is "My Documents".
        if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0 and buf.value:
            return Path(buf.value)
    except Exception:
        pass
    return None


def data_dir() -> Path:
    """
    Base folder for scan reports.

    A build writes under the user's Documents folder, where people look for
    their files and where an uninstall leaves them alone. From source it is the
    project root, so ./output keeps meaning the repo's output/ folder.
    """
    if not is_frozen():
        return _project_root()
    docs = _windows_documents() if sys.platform == "win32" else None
    return (docs or Path.home() / "Documents") / APP_NAME


def resolve_output_dir(configured: Optional[str]) -> Path:
    """
    Turn the configured output.directory into an absolute path.

    Absolute paths are used as given; relative ones (including the default
    "./output") hang off data_dir(), never the working directory.
    """
    raw = os.path.expandvars(os.path.expanduser(configured or "output"))
    path = Path(raw)
    if not path.is_absolute():
        path = data_dir() / path
    return Path(os.path.normpath(str(path)))


def machine_config_path() -> Path:
    """
    The settings file for an installed copy.

    On Windows this is under ProgramData - machine-wide, outside Program Files
    so it survives upgrades, and next to where the Insights collector feed
    normally lives. The installer puts the default config here.
    """
    if sys.platform == "win32":
        base = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return Path(base) / "CybX" / "NetworkLens" / "config.json"
    return Path.home() / ".config" / "cybx-networklens" / "config.json"


def config_candidates() -> List[Path]:
    """Config files to try, first match wins."""
    bundled = bundle_root() / "config" / "config.json"
    if is_frozen():
        # A config.json dropped beside a portable exe overrides the installed
        # one, which overrides the defaults baked into the build. The working
        # directory is deliberately not searched: for an installed app it is
        # arbitrary.
        return [app_dir() / "config.json", machine_config_path(), bundled]
    return [bundled, Path("./config.json"), Path("./config/config.json")]


def icon_path(extension: str = "ico") -> Optional[Path]:
    """The app icon in the given format, or None if this build lacks it."""
    path = bundle_root() / "packaging" / "icon" / f"icon.{extension}"
    return path if path.exists() else None
