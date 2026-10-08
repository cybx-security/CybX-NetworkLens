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
from typing import List, Optional, Tuple


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


def _owner() -> Tuple[Optional[int], Optional[int], Optional[Path]]:
    """
    (uid, gid, home) of the person actually using the app when it runs as
    root - through its own elevation (CYBX_OWNER_*), sudo, or pkexec. All
    None when not elevated, or when the owner can't be worked out.
    """
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return None, None, None
    try:
        import pwd
        if os.environ.get("CYBX_OWNER_UID"):
            uid = int(os.environ["CYBX_OWNER_UID"])
            gid = int(os.environ.get("CYBX_OWNER_GID") or pwd.getpwuid(uid).pw_gid)
            home = Path(os.environ.get("CYBX_OWNER_HOME") or pwd.getpwuid(uid).pw_dir)
            return uid, gid, home
        if os.environ.get("PKEXEC_UID"):
            entry = pwd.getpwuid(int(os.environ["PKEXEC_UID"]))
            return entry.pw_uid, entry.pw_gid, Path(entry.pw_dir)
        if os.environ.get("SUDO_USER") and os.environ["SUDO_USER"] != "root":
            entry = pwd.getpwnam(os.environ["SUDO_USER"])
            return entry.pw_uid, entry.pw_gid, Path(entry.pw_dir)
    except (KeyError, ValueError, ImportError):
        pass
    return None, None, None


def owner_home() -> Path:
    """The home folder reports belong in: the real user's, even under sudo."""
    _uid, _gid, home = _owner()
    return home or Path.home()


def claim_for_owner(path) -> None:
    """
    Hand a file or folder written by an elevated process back to the user.

    Only touches paths inside the user's home: a collector feed under
    /var/log or ProgramData must keep the ownership the collector expects.
    Silently does nothing when not elevated or on failure.
    """
    uid, gid, home = _owner()
    if uid is None:
        return
    try:
        target = Path(path).resolve()
        if home is None or home.resolve() not in target.parents:
            return
        os.chown(target, uid, gid)
    except OSError:
        pass


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
    return (docs or owner_home() / "Documents") / APP_NAME


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
    return owner_home() / ".config" / "cybx-networklens" / "config.json"


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
