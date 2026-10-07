"""
Self-update from GitHub Releases.

Checks the latest release of the public repository, downloads the Windows
installer from it, verifies the download against the release's SHA256SUMS,
and runs the installer silently with /RELAUNCH so the app comes back up on
the new version. Only the stdlib is used (urllib), so this adds nothing to
the build.

Releases are unsigned for now: integrity rests on HTTPS to GitHub plus the
published checksums. Anything that can publish a release to the repository
below can update every customer machine - guard that account accordingly.

The check sends one request for the latest release and nothing else: no scan
data, no identifiers beyond a User-Agent naming the app version.
"""

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

try:
    from paths import is_frozen, app_dir
except ImportError:
    from .paths import is_frozen, app_dir


# The public repository releases are published from. Override the API root
# for tests or a staging feed with CYBX_UPDATE_API.
REPO = "cybx-security/CybX-NetworkLens"
API_BASE = os.environ.get("CYBX_UPDATE_API", "https://api.github.com").rstrip("/")
RELEASES_PAGE = f"https://github.com/{REPO}/releases"

# The installer the Windows build produces (build\build_windows.bat), and the
# checksum list every release must carry. Matched loosely on the prefix so a
# renamed product keeps updating older installs.
_SETUP_ASSET_RE = re.compile(r"-Setup-[\w.\-]+\.exe$", re.IGNORECASE)
_SUMS_NAMES = ("SHA256SUMS", "SHA256SUMS.txt")

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
_TIMEOUT = 30  # seconds per request


class UpdateError(Exception):
    """A readable reason the update could not be checked, fetched or applied."""


@dataclass
class Release:
    version: str          # "1.2.0", no leading v
    tag: str
    notes: str
    url: str              # release page
    published_at: str
    asset_name: str = ""  # Windows installer in this release, if any
    asset_url: str = ""
    asset_size: int = 0
    sums_url: str = ""

    @property
    def has_installer(self) -> bool:
        return bool(self.asset_url)


def parse_version(text: str) -> Tuple[int, int, int]:
    """X.Y.Z as a tuple; anything unparsable sorts lowest (a dev build is 'old')."""
    m = _VERSION_RE.match((text or "").strip())
    if not m:
        return (-1, -1, -1)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1 ordering two version strings numerically."""
    pa, pb = parse_version(a), parse_version(b)
    return (pa > pb) - (pa < pb)


def _request(url: str, current_version: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": f"CybXNetworkLens/{current_version}",
    })


def check_for_update(current_version: str) -> Tuple[Release, bool]:
    """
    The latest published release and whether it is newer than current_version.

    A release that is not newer is still returned so callers can say "you
    have the latest". Raises UpdateError with a message fit to show the user.
    """
    url = f"{API_BASE}/repos/{REPO}/releases/latest"
    try:
        with urllib.request.urlopen(_request(url, current_version), timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read(4 << 20).decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise UpdateError(
                f"No releases were found at github.com/{REPO}. "
                "Nothing has been published yet, or this computer cannot reach GitHub.")
        if e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0":
            # Anonymous API calls are limited per source IP (60/hour); an
            # office full of machines behind one NAT can hit it.
            raise UpdateError("GitHub is limiting update checks from this network right now. "
                              "Try again in an hour.")
        raise UpdateError(f"GitHub answered HTTP {e.code} while checking for updates.")
    except urllib.error.URLError as e:
        raise UpdateError(f"Cannot reach GitHub to check for updates: {e.reason}")
    except (OSError, ValueError) as e:
        raise UpdateError(f"Could not read the release information: {e}")

    tag = str(data.get("tag_name", ""))
    release = Release(
        version=tag[1:] if tag.startswith("v") else tag,
        tag=tag,
        notes=str(data.get("body") or ""),
        url=str(data.get("html_url") or RELEASES_PAGE),
        published_at=str(data.get("published_at") or ""),
    )
    for asset in data.get("assets", []) or []:
        name = str(asset.get("name", ""))
        if _SETUP_ASSET_RE.search(name) and not release.asset_url:
            release.asset_name = name
            release.asset_url = str(asset.get("browser_download_url", ""))
            release.asset_size = int(asset.get("size") or 0)
        elif name in _SUMS_NAMES:
            release.sums_url = str(asset.get("browser_download_url", ""))

    return release, compare_versions(release.version, current_version) > 0


def can_self_update() -> bool:
    """
    Whether this process can replace itself by running the installer.

    True only for the installed Windows layout (the folder build the
    installer puts in Program Files). A portable exe, a macOS/Linux build or
    a source checkout is pointed at the releases page instead: running the
    Windows installer there would install a second copy, not update this one.
    """
    if platform.system() != "Windows" or not is_frozen():
        return False
    here = app_dir()
    return (here / "_internal").is_dir() and (here / "CybXNetworkLens.exe").exists()


def _expected_sum(release: Release, current_version: str) -> str:
    """The installer's checksum from the release's SHA256SUMS (sha256sum format)."""
    try:
        with urllib.request.urlopen(_request(release.sums_url, current_version), timeout=_TIMEOUT) as resp:
            text = resp.read(1 << 20).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"Could not fetch the release's checksum list: {e}")
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        digest, name = fields[0].lower(), fields[1].lstrip("*")
        if Path(name).name == release.asset_name and len(digest) == 64:
            return digest
    raise UpdateError(f"The release's checksum list has no entry for {release.asset_name}; "
                      "not installing it.")


def download_installer(release: Release, dest_dir: str, current_version: str,
                       progress: Optional[Callable[[int, int], None]] = None) -> str:
    """
    Download the release's installer into dest_dir and verify it.

    Refuses a release without a checksum list, and deletes the file if the
    checksum does not match. progress(done, total) is called as bytes arrive.
    Returns the verified installer's path.
    """
    if not release.has_installer:
        raise UpdateError(f"Release {release.tag} has no Windows installer attached.")
    if not release.sums_url:
        raise UpdateError(f"Release {release.tag} has no SHA256SUMS file, so the download "
                          "cannot be verified; refusing to install it.")
    want = _expected_sum(release, current_version)

    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    path = Path(dest_dir) / release.asset_name
    digest = hashlib.sha256()
    done = 0
    try:
        with urllib.request.urlopen(_request(release.asset_url, current_version), timeout=_TIMEOUT) as resp, \
                open(path, "wb") as out:
            total = int(resp.headers.get("Content-Length") or release.asset_size or 0)
            while True:
                chunk = resp.read(256 << 10)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except (urllib.error.URLError, OSError) as e:
        try:
            path.unlink()
        except OSError:
            pass
        raise UpdateError(f"Download interrupted: {e}")

    got = digest.hexdigest()
    if got != want:
        try:
            path.unlink()
        except OSError:
            pass
        raise UpdateError(f"The downloaded {release.asset_name} does not match the release's "
                          f"checksum (got {got[:12]}..., expected {want[:12]}...). Not installing it.")
    return str(path)


def run_installer(installer_path: str) -> None:
    """
    Start the downloaded installer silently and detached, with /RELAUNCH so it
    reopens the app when done. The caller must exit promptly afterwards: the
    installer waits for this process to release its files, then replaces them.
    """
    if platform.system() != "Windows":
        raise UpdateError("Self-update is only available on Windows.")
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        subprocess.Popen([installer_path, "/S", "/RELAUNCH"],
                         creationflags=flags, close_fds=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        raise UpdateError(f"Could not start the installer: {e}")
