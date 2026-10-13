"""
Self-update from GitHub Releases.

Checks the latest release of the public repository, downloads this
platform's package from it, verifies the download against the release's
SHA256SUMS, and installs it:
  Windows  runs the installer silently with /RELAUNCH
  macOS    mounts the DMG, swaps the .app bundle in place, relaunches
  Linux    unpacks the tar.gz over the installed files, relaunches
Only the stdlib is used (urllib), so this adds nothing to the build.

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
import shutil
import subprocess
import sys
import tempfile
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

# The checksum list every release must carry.
_SUMS_NAMES = ("SHA256SUMS", "SHA256SUMS.txt")


def _asset_pattern() -> re.Pattern:
    """The release file for this OS and CPU. Matched loosely on the prefix so a
    renamed product keeps updating older installs."""
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        return re.compile(r"-Setup-[\w.\-]+\.exe$", re.IGNORECASE)
    if system == "Darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64"
        return re.compile(rf"-macos-{arch}\.dmg$", re.IGNORECASE)
    arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
    return re.compile(rf"-linux-{arch}\.tar\.gz$", re.IGNORECASE)

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
    asset_name: str = ""  # this platform's package in the release, if any
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
    wanted = _asset_pattern()
    for asset in data.get("assets", []) or []:
        name = str(asset.get("name", ""))
        if wanted.search(name) and not release.asset_url:
            release.asset_name = name
            release.asset_url = str(asset.get("browser_download_url", ""))
            release.asset_size = int(asset.get("size") or 0)
        elif name in _SUMS_NAMES:
            release.sums_url = str(asset.get("browser_download_url", ""))

    return release, compare_versions(release.version, current_version) > 0


_MD_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")


def notes_for_display(body: str, limit: int = 700) -> str:
    """
    The human part of a release body, as plain text.

    Release bodies start with the download table from
    packaging/release-notes.md (meant for the web page) and continue with the
    generated change list; the dialog wants only the latter, without markdown
    syntax.
    """
    text = body or ""
    for marker in ("## Changes", "## What's Changed"):
        idx = text.find(marker)
        if idx >= 0:
            text = text[idx + len(marker):]
            break
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or _MD_TABLE_ROW.match(line) or line.startswith("<!--"):
            continue
        line = re.sub(r"^#{1,6}\s*", "", line)                    # headings
        line = re.sub(r"\*\*(.+?)\*\*", r"\1", line)               # bold
        line = re.sub(r"`([^`]*)`", r"\1", line)                   # code
        line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)      # links
        line = re.sub(r"\s+by\s+@\S+\s+in\s+https?://\S+$", "", line)  # "by @x in <pr url>"
        line = re.sub(r"https?://\S+", "", line).rstrip()
        if line.lower().startswith("full changelog"):
            continue
        if line.startswith(("* ", "- ")):
            line = "• " + line[2:]
        if line:
            lines.append(line)
    out = "\n".join(lines).strip()
    if len(out) > limit:
        out = out[:limit].rstrip() + "..."
    return out


def app_bundle_path() -> Optional[Path]:
    """The .app this process runs from on macOS, or None."""
    exe = Path(sys.executable).resolve()
    for parent in exe.parents:
        if parent.suffix == ".app":
            return parent
    return None


def _writable_dir(path: Path) -> bool:
    try:
        if os.statvfs(path).f_flag & os.ST_RDONLY:
            return False
    except (OSError, AttributeError):
        pass
    return os.access(path, os.W_OK)


def can_self_update() -> bool:
    """
    Whether this process can replace itself by running the installer.

    Windows: the installed layout (the folder build the installer puts in
    Program Files) - a portable exe is pointed at the releases page instead,
    since the installer would add a second copy rather than update it.
    macOS: running from a .app bundle in a writable folder (not straight off
    the DMG). Linux: the installed folder (install.sh) when writable. A
    source checkout never self-updates.
    """
    if not is_frozen():
        return False
    system = platform.system()
    here = app_dir()
    if system == "Windows":
        return (here / "_internal").is_dir() and (here / "CybXNetworkLens.exe").exists()
    if system == "Darwin":
        bundle = app_bundle_path()
        return bundle is not None and _writable_dir(bundle.parent)
    if system == "Linux":
        return (here / "networklens-gui").exists() and _writable_dir(here)
    return False


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


def apply_update(package_path: str) -> None:
    """
    Install the verified package for this platform and start the new version.
    The caller must exit promptly afterwards.
    """
    system = platform.system()
    if system == "Windows":
        run_installer(package_path)
    elif system == "Darwin":
        _install_dmg(package_path)
    elif system == "Linux":
        _install_tarball(package_path)
    else:
        raise UpdateError(f"Self-update is not available on {system}.")


def _relaunch(executable: Path) -> None:
    """Start the new build, detached, with the same environment (it is already
    elevated, so the loop guard keeps it from prompting again)."""
    env = dict(os.environ)
    env["CYBX_ELEVATED"] = "1"
    try:
        subprocess.Popen([str(executable)], env=env, cwd="/", close_fds=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except OSError as e:
        raise UpdateError(f"Installed, but could not start the new version: {e}")


def _install_dmg(dmg_path: str, bundle: Optional[Path] = None) -> Path:
    """
    Replace the running .app with the one inside the DMG. Returns the new
    bundle path. `bundle` is the app to replace (default: the running one).
    """
    bundle = bundle or app_bundle_path()
    if bundle is None:
        raise UpdateError("Not running from an .app bundle; download the update from the releases page.")
    if not _writable_dir(bundle.parent):
        raise UpdateError(f"{bundle.parent} is not writable (is the app still on the disk image? "
                          "Drag it to Applications first).")
    mount = Path(tempfile.mkdtemp(prefix="networklens-dmg-"))
    try:
        r = subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", str(mount), dmg_path],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise UpdateError(f"Could not open the downloaded disk image: {(r.stderr or r.stdout).strip()}")
        apps = [p for p in mount.iterdir() if p.suffix == ".app"]
        if not apps:
            raise UpdateError("The disk image holds no application bundle.")
        new_app = apps[0]
        staged = bundle.parent / (bundle.name + ".update")
        shutil.rmtree(staged, ignore_errors=True)
        # ditto keeps the code signature, permissions and resource forks intact.
        r = subprocess.run(["ditto", str(new_app), str(staged)], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            shutil.rmtree(staged, ignore_errors=True)
            raise UpdateError(f"Could not copy the new version: {(r.stderr or r.stdout).strip()}")
        r = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(staged)],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            shutil.rmtree(staged, ignore_errors=True)
            raise UpdateError("The new version's code signature does not verify; not installing it.")
        old = bundle.parent / (bundle.name + ".old")
        shutil.rmtree(old, ignore_errors=True)
        os.rename(bundle, old)
        try:
            os.rename(staged, bundle)
        except OSError:
            os.rename(old, bundle)
            raise
        shutil.rmtree(old, ignore_errors=True)
    finally:
        subprocess.run(["hdiutil", "detach", str(mount), "-force"], capture_output=True, timeout=120)
        shutil.rmtree(mount, ignore_errors=True)
    try:
        from paths import claim_for_owner
    except ImportError:
        from .paths import claim_for_owner
    claim_for_owner(bundle)
    exe = bundle / "Contents" / "MacOS" / "networklens-gui"
    if not exe.exists():
        raise UpdateError(f"Installed, but {exe} is missing.")
    _relaunch(exe)
    return bundle


def _install_tarball(tar_path: str, dest: Optional[Path] = None) -> Path:
    """Unpack the Linux package over the installed folder and relaunch."""
    import tarfile
    dest = dest or app_dir()
    if not _writable_dir(dest):
        raise UpdateError(f"{dest} is not writable; run the app with administrator rights to update.")
    with tempfile.TemporaryDirectory(prefix="networklens-tgz-") as tmp:
        with tarfile.open(tar_path, "r:gz") as tar:
            members = [m for m in tar.getmembers() if not (m.name.startswith("/") or ".." in m.name)]
            tar.extractall(tmp, members=members)
        roots = [p for p in Path(tmp).iterdir() if p.is_dir()]
        src = roots[0] if roots else Path(tmp)
        for name in ("networklens", "networklens-gui"):
            new = src / name
            if not new.exists():
                raise UpdateError(f"The package has no {name}.")
            target = dest / name
            tmp_target = dest / (name + ".update")
            shutil.copy2(new, tmp_target)
            os.chmod(tmp_target, 0o755)
            os.replace(tmp_target, target)
        for extra in ("README.txt", "icon.png", "install.sh", "uninstall.sh"):
            if (src / extra).exists():
                try:
                    shutil.copy2(src / extra, dest / extra)
                except OSError:
                    pass
    _relaunch(dest / "networklens-gui")
    return dest


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
