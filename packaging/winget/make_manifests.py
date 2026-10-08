#!/usr/bin/env python3
"""Write winget manifests for a published CybX NetworkLens release.

    python packaging/winget/make_manifests.py 1.3.0 [--out DIR]

Reads SHA256SUMS from the GitHub release (so the version must be published)
and writes the three manifest files winget-pkgs expects.
"""
import argparse
import os
import sys
import urllib.request

REPO = "cybx-security/CybX-NetworkLens"
PACKAGE_ID = "CybX.NetworkLens"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--out", default="manifests")
    args = ap.parse_args()
    v = args.version.lstrip("v")
    base = f"https://github.com/{REPO}/releases/download/v{v}"
    setup = f"CybXNetworkLens-Setup-{v}.exe"
    try:
        sums = urllib.request.urlopen(f"{base}/SHA256SUMS", timeout=30).read().decode()
    except Exception as e:
        print(f"Could not fetch {base}/SHA256SUMS - is v{v} published? ({e})", file=sys.stderr)
        return 1
    digest = next((line.split()[0].upper() for line in sums.splitlines()
                   if line.strip().endswith(setup)), None)
    if not digest:
        print(f"{setup} not listed in SHA256SUMS", file=sys.stderr)
        return 1

    folder = os.path.join(args.out, "c", "CybX", "NetworkLens", v)
    os.makedirs(folder, exist_ok=True)
    files = {
        f"{PACKAGE_ID}.yaml": f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
PackageIdentifier: {PACKAGE_ID}
PackageVersion: {v}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
""",
        f"{PACKAGE_ID}.installer.yaml": f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
PackageIdentifier: {PACKAGE_ID}
PackageVersion: {v}
InstallerType: nullsoft
Scope: machine
InstallModes:
  - interactive
  - silent
InstallerSwitches:
  Silent: /S
  SilentWithProgress: /S
UpgradeBehavior: install
Installers:
  - Architecture: x64
    InstallerUrl: {base}/{setup}
    InstallerSha256: {digest}
ManifestType: installer
ManifestVersion: 1.6.0
""",
        f"{PACKAGE_ID}.locale.en-US.yaml": f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: {PACKAGE_ID}
PackageVersion: {v}
PackageLocale: en-US
Publisher: CybX
PublisherUrl: https://github.com/cybx-security
PublisherSupportUrl: https://github.com/{REPO}/issues
PackageName: CybX NetworkLens
PackageUrl: https://github.com/{REPO}
License: Proprietary
ShortDescription: Network scanner that finds devices, open ports and risky services, with offline risk analysis.
Tags:
  - network
  - nmap
  - security
  - scanner
ReleaseNotesUrl: https://github.com/{REPO}/releases/tag/v{v}
ManifestType: defaultLocale
ManifestVersion: 1.6.0
""",
    }
    for name, text in files.items():
        with open(os.path.join(folder, name), "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote", os.path.join(folder, name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
