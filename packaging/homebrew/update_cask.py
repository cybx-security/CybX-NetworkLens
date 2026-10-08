#!/usr/bin/env python3
"""Fill the Homebrew cask's version and checksums from a published release.

    python packaging/homebrew/update_cask.py 1.3.0
"""
import re
import sys
import urllib.request

REPO = "cybx-security/CybX-NetworkLens"
CASK = __file__.rsplit("/", 1)[0] + "/cybx-networklens.rb"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    v = sys.argv[1].lstrip("v")
    url = f"https://github.com/{REPO}/releases/download/v{v}/SHA256SUMS"
    try:
        sums = urllib.request.urlopen(url, timeout=30).read().decode()
    except Exception as e:
        print(f"Could not fetch {url} - is v{v} published? ({e})", file=sys.stderr)
        return 1
    digests = {}
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) == 2:
            digests[parts[1]] = parts[0]
    arm = digests.get(f"CybXNetworkLens-{v}-macos-arm64.dmg")
    intel = digests.get(f"CybXNetworkLens-{v}-macos-x86_64.dmg")
    if not (arm and intel):
        print("Both macOS DMGs must be in SHA256SUMS", file=sys.stderr)
        return 1
    text = open(CASK, encoding="utf-8").read()
    text = re.sub(r'version "[^"]+"', f'version "{v}"', text, count=1)
    text = re.sub(r'arm:\s+"[^"]+"', f'arm:   "{arm}"', text, count=1)
    text = re.sub(r'intel:\s+"[^"]+"', f'intel: "{intel}"', text, count=1)
    open(CASK, "w", encoding="utf-8").write(text)
    print(f"updated {CASK} to {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
