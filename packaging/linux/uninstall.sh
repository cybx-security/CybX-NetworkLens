#!/bin/sh
# Removes CybX NetworkLens installed by install.sh. Run with sudo.
# Saved scan reports (Documents/CybX NetworkLens) are left in place.
set -e
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo:  sudo $0" >&2
    exit 1
fi
rm -f /usr/share/applications/cybx-networklens.desktop /usr/local/bin/networklens
rm -rf /opt/cybx-networklens
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database /usr/share/applications || true
echo "CybX NetworkLens removed. Scan reports in Documents/CybX NetworkLens were kept."
