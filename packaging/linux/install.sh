#!/bin/sh
# Installs CybX NetworkLens system-wide from this folder. Run with sudo:
#   sudo ./install.sh
# Puts the program in /opt/cybx-networklens, the CLI on the PATH as
# `networklens`, and an application-menu entry. Remove with uninstall.sh.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/cybx-networklens

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo:  sudo $0" >&2
    exit 1
fi
if ! command -v nmap >/dev/null 2>&1; then
    echo "nmap is not installed. NetworkLens uses the system nmap on Linux - install it first:"
    echo "    Debian/Ubuntu:  sudo apt install nmap"
    echo "    Fedora/RHEL:    sudo dnf install nmap"
    echo "    Arch:           sudo pacman -S nmap"
    exit 1
fi

mkdir -p "$DEST"
cp "$HERE/networklens" "$HERE/networklens-gui" "$DEST/"
cp "$HERE/icon.png" "$DEST/icon.png"
cp "$HERE/README.txt" "$DEST/README.txt"
chmod 755 "$DEST/networklens" "$DEST/networklens-gui"
ln -sf "$DEST/networklens" /usr/local/bin/networklens

# Full scans (SYN, OS detection, UDP) need root. The launcher asks for the
# password through pkexec where it can show a prompt, and otherwise runs
# unprivileged, where the scanner falls back to a TCP-connect scan.
cat > "$DEST/launch-gui.sh" <<'LAUNCH'
#!/bin/sh
APP=/opt/cybx-networklens/networklens-gui
if [ "$(id -u)" -ne 0 ] && command -v pkexec >/dev/null 2>&1 && [ -n "$DISPLAY" ]; then
    exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" HOME="$HOME" "$APP" "$@"
fi
exec "$APP" "$@"
LAUNCH
chmod 755 "$DEST/launch-gui.sh"

mkdir -p /usr/share/applications
cat > /usr/share/applications/cybx-networklens.desktop <<DESKTOP
[Desktop Entry]
Type=Application
Name=CybX NetworkLens
Comment=Scan a network for devices, open ports and risky services
Exec=$DEST/launch-gui.sh
Icon=$DEST/icon.png
Terminal=false
Categories=Network;Security;
DESKTOP
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database /usr/share/applications || true

echo "Installed. Find 'CybX NetworkLens' in your application menu, or run: networklens --help"
echo "Reports are saved under ~/Documents/CybX NetworkLens (or /root/Documents when run as root)."
