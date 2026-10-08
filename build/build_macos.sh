#!/bin/bash
# Build script for macOS
# Creates a standalone executable with bundled nmap

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/dist"
BINARIES_DIR="$PROJECT_DIR/binaries/macos"

echo "=========================================="
echo "  CybX NetworkLens - macOS Build"
echo "=========================================="

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment if needed
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/venv"
fi

# Activate virtual environment
source "$PROJECT_DIR/venv/bin/activate"

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r "$PROJECT_DIR/requirements.txt"

# Create binaries directory
mkdir -p "$BINARIES_DIR"

# ============================================================
# Bundle nmap - binary, data files AND libraries.
#
# Copying the nmap binary alone is not enough twice over: nmap
# needs its data directory (nselib/, scripts/, nmap-services,
# ...) or it aborts at startup, and the Homebrew binary links
# against Homebrew libraries by absolute path, so it won't start
# on a Mac without Homebrew. bundle_nmap_macos.sh handles all of
# it and refuses to leave an incomplete bundle behind.
# ============================================================
if [ -f "$BINARIES_DIR/nmap" ] && [ -f "$BINARIES_DIR/nse_main.lua" ] && [ -d "$BINARIES_DIR/lib" ]; then
    echo "[*] Using the nmap already bundled in $BINARIES_DIR"
    echo "    (delete that folder's contents to re-bundle from Homebrew)"
else
    if ! command -v nmap &> /dev/null; then
        echo "[!] nmap is not installed on this Mac, so there is nothing to bundle."
        echo "    Install it, then run this script again:"
        echo "        brew install nmap"
        exit 1
    fi
    "$SCRIPT_DIR/bundle_nmap_macos.sh"
fi

cd "$PROJECT_DIR"

# ============================================================
# Build 1: CLI binary
# ============================================================
echo "[*] Building CLI executable (networklens)..."
pyinstaller \
    --name networklens \
    --onefile \
    --console \
    --noconfirm \
    --clean \
    --add-data "config:config" \
    --add-data "binaries:binaries" \
    --add-data "installers:installers" \
    --add-data "packaging/icon:packaging/icon" \
    --hidden-import gui \
    --hidden-import local_analyzer \
    --hidden-import selftest \
    --paths src \
    src/main.py

# ============================================================
# Build 2: GUI binary (windowed → produces .app bundle)
# ============================================================
echo ""
echo "[*] Building GUI executable (networklens-gui.app)..."
pyinstaller \
    --name networklens-gui \
    --onefile \
    --windowed \
    --icon packaging/icon/icon.icns \
    --noconfirm \
    --clean \
    --add-data "config:config" \
    --add-data "binaries:binaries" \
    --add-data "installers:installers" \
    --add-data "packaging/icon:packaging/icon" \
    --hidden-import local_analyzer \
    --hidden-import selftest \
    --paths src \
    src/gui.py

echo ""
echo "[*] Running build self-test (scans localhost, takes ~30s)..."
echo "    (runs from / so the bundle can't borrow Homebrew's nmap by accident)"
echo ""
# The file-presence checks above only catch problems someone thought to list.
# Running the binary we just built catches the rest: if it can scan localhost
# end to end, the bundle is good.
if ! (cd / && "$BUILD_DIR/networklens" --self-test); then
    echo ""
    echo "[!] The build completed but the executable cannot scan."
    echo "[!] Read the self-test output above - it names what is missing."
    echo "[!] Do NOT ship this build."
    exit 1
fi

# ============================================================
# Package: a DMG with the app, an Applications shortcut, the CLI
# and a READ ME - the usual drag-to-install download.
# ============================================================
VERSION="$(python3 "$PROJECT_DIR/src/version.py")"
ARCH="$(uname -m)"
DMG="$BUILD_DIR/CybXNetworkLens-$VERSION-macos-$ARCH.dmg"
STAGE="$(mktemp -d)"
cp -R "$BUILD_DIR/networklens-gui.app" "$STAGE/CybX NetworkLens.app"
cp "$BUILD_DIR/networklens" "$STAGE/networklens"
cp "$PROJECT_DIR/packaging/macos/READ ME FIRST.txt" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "CybX NetworkLens $VERSION" -srcfolder "$STAGE" -ov -format UDZO -quiet "$DMG"
rm -rf "$STAGE"
echo "[+] Disk image: $DMG"

echo ""
echo "=========================================="
echo "  Build Complete!"
echo "=========================================="
echo ""
echo "Disk image (give this to users): $DMG"
echo "CLI executable: $BUILD_DIR/networklens"
echo "GUI app bundle: $BUILD_DIR/networklens-gui.app"
echo ""
echo "CLI usage (needs sudo for SYN scan / OS detection):"
echo "  sudo $BUILD_DIR/networklens --target 192.168.1.0/24"
echo ""
echo "GUI usage:"
echo "  open $BUILD_DIR/networklens-gui.app"
echo "  (Note: macOS does not auto-elevate — to scan with SYN/OS detection,"
echo "   launch from Terminal with: sudo $BUILD_DIR/networklens-gui.app/Contents/MacOS/networklens-gui)"
echo ""
echo "The bundled nmap is for this Mac's CPU ($(uname -m)) only; build on an"
echo "Intel Mac for Intel users. Unsigned: first launch needs right-click > Open."
echo ""
