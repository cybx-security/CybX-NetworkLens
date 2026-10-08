#!/bin/bash
# Build script for Linux
# Creates a standalone executable with bundled nmap

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/dist"
BINARIES_DIR="$PROJECT_DIR/binaries/linux"

echo "=========================================="
echo "  CybX NetworkLens - Linux Build Script"
echo "=========================================="

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is required but not installed."
    echo "[!] Install with: sudo apt install python3 python3-venv python3-pip"
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
# nmap: NOT bundled on Linux. The distro package is one command
# away, matches the machine's libraries, and gets security updates
# with the rest of the system - a copy taken from this build box
# would only run where the same shared libraries exist. The build
# therefore relies on the system nmap and tells the self-test so.
# ============================================================
if ! command -v nmap &> /dev/null; then
    echo "[!] nmap is required to self-test the build:  sudo apt install nmap"
    exit 1
fi
export ALLOW_SYSTEM_NMAP=1

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
    --collect-all sv_ttk \
    --hidden-import gui \
    --hidden-import local_analyzer \
    --hidden-import selftest \
    --paths src \
    src/main.py

# ============================================================
# Build 2: GUI binary
# ============================================================
echo ""
echo "[*] Building GUI executable (networklens-gui)..."
pyinstaller \
    --name networklens-gui \
    --onefile \
    --windowed \
    --noconfirm \
    --clean \
    --add-data "config:config" \
    --add-data "binaries:binaries" \
    --add-data "installers:installers" \
    --add-data "packaging/icon:packaging/icon" \
    --collect-all sv_ttk \
    --hidden-import local_analyzer \
    --hidden-import selftest \
    --paths src \
    src/gui.py

echo ""
echo "[*] Running build self-test (scans localhost, takes ~30s)..."
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
# Package: tar.gz with both executables, the icon, a READ ME and
# install/uninstall scripts (menu entry + `networklens` on PATH).
# ============================================================
VERSION="$(python3 "$PROJECT_DIR/src/version.py")"
ARCH="$(uname -m)"
NAME="CybXNetworkLens-$VERSION-linux-$ARCH"
STAGE="$(mktemp -d)"
mkdir -p "$STAGE/$NAME"
cp "$BUILD_DIR/networklens" "$BUILD_DIR/networklens-gui" "$STAGE/$NAME/"
cp "$PROJECT_DIR/packaging/linux/install.sh" "$PROJECT_DIR/packaging/linux/uninstall.sh" \
   "$PROJECT_DIR/packaging/linux/README.txt" "$STAGE/$NAME/"
cp "$PROJECT_DIR/packaging/icon/icon.png" "$STAGE/$NAME/icon.png"
chmod 755 "$STAGE/$NAME"/networklens "$STAGE/$NAME"/networklens-gui "$STAGE/$NAME"/*.sh
tar -czf "$BUILD_DIR/$NAME.tar.gz" -C "$STAGE" "$NAME"
rm -rf "$STAGE"
echo "[+] Package: $BUILD_DIR/$NAME.tar.gz"

echo ""
echo "=========================================="
echo "  Build Complete!"
echo "=========================================="
echo ""
echo "Package (give this to users): $BUILD_DIR/$NAME.tar.gz"
echo "CLI executable: $BUILD_DIR/networklens"
echo "GUI executable: $BUILD_DIR/networklens-gui"
echo ""
echo "CLI usage (needs sudo for SYN scan / OS detection):"
echo "  sudo $BUILD_DIR/networklens --target 192.168.1.0/24"
echo ""
echo "GUI usage (needs sudo for SYN scan / OS detection):"
echo "  sudo $BUILD_DIR/networklens-gui"
echo ""
echo "Note: Linux does not auto-elevate. Run with sudo from a terminal,"
echo "or use a .desktop launcher with 'pkexec' if you want GUI elevation prompts."
echo ""
