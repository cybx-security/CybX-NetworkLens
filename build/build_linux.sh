#!/bin/bash
# Build script for Linux
# Creates a standalone executable with bundled nmap

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/dist"
BINARIES_DIR="$PROJECT_DIR/binaries/linux"

echo "=========================================="
echo "  Nmap Analyzer - Linux Build Script"
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

# Check for nmap binary
if [ ! -f "$BINARIES_DIR/nmap" ]; then
    echo "[*] Nmap binary not found in $BINARIES_DIR"
    echo ""
    echo "To bundle nmap, you have several options:"
    echo ""
    echo "Option 1: Copy from system installation"
    echo "  If you have nmap installed:"
    echo "    cp \$(which nmap) $BINARIES_DIR/"
    echo ""
    echo "Option 2: Download static build"
    echo "  1. Download a static nmap build"
    echo "  2. Copy to $BINARIES_DIR/"
    echo ""
    echo "Option 3: Use system nmap (no bundling)"
    echo "  The app will fall back to system nmap if bundled binary is not found."
    echo "  Install with: sudo apt install nmap"
    echo ""
    
    # Try to copy from system if available
    if command -v nmap &> /dev/null; then
        NMAP_PATH=$(which nmap)
        echo "[*] Found nmap at $NMAP_PATH"
        read -p "Copy to binaries directory? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp "$NMAP_PATH" "$BINARIES_DIR/"
            chmod +x "$BINARIES_DIR/nmap"
            echo "[+] Copied nmap to $BINARIES_DIR/"
            
            # Copy nmap data files
            NMAP_DATA_DIR="/usr/share/nmap"
            if [ -d "$NMAP_DATA_DIR" ]; then
                echo "[*] Copying nmap data files..."
                cp -r "$NMAP_DATA_DIR"/* "$BINARIES_DIR/" 2>/dev/null || true
            fi
        fi
    fi
fi

cd "$PROJECT_DIR"

# ============================================================
# Build 1: CLI binary
# ============================================================
echo "[*] Building CLI executable (nmap-analyzer)..."
pyinstaller \
    --name nmap-analyzer \
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
# Build 2: GUI binary
# ============================================================
echo ""
echo "[*] Building GUI executable (nmap-analyzer-gui)..."
pyinstaller \
    --name nmap-analyzer-gui \
    --onefile \
    --windowed \
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
echo ""
# The file-presence checks above only catch problems someone thought to list.
# Running the binary we just built catches the rest: if it can scan localhost
# end to end, the bundle is good.
if ! "$BUILD_DIR/nmap-analyzer" --self-test; then
    echo ""
    echo "[!] The build completed but the executable cannot scan."
    echo "[!] Read the self-test output above - it names what is missing."
    echo "[!] Do NOT ship this build."
    exit 1
fi

echo ""
echo "=========================================="
echo "  Build Complete!"
echo "=========================================="
echo ""
echo "CLI executable: $BUILD_DIR/nmap-analyzer"
echo "GUI executable: $BUILD_DIR/nmap-analyzer-gui"
echo ""
echo "CLI usage (needs sudo for SYN scan / OS detection):"
echo "  sudo $BUILD_DIR/nmap-analyzer --target 192.168.1.0/24"
echo ""
echo "GUI usage (needs sudo for SYN scan / OS detection):"
echo "  sudo $BUILD_DIR/nmap-analyzer-gui"
echo ""
echo "Note: Linux does not auto-elevate. Run with sudo from a terminal,"
echo "or use a .desktop launcher with 'pkexec' if you want GUI elevation prompts."
echo ""
