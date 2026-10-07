#!/bin/bash
# Bundle the Homebrew nmap into binaries/macos/ so a built app works on a Mac
# that has neither Homebrew nor nmap.
#
# Three things have to travel together, and the first two are what people
# forget:
#   1. nmap's DATA directory (nselib/, scripts/, nmap-services, nmap-os-db, ...)
#      - nmap loads these at startup and a missing one is a hard failure, not a
#      skipped feature. Copying just the nmap binary gives a bundle the
#      self-test rejects.
#   2. The Homebrew LIBRARIES nmap links against (OpenSSL, libssh2, Lua, PCRE2,
#      liblinear). The binary refers to them by absolute /opt/homebrew paths,
#      so on a machine without Homebrew it dies before main() with
#      "Library not loaded". They are copied into lib/ and the references
#      rewritten to @loader_path, then everything is re-signed (ad hoc) -
#      Apple Silicon refuses to run a binary whose signature no longer matches.
#   3. The nmap binary itself.
#
# Usage:  build/bundle_nmap_macos.sh            (called by build_macos.sh)
# Needs:  brew install nmap
#
# The result is for the CPU this Mac has (Apple Silicon or Intel) - a build
# made on an M-series Mac does not run on an Intel Mac, and vice versa.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEST="$PROJECT_DIR/binaries/macos"
LIBDIR="$DEST/lib"

NMAP_BIN="$(command -v nmap || true)"
if [ -z "$NMAP_BIN" ]; then
    echo "[!] nmap is not installed. Install it first:  brew install nmap"
    exit 1
fi
NMAP_BIN="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$NMAP_BIN")"

# Homebrew's data dir sits next to the binary's prefix: <prefix>/share/nmap.
PREFIX="$(dirname "$(dirname "$NMAP_BIN")")"
DATADIR="$PREFIX/share/nmap"
if [ ! -f "$DATADIR/nse_main.lua" ]; then
    # Non-Homebrew install (e.g. the nmap.org package)
    for candidate in /usr/local/share/nmap /opt/homebrew/share/nmap /usr/share/nmap; do
        if [ -f "$candidate/nse_main.lua" ]; then DATADIR="$candidate"; break; fi
    done
fi
if [ ! -f "$DATADIR/nse_main.lua" ]; then
    echo "[!] Found nmap at $NMAP_BIN but not its data directory (share/nmap)."
    exit 1
fi

echo "[*] Bundling nmap from: $NMAP_BIN"
echo "[*] Data directory    : $DATADIR"

# Start clean so files from an older nmap don't linger.
find "$DEST" -mindepth 1 ! -name README.txt -exec rm -rf {} + 2>/dev/null || true
mkdir -p "$LIBDIR"

cp -R "$DATADIR"/. "$DEST/"
cp "$NMAP_BIN" "$DEST/nmap"
chmod 755 "$DEST/nmap"

# ---- libraries -------------------------------------------------------------
# Walk the dependency tree: nmap -> libssh2 -> openssl -> ... Anything under
# /usr/lib or /System is part of macOS and is left alone.

is_system_lib() {
    case "$1" in
        /usr/lib/*|/System/*) return 0 ;;
        *) return 1 ;;
    esac
}

deps_of() {
    # Dependencies of a Mach-O file, one absolute path per line (not its own id).
    otool -L "$1" | tail -n +2 | awk '{print $1}' | grep -v "^@" || true
}

declare -a QUEUE=("$DEST/nmap")
declare -a COPIED=()
while [ ${#QUEUE[@]} -gt 0 ]; do
    target="${QUEUE[0]}"; QUEUE=("${QUEUE[@]:1}")
    while IFS= read -r dep; do
        [ -z "$dep" ] && continue
        is_system_lib "$dep" && continue
        real="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$dep")"
        name="$(basename "$dep")"
        if [ ! -f "$LIBDIR/$name" ]; then
            if [ ! -f "$real" ]; then
                echo "[!] $target needs $dep, which does not exist on this machine."
                exit 1
            fi
            cp "$real" "$LIBDIR/$name"
            chmod 644 "$LIBDIR/$name"
            COPIED+=("$name")
            QUEUE+=("$LIBDIR/$name")
            echo "    + lib/$name"
        fi
        # nmap is in the bundle root, the libraries in lib/ beside it.
        if [ "$target" = "$DEST/nmap" ]; then
            install_name_tool -change "$dep" "@loader_path/lib/$name" "$target" 2>/dev/null
        else
            install_name_tool -change "$dep" "@loader_path/$name" "$target" 2>/dev/null
        fi
    done < <(deps_of "$target")
done

for name in "${COPIED[@]}"; do
    install_name_tool -id "@loader_path/$name" "$LIBDIR/$name" 2>/dev/null
done

# Modifying a binary invalidates its signature; re-sign everything ad hoc.
for f in "$DEST/nmap" "$LIBDIR"/*.dylib; do
    [ -f "$f" ] && codesign --force -s - "$f" >/dev/null 2>&1
done

# ---- verify ----------------------------------------------------------------
# No absolute non-system paths may remain, or the bundle is tied to this Mac.
leftover="$( (otool -L "$DEST/nmap"; for f in "$LIBDIR"/*.dylib; do otool -L "$f"; done) \
             | awk '{print $1}' | grep -E '^/(opt|usr/local)/' || true)"
if [ -n "$leftover" ]; then
    echo "[!] These library references still point at this machine:"
    echo "$leftover"
    exit 1
fi

for required in nmap nse_main.lua nselib scripts nmap-services nmap-service-probes nmap-os-db; do
    if [ ! -e "$DEST/$required" ]; then
        echo "[!] Bundle is incomplete: $required missing from $DEST"
        exit 1
    fi
done

# Prove it runs from the bundle with its own data and libraries, from a
# directory where Homebrew's copies can't be picked up by accident.
if ! (cd / && "$DEST/nmap" --datadir "$DEST" --version >/dev/null); then
    echo "[!] The bundled nmap does not run."
    exit 1
fi

echo "[+] nmap bundled into $DEST ($(ls "$LIBDIR" | wc -l | tr -d ' ') libraries, $(du -sh "$DEST" | cut -f1))"
