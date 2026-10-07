# macOS nmap bundle

Do NOT copy files here by hand. Run (needs `brew install nmap`):

    build/bundle_nmap_macos.sh

build/build_macos.sh runs it automatically when this folder is empty.

It puts three things here, and all three are required:

    nmap                  the binary
    nse_main.lua, nselib/, scripts/, nmap-services, nmap-service-probes,
    nmap-os-db, ...       nmap's data directory - missing files abort the scan
    lib/*.dylib           the Homebrew libraries nmap links against (OpenSSL,
                          libssh2, Lua, PCRE2, liblinear), rewritten to load
                          from here so the bundle runs on Macs without Homebrew

The bundle matches this Mac's CPU (Apple Silicon or Intel). To refresh after
upgrading nmap, delete everything here except this file and re-run the script.
