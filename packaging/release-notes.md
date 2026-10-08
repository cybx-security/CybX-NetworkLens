## Downloads

| Platform | File | How to install |
|---|---|---|
| **Windows 10/11** (64-bit) | `CybXNetworkLens-Setup-<version>.exe` | Run it. Adds Desktop + Start Menu icons and an uninstaller. Offers to install Npcap (needed for full scans). Windows shows "Windows protected your PC" the first time: click **More info › Run anyway**. |
| Windows, portable | `networklens-gui.exe`, `networklens.exe` | No install - run from anywhere, e.g. a USB stick. |
| **macOS** Apple Silicon | `CybXNetworkLens-<version>-macos-arm64.dmg` | Open, drag to Applications. First launch: System Settings › Privacy & Security › **Open Anyway** (the app isn't notarized yet). |
| **macOS** Intel | `CybXNetworkLens-<version>-macos-x86_64.dmg` | Same as above. |
| **Linux** x86-64 / arm64 | `CybXNetworkLens-<version>-linux-<arch>.tar.gz` | `tar xzf`, then `sudo ./install.sh` (needs `nmap` from your distro). |

`SHA256SUMS` lists every file's checksum; the app's **Check for Updates** verifies the Windows installer against it before installing.

Full scans (SYN scan, OS detection, UDP services) need administrator/root rights: the Windows app asks automatically; on macOS/Linux start it with `sudo` (details in the READ ME inside each download). Without them the scanner still runs, using a TCP-connect scan.

## Changes
