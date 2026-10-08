CybX NetworkLens for Linux
==========================

Needs nmap from your distribution (it is not bundled on Linux):
    Debian/Ubuntu:  sudo apt install nmap
    Fedora/RHEL:    sudo dnf install nmap

Install (application-menu entry + `networklens` command):
    sudo ./install.sh
Remove:
    sudo ./uninstall.sh

Or run in place, no install:
    sudo ./networklens-gui            # graphical
    sudo ./networklens --target 192.168.1.0/24

Root is needed for full scans - SYN scan, OS detection, UDP services. The
graphical app asks for your password itself when it starts (through
pkexec, on desktops that allow it); click Cancel, or run on a desktop that
blocks it (some Wayland setups), and it carries on unprivileged with a
TCP-connect scan. The command line does not prompt - use sudo.

Reports are saved under ~/Documents/CybX NetworkLens/output.
Settings: ~/.config/cybx-networklens/config.json (created on first edit).
