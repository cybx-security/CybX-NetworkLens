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

Root (sudo) is needed for full scans - SYN scan, OS detection, UDP services.
Without it the scanner still works, falling back to a TCP-connect scan.
The menu entry asks for your password via pkexec when it can; on desktops
where that is blocked (some Wayland setups) it runs unprivileged instead.

Reports are saved under ~/Documents/CybX NetworkLens/output.
Settings: ~/.config/cybx-networklens/config.json (created on first edit).
