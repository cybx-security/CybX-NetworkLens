# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for the INSTALLED layout - the folder the Windows installer
# (packaging/windows/installer.nsi) copies into Program Files:
#
#   dist/CybXNetworkLens/
#       CybXNetworkLens.exe   GUI: windowed, elevates through UAC
#       networklens.exe        CLI: console, same engine
#       _internal/               Python runtime, nmap, Npcap installer, icon
#
# Why a folder and not the single-file exes the build scripts also make: a
# --onefile exe unpacks itself - nmap and several hundred script files included
# - into a temp directory on every launch. Fine from a USB stick, but an
# installed app that sits there for ten seconds after a double-click looks
# broken. A folder build starts immediately and nmap runs from Program Files.
#
# Build (from the project root):
#   python -m PyInstaller --noconfirm --clean packaging/installed_app.spec
#
# Both executables share one _internal folder. The data list below must match
# the --add-data flags in build/build_windows.bat: the self-test run against
# this folder at build time fails if nmap or the icon is missing from it.

import os
import sys

from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
SRC = os.path.join(ROOT, 'src')
IS_WINDOWS = sys.platform == 'win32'
ICON = os.path.join(ROOT, 'packaging', 'icon',
                    'icon.ico' if IS_WINDOWS else 'icon.icns')

datas = [
    (os.path.join(ROOT, 'config'), 'config'),
    (os.path.join(ROOT, 'binaries'), 'binaries'),
    (os.path.join(ROOT, 'installers'), 'installers'),
    (os.path.join(ROOT, 'packaging', 'icon'), os.path.join('packaging', 'icon')),
]
hiddenimports = ['gui', 'local_analyzer', 'selftest']

# The Sun Valley ttk theme is Tcl files inside the sv_ttk package; PyInstaller
# only finds the Python side on its own.
_sv_datas, _sv_binaries, _sv_hidden = collect_all('sv_ttk')
datas += _sv_datas
hiddenimports += _sv_hidden


def analyse(script):
    return Analysis(
        [os.path.join(SRC, script)],
        pathex=[SRC],
        datas=datas,
        hiddenimports=hiddenimports,
    )


gui_a = analyse('gui.py')
cli_a = analyse('main.py')

gui_exe = EXE(
    PYZ(gui_a.pure),
    gui_a.scripts,
    [],
    exclude_binaries=True,
    name='CybXNetworkLens',
    console=False,
    # Scans need raw sockets, so the GUI always asks for elevation at launch.
    uac_admin=True,
    icon=ICON,
)

cli_exe = EXE(
    PYZ(cli_a.pure),
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name='networklens',
    console=True,
    icon=ICON,
)

COLLECT(
    gui_exe,
    cli_exe,
    gui_a.binaries,
    gui_a.datas,
    cli_a.binaries,
    cli_a.datas,
    name='CybXNetworkLens',
)
