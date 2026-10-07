@echo off
REM Build script for Windows
REM Creates, in dist\:
REM   - nmap-analyzer.exe / nmap-analyzer-gui.exe   portable single-file exes
REM   - CybXNetworkScanner\                          the installed-app folder
REM   - CybXNetworkScanner-Setup-x.y.z.exe          the installer (needs NSIS)
REM all with bundled nmap/Npcap.
REM Safe to double-click: the window always stays open, and everything is
REM also written to build\build_log.txt.
REM
REM Environment switches (for CI - .github\workflows\release.yml):
REM   NO_PAUSE=1    don't wait for a key press at the end
REM   SKIP_NPCAP=1  don't download the Npcap installer (don't bundle it)

setlocal enabledelayedexpansion
title CybX Network Scanner - Windows Build

set SCRIPT_DIR=%~dp0
for %%I in ("%SCRIPT_DIR%..") do set PROJECT_DIR=%%~fI
set BUILD_DIR=%PROJECT_DIR%\dist
set BINARIES_DIR=%PROJECT_DIR%\binaries\windows
set INSTALLERS_DIR=%PROJECT_DIR%\installers\windows
set LOG_FILE=%SCRIPT_DIR%build_log.txt
set ICON_FILE=%PROJECT_DIR%\packaging\icon\icon.ico
set APP_DIR=%BUILD_DIR%\CybXNetworkScanner
set NPCAP_VERSION=1.79
set NPCAP_URL=https://npcap.com/dist/npcap-%NPCAP_VERSION%.exe

echo ========================================== > "%LOG_FILE%"
echo   CybX Network Scanner - Windows Build >> "%LOG_FILE%"
echo ========================================== >> "%LOG_FILE%"

echo ==========================================
echo   CybX Network Scanner - Windows Build
echo ==========================================
echo.
echo A full log is written to: %LOG_FILE%
echo.

REM ============================================================
REM Find a real Python 3.
REM Fresh Windows installs have a fake "python.exe" alias that
REM opens the Microsoft Store - it exists but can't run anything,
REM so test that it actually executes. Prefer the "py" launcher.
REM ============================================================
set PYTHON=
py -3 --version >nul 2>&1
if not errorlevel 1 set PYTHON=py -3
if not defined PYTHON (
    python --version >nul 2>&1
    if not errorlevel 1 set PYTHON=python
)
if not defined PYTHON (
    echo [!] Python 3 was not found on this machine.
    echo [!] The "python" command on fresh Windows installs is a fake
    echo     shortcut to the Microsoft Store, not real Python.
    echo.
    echo     Fix: download Python from https://python.org/downloads
    echo     and during install CHECK THE BOX "Add python.exe to PATH".
    echo     Then run this script again.
    goto :fail
)
echo [*] Using Python: %PYTHON%
%PYTHON% --version
%PYTHON% --version >> "%LOG_FILE%" 2>&1

REM Create virtual environment if needed
if not exist "%PROJECT_DIR%\venv" (
    echo [*] Creating virtual environment...
    %PYTHON% -m venv "%PROJECT_DIR%\venv" >> "%LOG_FILE%" 2>&1
    if errorlevel 1 (
        echo [!] Failed to create the virtual environment. See %LOG_FILE%
        goto :fail
    )
)

REM Activate virtual environment
call "%PROJECT_DIR%\venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [!] Failed to activate the virtual environment.
    echo     Try deleting the "venv" folder and running this script again.
    goto :fail
)

REM Install dependencies
echo [*] Installing build dependencies (PyInstaller)...
python -m pip install --upgrade pip >> "%LOG_FILE%" 2>&1
python -m pip install -r "%PROJECT_DIR%\requirements.txt" >> "%LOG_FILE%" 2>&1
if errorlevel 1 (
    echo [!] pip install failed. Are you connected to the internet?
    echo     Details are in %LOG_FILE%
    goto :fail
)

REM Create binaries directory
if not exist "%BINARIES_DIR%" mkdir "%BINARIES_DIR%"

REM ============================================================
REM Npcap installer: bundled so the GUI can install it silently
REM on first launch (kernel driver can't be packed into a .exe).
REM
REM Licensing note: Npcap's free OEM redistribution allows up to
REM 5 installations per organization. For broader distribution,
REM purchase an OEM license at https://npcap.com/oem
REM ============================================================
if not exist "%INSTALLERS_DIR%" mkdir "%INSTALLERS_DIR%"

REM Does any npcap-*.exe already exist? If so, skip download.
if defined SKIP_NPCAP (
    echo [*] SKIP_NPCAP set: not bundling the Npcap installer.
    goto :npcap_done
)
dir /b "%INSTALLERS_DIR%\npcap-*.exe" >nul 2>&1
if errorlevel 1 (
    echo [*] No Npcap installer found in %INSTALLERS_DIR%
    echo [*] Attempting to download Npcap %NPCAP_VERSION% from npcap.com...
    powershell -NoProfile -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%INSTALLERS_DIR%\npcap-%NPCAP_VERSION%.exe' -UseBasicParsing } catch { Write-Host $_.Exception.Message; exit 1 } }" >> "%LOG_FILE%" 2>&1
    if errorlevel 1 (
        echo.
        echo [!] Auto-download failed. Manual fallback:
        echo     1. Visit https://npcap.com/#download
        echo     2. Download the installer ^(npcap-X.XX.exe^)
        echo     3. Place it in %INSTALLERS_DIR%
        echo     4. Re-run this build script
        echo.
        echo [!] Continuing the build without it - the GUI will tell users
        echo     to install Npcap manually from npcap.com on first launch.
        echo.
    ) else (
        echo [+] Downloaded npcap-%NPCAP_VERSION%.exe
    )
) else (
    echo [*] Found existing Npcap installer in %INSTALLERS_DIR%
)
:npcap_done

REM ============================================================
REM Check for nmap, and for the data files it loads at runtime.
REM
REM Bundling nmap.exe on its own produces a build that looks fine
REM and then fails on the first scan: nmap resolves its data files
REM from the directory holding the binary, and a missing one is a
REM hard error, not a skipped feature. Missing nselib\ is the
REM classic - every scan aborts with "failed to initialize the
REM script engine: module 'lpeg-utility' not found". So verify the
REM whole data directory here, at build time, not at scan time.
REM ============================================================
if not exist "%BINARIES_DIR%\nmap.exe" (
    echo [*] Nmap binary not found in %BINARIES_DIR%
    goto :nmap_help
)

echo [*] Checking bundled nmap data files...
set NMAP_INCOMPLETE=
for %%F in (nmap-os-db nmap-services nmap-service-probes nmap-protocols nmap-rpc nmap-mac-prefixes nse_main.lua) do (
    if not exist "%BINARIES_DIR%\%%F" (
        echo     MISSING: %%F
        set NMAP_INCOMPLETE=1
    )
)
for %%D in (nselib scripts) do (
    if not exist "%BINARIES_DIR%\%%D\" (
        echo     MISSING: %%D\ [directory]
        set NMAP_INCOMPLETE=1
    )
)

if defined NMAP_INCOMPLETE (
    echo.
    echo [!] The bundled nmap in %BINARIES_DIR% is INCOMPLETE.
    echo     Scans will abort or silently lose features with those absent.
    goto :nmap_help
)

echo [+] Bundled nmap looks complete.
goto :nmap_ok

:nmap_help
echo.
echo To bundle nmap for Windows:
echo.
echo 1. Download the portable zip from https://nmap.org/download.html
echo    Look for "nmap-X.XX-win32.zip" or "nmap-X.XX-setup.exe"
echo.
echo 2. Extract or install it, then copy the ENTIRE folder contents -
echo    every file AND every subfolder - into %BINARIES_DIR%
echo.
echo      xcopy /E /I /Y "C:\path\to\nmap-X.XX" "%BINARIES_DIR%"
echo.
echo    or, if you used the .exe installer:
echo.
echo      xcopy /E /I /Y "C:\Program Files (x86)\Nmap" "%BINARIES_DIR%"
echo.
echo    Do NOT copy just nmap.exe. It needs nselib\, scripts\,
echo    nse_main.lua, the nmap-* data files and all .dll files
echo    sitting right beside it.
echo.
echo 3. Re-run this build script
echo.

REM Check if nmap is installed system-wide
where nmap.exe >nul 2>&1
if not errorlevel 1 (
    echo [*] Found nmap in PATH. The app will fall back to system nmap.
) else (
    echo [!] No nmap found anywhere. The build will still finish, but the
    echo     app won't be able to scan until nmap is installed or bundled.
)
echo.

:nmap_ok

cd /d "%PROJECT_DIR%"

REM ============================================================
REM App icon: embedded in every exe, used for the shortcuts and
REM the installer, and loaded by the GUI for its window icon.
REM It is kept in the repo (regenerate with packaging\make_icon.py),
REM so a missing file means an incomplete checkout.
REM ============================================================
if not exist "%ICON_FILE%" (
    echo [!] App icon not found: %ICON_FILE%
    echo     It ships with the project. Restore packaging\icon\ and re-run.
    goto :fail
)

REM ============================================================
REM Build 1: CLI binary (console, no UAC manifest)
REM   - Run from an already-elevated cmd/PowerShell
REM   - No UAC prompt on --help / --version / piped invocations
REM ============================================================
echo [*] Building CLI executable (nmap-analyzer.exe)... this takes a few minutes.
python -m PyInstaller ^
    --name nmap-analyzer ^
    --onefile ^
    --console ^
    --noconfirm ^
    --clean ^
    --icon "%ICON_FILE%" ^
    --add-data "config;config" ^
    --add-data "binaries;binaries" ^
    --add-data "installers;installers" ^
    --add-data "packaging\icon;packaging\icon" ^
    --hidden-import gui ^
    --hidden-import local_analyzer ^
    --hidden-import selftest ^
    --paths src ^
    src\main.py >> "%LOG_FILE%" 2>&1

if errorlevel 1 (
    echo [!] CLI build failed. Details are in %LOG_FILE%
    goto :fail
)
echo [+] CLI build done.

REM ============================================================
REM Build 2: GUI binary (windowed, UAC auto-elevation)
REM   - Double-click to launch
REM   - Windows shows UAC prompt automatically on launch
REM   - No console window appears behind the GUI
REM ============================================================
echo [*] Building GUI executable (nmap-analyzer-gui.exe)... this takes a few minutes.
python -m PyInstaller ^
    --name nmap-analyzer-gui ^
    --onefile ^
    --windowed ^
    --uac-admin ^
    --noconfirm ^
    --clean ^
    --icon "%ICON_FILE%" ^
    --add-data "config;config" ^
    --add-data "binaries;binaries" ^
    --add-data "installers;installers" ^
    --add-data "packaging\icon;packaging\icon" ^
    --hidden-import local_analyzer ^
    --hidden-import selftest ^
    --paths src ^
    src\gui.py >> "%LOG_FILE%" 2>&1

if errorlevel 1 (
    echo [!] GUI build failed. Details are in %LOG_FILE%
    goto :fail
)
echo [+] GUI build done.

REM ============================================================
REM Self-test: run the executable we just built.
REM
REM This is the gate that matters. The file checks above only
REM catch problems someone thought to check for - the nselib\
REM omission that broke a shipped build was missing from every
REM list precisely because nobody knew to look for it. So stop
REM inspecting the bundle and use it: scan localhost through the
REM real pipeline. If that works, the build works.
REM
REM It runs the .exe, not the source, so it exercises the actual
REM PyInstaller bundle - the same unpacked _MEI temp directory a
REM user's scan would run from.
REM ============================================================
echo.
echo [*] Running build self-test (scans localhost, takes ~30s)...
echo.
"%BUILD_DIR%\nmap-analyzer.exe" --self-test
if errorlevel 1 (
    echo.
    echo [!] The build completed but the executable cannot scan.
    echo [!] Read the self-test output above - it names what is missing.
    echo [!] Do NOT ship this build.
    goto :fail
)

REM ============================================================
REM Build 3: the installed-app folder (dist\CybXNetworkScanner)
REM
REM Same code as the two exes above, built as a folder instead of
REM a single file: it starts instantly instead of unpacking nmap
REM to a temp directory on every launch. This folder is what the
REM installer puts in Program Files. See packaging\installed_app.spec.
REM ============================================================
echo.
echo [*] Building the installed-app folder (dist\CybXNetworkScanner)... a few more minutes.
python -m PyInstaller --noconfirm --clean "%PROJECT_DIR%\packaging\installed_app.spec" >> "%LOG_FILE%" 2>&1
if errorlevel 1 (
    echo [!] Installed-app build failed. Details are in %LOG_FILE%
    goto :fail
)
if not exist "%APP_DIR%\CybXNetworkScanner.exe" (
    echo [!] Installed-app build did not produce %APP_DIR%\CybXNetworkScanner.exe
    echo     Details are in %LOG_FILE%
    goto :fail
)
echo [+] Installed-app folder done.

REM The installer ships this folder, so it gets its own self-test:
REM passing the single-file exe says nothing about what is in here.
echo.
echo [*] Self-testing the installed-app folder...
echo.
"%APP_DIR%\nmap-analyzer.exe" --self-test
if errorlevel 1 (
    echo.
    echo [!] The installed-app folder cannot scan, so no installer was built.
    echo [!] Read the self-test output above - it names what is missing.
    goto :fail
)

REM ============================================================
REM Build 4: the installer (dist\CybXNetworkScanner-Setup-x.y.z.exe)
REM
REM Made with NSIS (free): https://nsis.sourceforge.io/Download
REM or, from a terminal:  winget install NSIS.NSIS
REM The script is packaging\windows\installer.nsi. It refuses to
REM build if nmap.exe is missing from the folder above.
REM ============================================================
set APP_VERSION=
for /f "delims=" %%V in ('python src\version.py') do set APP_VERSION=%%V
if not defined APP_VERSION (
    echo [!] Could not read the version from src\version.py
    goto :fail
)

set MAKENSIS=
where makensis.exe >nul 2>&1
if not errorlevel 1 set MAKENSIS=makensis.exe
if not defined MAKENSIS if exist "%ProgramFiles(x86)%\NSIS\makensis.exe" set MAKENSIS=%ProgramFiles(x86)%\NSIS\makensis.exe
if not defined MAKENSIS if exist "%ProgramFiles%\NSIS\makensis.exe" set MAKENSIS=%ProgramFiles%\NSIS\makensis.exe
if not defined MAKENSIS goto :no_nsis

set SETUP_EXE=%BUILD_DIR%\CybXNetworkScanner-Setup-%APP_VERSION%.exe
if exist "%SETUP_EXE%" del "%SETUP_EXE%"
echo.
echo [*] Building the installer (CybXNetworkScanner-Setup-%APP_VERSION%.exe)...
"!MAKENSIS!" /V2 /DVERSION=%APP_VERSION% "/DSRC=%APP_DIR%" "/DICON=%ICON_FILE%" "/DCONFIG=%PROJECT_DIR%\config\config.json" "/DOUTFILE=%SETUP_EXE%" "%PROJECT_DIR%\packaging\windows\installer.nsi" >> "%LOG_FILE%" 2>&1
if errorlevel 1 (
    echo [!] Installer build failed. Details are in %LOG_FILE%
    goto :fail
)
if not exist "%SETUP_EXE%" (
    echo [!] makensis reported success but %SETUP_EXE% is missing.
    echo     Details are in %LOG_FILE%
    goto :fail
)
echo [+] Installer done.

REM Checksums: the app's self-updater refuses a release without them, and
REM verifies the installer it downloads against this file. Upload it to the
REM GitHub release next to the installer (the release workflow does).
python -c "import hashlib,sys,os; [print(hashlib.sha256(open(f,'rb').read()).hexdigest()+'  '+os.path.basename(f)) for f in sys.argv[1:] if os.path.isfile(f)]" "%SETUP_EXE%" "%BUILD_DIR%\nmap-analyzer.exe" "%BUILD_DIR%\nmap-analyzer-gui.exe" > "%BUILD_DIR%\SHA256SUMS"
if errorlevel 1 (
    echo [!] Could not write %BUILD_DIR%\SHA256SUMS
    goto :fail
)
echo [+] Checksums written to %BUILD_DIR%\SHA256SUMS

echo.
echo ==========================================
echo   Build Complete - self-tests PASSED
echo ==========================================
echo.
echo INSTALLER (give this to users):
echo   %SETUP_EXE%
echo   %BUILD_DIR%\SHA256SUMS   (upload next to it on the GitHub release)
echo   Double-click to install. Adds Desktop + Start Menu icons and an
echo   uninstaller (Settings ^> Apps ^> Installed apps).
echo.
echo Portable, no install needed (run from a USB stick):
echo   GUI: %BUILD_DIR%\nmap-analyzer-gui.exe  (auto-elevates via UAC)
echo   CLI: %BUILD_DIR%\nmap-analyzer.exe      (run from an Administrator prompt)
echo.
echo To verify the portable GUI build too (triggers a UAC prompt, writes
echo %BUILD_DIR%\selftest_gui_log.txt):
echo   %BUILD_DIR%\nmap-analyzer-gui.exe --self-test
echo.
if not defined NO_PAUSE pause
endlocal
exit /b 0

:no_nsis
echo.
echo ==========================================
echo   INSTALLER NOT BUILT - NSIS is not installed
echo ==========================================
echo.
echo Everything else built and passed its self-test:
echo   %BUILD_DIR%\nmap-analyzer.exe, %BUILD_DIR%\nmap-analyzer-gui.exe
echo   %APP_DIR%\
echo.
echo To get the installer, install NSIS (free, one time):
echo   winget install NSIS.NSIS
echo or download it from https://nsis.sourceforge.io/Download
echo then run this script again.
echo.
if not defined NO_PAUSE pause
endlocal
exit /b 1

:fail
echo.
echo ==========================================
echo   BUILD FAILED - read the message above.
echo   Full log: %LOG_FILE%
echo ==========================================
echo.
if not defined NO_PAUSE pause
endlocal
exit /b 1
