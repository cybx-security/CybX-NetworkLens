# Windows nmap bundle — COMPLETE file checklist

Files come from TWO places. Missing either one produces a build that works on
your machine and fails on everyone else's. Both are verified at build time by
the self-test, so a build that prints SELF-TEST PASSED has everything below.

--------------------------------------------------------------------------
SOURCE 1: The nmap install itself (copy EVERYTHING)
--------------------------------------------------------------------------

Download portable nmap from https://nmap.org/download.html and copy the ENTIRE
contents of the extracted folder into this directory — every file and every
subfolder:

    xcopy /E /I /Y "C:\path\to\extracted\nmap-7.94" "binaries\windows"

Or, if you used the .exe installer instead of the zip:

    xcopy /E /I /Y "C:\Program Files (x86)\Nmap" "binaries\windows"

COPY EVERYTHING. Cherry-picking files will break the scan.

Nmap loads its data files out of whatever directory holds nmap.exe, and a
missing file is a hard failure rather than a skipped feature. The load-bearing
ones (all verified at launch and by the self-test):

    nmap.exe
    nse_main.lua
    nselib\            <- the one people leave behind; without it every scan
    scripts\              dies at startup with "failed to initialize the
                          script engine: module 'lpeg-utility' not found"
    nmap-services
    nmap-service-probes
    nmap-os-db
    *.dll              <- every DLL that ships in the nmap folder
                          (libssh2, zlib, OpenSSL, ... names vary by version)

--------------------------------------------------------------------------
SOURCE 2: The Visual C++ runtime (NOT in the nmap folder!)
--------------------------------------------------------------------------

nmap.exe also needs Microsoft's Visual C++ runtime DLLs. These are NOT part of
the nmap download — Windows normally finds them in System32, where Visual
Studio or some installer put them. Your build machine has them; a clean target
machine does not, and there nmap.exe dies before it starts with:

    The code execution cannot proceed because MSVCP140.dll was not found.

THIS FAILURE IS INVISIBLE ON THE BUILD MACHINE. Scans work, the test scan
works — because your machine has the runtime installed system-wide. Only the
self-test's file check catches it. Windows searches the exe's own directory
before System32, so copies placed here make the bundle portable.

Copy these two files into this directory, next to nmap.exe:

    msvcp140.dll
    vcruntime140.dll

Official nmap Windows builds are 32-bit, so take the 32-bit DLLs — which, on
64-bit Windows, live in SysWOW64 (yes, the naming is backwards):

    copy /Y "C:\Windows\SysWOW64\msvcp140.dll"     "binaries\windows"
    copy /Y "C:\Windows\SysWOW64\vcruntime140.dll" "binaries\windows"

(Only if your nmap.exe is a 64-bit build — i.e. it installed under
"C:\Program Files\Nmap" WITHOUT the "(x86)" — take the DLLs from
C:\Windows\System32 instead, and also copy vcruntime140_1.dll.)

If a target machine still reports some other *140.dll missing, copy that DLL
from the same SysWOW64 folder here too and rebuild.

--------------------------------------------------------------------------
NOT COPIED BY HAND, BUT ALSO REQUIRED BY THE BUILD
--------------------------------------------------------------------------

These are not files you put in this folder; they are listed so this stays the
one complete list of what a Windows build needs. The build script checks each.

    packaging\icon\icon.ico   The app icon. Ships with the project. Bundled into
                              every exe and loaded for the window icon; the
                              build stops if it is missing, and the self-test
                              fails if it did not make it into the exe.

    NSIS (makensis.exe)       Builds the installer. Install once on the build
                              machine:  winget install NSIS.NSIS
                              Without it the build ends with
                              "INSTALLER NOT BUILT" (the portable exes are
                              still produced).

    installers\windows\npcap-*.exe
                              Downloaded automatically by the build script.
                              Optional: without it, users are pointed to
                              npcap.com instead of being offered the install.

--------------------------------------------------------------------------

The scanner verifies all of the above at launch and prints a warning listing
anything missing, and the build self-test FAILS if the runtime DLLs are not
here. Run the built .exe once and read its first few lines before you ship.
