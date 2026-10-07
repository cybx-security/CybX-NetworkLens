; CybX Network Scanner Setup - the Windows setup wizard (NSIS 3).
;
; Installs the folder build made by packaging/installed_app.spec into Program
; Files, adds Start Menu and Desktop shortcuts, lists the app under
; Settings > Apps > Installed apps, and writes an uninstaller.
;
; Built by build\build_windows.bat:
;   makensis /DVERSION=1.1.0 /DSRC=<dist\CybXNetworkScanner> /DICON=<icon.ico>
;            /DCONFIG=<config\config.json> /DOUTFILE=<setup.exe> installer.nsi
; (use -D instead of /D with makensis on macOS/Linux). SRC is the folder
; holding CybXNetworkScanner.exe, nmap-analyzer.exe and _internal\.
;
; Silent use (RMM, scripts):  CybXNetworkScanner-Setup-x.y.z.exe /S [/NODESKTOP] [/RELAUNCH]
;   /RELAUNCH starts the app when the install finishes - how the app's own
;   "Check for Updates" applies a downloaded release (src/updater.py).
; Silent removal:             "%ProgramFiles%\CybX Network Scanner\Uninstall.exe" /S [/PURGE]
; Exit code 0 = success, 2 = failed.
;
; Where things go (must match src/paths.py):
;   program    %ProgramFiles%\CybX Network Scanner\
;   settings   %ProgramData%\CybX\Network Scanner\config.json   (kept on upgrade)
;   reports    Documents\CybX Network Scanner\output\            (never touched here)

Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"
!include "FileFunc.nsh"

!ifndef VERSION
  !error "VERSION is not defined (build with build\build_windows.bat)"
!endif
!ifndef SRC
  !error "SRC is not defined (the dist\CybXNetworkScanner folder)"
!endif
!ifndef ICON
  !error "ICON is not defined (packaging\icon\icon.ico)"
!endif
!ifndef CONFIG
  !error "CONFIG is not defined (config\config.json)"
!endif
!ifndef OUTFILE
  !error "OUTFILE is not defined"
!endif

; Fail the installer build, not the install, when the payload is incomplete.
!if /FileExists "${SRC}\CybXNetworkScanner.exe"
!else
  !error "CybXNetworkScanner.exe not found in SRC - build packaging\installed_app.spec first"
!endif
!if /FileExists "${SRC}\_internal\binaries\windows\nmap.exe"
!else
  !error "nmap.exe is not in SRC\_internal\binaries\windows - the build has no bundled nmap"
!endif

; The Npcap installer is bundled when the build machine had one in
; installers\windows\. Without it the component simply isn't offered and the
; app points the user at npcap.com on first launch.
!if /FileExists "${SRC}\_internal\installers\windows\npcap-*.exe"
  !define HAVE_NPCAP
!endif

!define APPNAME "CybX Network Scanner"
!define GUI_EXE "CybXNetworkScanner.exe"
!define CLI_EXE "nmap-analyzer.exe"
!define ARP "Software\Microsoft\Windows\CurrentVersion\Uninstall\CybXNetworkScanner"

Name "${APPNAME}"
OutFile "${OUTFILE}"
; Fixed location, no folder-picker page: the uninstaller removes exactly what
; Setup put here, which is only safe when "here" cannot be an arbitrary folder.
InstallDir "$PROGRAMFILES64\${APPNAME}"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show
BrandingText "${APPNAME} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "CompanyName" "CybX"
VIAddVersionKey "FileDescription" "${APPNAME} Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) CybX"

Var Purge
!ifdef HAVE_NPCAP
  Var NpcapPresent
!endif

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
; Stay on the progress page when done so the summary can be read.
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!define MUI_WELCOMEPAGE_TITLE "Welcome to ${APPNAME} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "${APPNAME} finds the devices on a network, lists their open ports and services, and flags the risky ones.$\r$\n$\r$\nSetup will:$\r$\n$\r$\n   -  install the scanner for everyone who uses this computer$\r$\n   -  add it to the Start Menu and the Desktop$\r$\n   -  offer to install the Npcap packet driver if it is missing$\r$\n$\r$\nScanning runs entirely on this computer. Only scan networks you are authorized to scan.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

!define MUI_COMPONENTSPAGE_SMALLDESC
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "${APPNAME} is installed"
!define MUI_FINISHPAGE_TEXT "To use it, double-click ${APPNAME} on the Desktop or in the Start Menu. Windows asks for permission each time it starts - scanning needs administrator rights.$\r$\n$\r$\nScan reports are saved in your Documents folder, under ${APPNAME}.$\r$\n$\r$\nTo remove it later, go to Settings > Apps > Installed apps."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APPNAME} now"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; The app needs elevation anyway and Setup is already elevated, so it is
; started directly rather than handed to Explorer (which would only raise a
; second UAC prompt).
Function LaunchApp
  SetOutPath "$INSTDIR"
  Exec '"$INSTDIR\${GUI_EXE}"'
FunctionEnd

; StopApp closes a running scanner - and, with /T, the nmap it started - so
; its files are not locked while they are replaced or removed.
!macro StopApp
  nsExec::Exec 'taskkill /F /T /IM ${GUI_EXE}'
  Pop $0
  nsExec::Exec 'taskkill /F /T /IM ${CLI_EXE}'
  Pop $0
  Sleep 500
!macroend

; WaitForUnlock gives a copy of the app that is shutting down on its own (the
; self-updater exits right after starting Setup) a moment to let go of its
; files, instead of tearing it down mid-exit. A running exe cannot be opened
; for writing, so that is the test; up to 15 seconds, then StopApp handles
; whatever is left.
!macro WaitForUnlock
  ${If} ${FileExists} "$INSTDIR\${GUI_EXE}"
    StrCpy $R9 0
    ${Do}
      ClearErrors
      FileOpen $R8 "$INSTDIR\${GUI_EXE}" a
      ${IfNot} ${Errors}
        FileClose $R8
        ${Break}
      ${EndIf}
      IntOp $R9 $R9 + 1
      ${If} $R9 > 30
        ${Break}
      ${EndIf}
      Sleep 500
    ${Loop}
  ${EndIf}
!macroend

Section "${APPNAME}" SecMain
  SectionIn RO
  SetShellVarContext all
  !insertmacro WaitForUnlock
  !insertmacro StopApp

  ; Clear out the previous version's runtime first: files a newer build no
  ; longer ships (old nmap scripts, old Python modules) must not linger.
  RMDir /r "$INSTDIR\_internal"

  SetOverwrite try
  ClearErrors
  SetOutPath "$INSTDIR"
  File "${SRC}\${GUI_EXE}"
  File "${SRC}\${CLI_EXE}"
  SetOutPath "$INSTDIR\_internal"
  File /r "${SRC}\_internal\*.*"
  ${If} ${Errors}
    MessageBox MB_ICONSTOP|MB_OK "Setup could not replace the ${APPNAME} program files - they are in use.$\r$\n$\r$\nClose ${APPNAME} (and wait for any running scan to stop), then run Setup again." /SD IDOK
    SetErrorLevel 2
    Abort "The ${APPNAME} program files are in use."
  ${EndIf}

  ; Default settings, machine-wide. Never overwritten: an upgrade must keep
  ; the Insights feed path and scan defaults already configured here.
  SetOutPath "$APPDATA\CybX\Network Scanner"
  SetOverwrite off
  File "/oname=config.json" "${CONFIG}"
  SetOverwrite try
  DetailPrint "Settings: $APPDATA\CybX\Network Scanner\config.json"

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\${GUI_EXE}" "" "$INSTDIR\${GUI_EXE}" 0 SW_SHOWNORMAL "" "Scan a network for devices, open ports and risky services"
  DetailPrint "Start Menu shortcut: ${APPNAME}"

  WriteRegStr HKLM "${ARP}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${ARP}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${ARP}" "Publisher" "CybX"
  WriteRegStr HKLM "${ARP}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${ARP}" "DisplayIcon" "$INSTDIR\${GUI_EXE}"
  WriteRegStr HKLM "${ARP}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${ARP}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${ARP}" "NoModify" 1
  WriteRegDWORD HKLM "${ARP}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${ARP}" "EstimatedSize" "$0"
  DetailPrint "Listed under Settings > Apps > Installed apps"
SectionEnd

Section "Desktop shortcut" SecDesktop
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${GUI_EXE}" "" "$INSTDIR\${GUI_EXE}" 0 SW_SHOWNORMAL "" "Scan a network for devices, open ports and risky services"
  DetailPrint "Desktop shortcut: ${APPNAME}"
SectionEnd

!ifdef HAVE_NPCAP
Section "Npcap packet driver (needed for full scans)" SecNpcap
  ; Npcap's free installer has no silent mode, so a silent Setup leaves it
  ; alone; the app offers it again on first launch.
  ${If} ${Silent}
    DetailPrint "Npcap: skipped (silent install). The scanner offers it on first launch."
    Return
  ${EndIf}
  FindFirst $0 $1 "$INSTDIR\_internal\installers\windows\npcap-*.exe"
  FindClose $0
  ${If} $1 == ""
    DetailPrint "Npcap: no bundled installer found - get it from https://npcap.com"
    Return
  ${EndIf}
  DetailPrint "Opening Npcap setup ($1) - click through its window to continue..."
  ClearErrors
  ExecWait '"$INSTDIR\_internal\installers\windows\$1" /winpcap_mode=yes' $0
  ${If} ${Errors}
    DetailPrint "Npcap setup could not be started. The scanner offers it again on first launch."
  ${Else}
    DetailPrint "Npcap setup finished (code $0)."
  ${EndIf}
SectionEnd
!endif

; /RELAUNCH: reopen the app once the install has finished. The self-updater
; passes it with /S, so the user sees the scanner close and come back on
; the new version. The app elevates itself, so starting it from here (also
; elevated) raises no extra prompt.
Function .onInstSuccess
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/RELAUNCH" $1
  ${IfNot} ${Errors}
    SetOutPath "$INSTDIR"
    Exec '"$INSTDIR\${GUI_EXE}"'
  ${EndIf}
FunctionEnd

; After the sections: it refers to their ids, which exist only once the
; sections have been declared.
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "${APPNAME} needs a 64-bit version of Windows." /SD IDOK
    SetErrorLevel 2
    Quit
  ${EndIf}
  SetRegView 64

  ; /NODESKTOP on the command line skips the Desktop shortcut (silent installs).
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/NODESKTOP" $1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecDesktop}
  ${EndIf}

!ifdef HAVE_NPCAP
  ; Already installed (by this app, Wireshark, nmap...): don't offer it again.
  ; Setup is a 32-bit program, so look at the real System32, not the
  ; redirected one.
  StrCpy $NpcapPresent "0"
  ${DisableX64FSRedirection}
  ${If} ${FileExists} "$WINDIR\System32\Npcap\wpcap.dll"
  ${OrIf} ${FileExists} "$WINDIR\System32\wpcap.dll"
  ${OrIf} ${FileExists} "$WINDIR\SysWOW64\wpcap.dll"
    StrCpy $NpcapPresent "1"
  ${EndIf}
  ${EnableX64FSRedirection}
  ${If} $NpcapPresent == "1"
    !insertmacro UnselectSection ${SecNpcap}
    SectionSetText ${SecNpcap} ""
  ${EndIf}
!endif
FunctionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "The scanner, its Start Menu entry, and its uninstaller."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Puts a ${APPNAME} icon on the Desktop for everyone who uses this computer."
!ifdef HAVE_NPCAP
  !insertmacro MUI_DESCRIPTION_TEXT ${SecNpcap} "Opens the Npcap setup window. Without Npcap, scans are slower and cannot detect operating systems or UDP services."
!endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function un.onInit
  SetRegView 64
  StrCpy $Purge ""
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/PURGE" $1
  ${IfNot} ${Errors}
    StrCpy $Purge "1"
  ${EndIf}
  ; Interactive removal asks; silent removal keeps the settings unless /PURGE.
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete the scanner's settings file?$\r$\n$\r$\nChoose No to keep it for a future reinstall.$\r$\n$\r$\nEither way, your saved scan reports (Documents > ${APPNAME}) are not removed." /SD IDNO IDNO keepSettings
    StrCpy $Purge "1"
  keepSettings:
FunctionEnd

Section "Uninstall"
  SetShellVarContext all
  !insertmacro StopApp

  ; Only what Setup put here is deleted, and the folder only if that leaves
  ; it empty.
  Delete "$INSTDIR\${GUI_EXE}"
  Delete "$INSTDIR\${CLI_EXE}"
  Delete "$INSTDIR\selftest_gui_log.txt"
  RMDir /r "$INSTDIR\_internal"
  Delete "$INSTDIR\Uninstall.exe"
  ; On Windows 11, Uninstall.exe stays locked for as long as this temporary
  ; copy of it is running, which would leave one stray file in an otherwise
  ; empty folder. A locked program file can still be renamed, so move it out
  ; to the temp folder and let Windows delete it there at the next restart.
  ${If} ${FileExists} "$INSTDIR\Uninstall.exe"
    GetTempFileName $2
    Delete $2
    Rename "$INSTDIR\Uninstall.exe" $2
    Delete /REBOOTOK $2
  ${EndIf}
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  Delete "$DESKTOP\${APPNAME}.lnk"
  DeleteRegKey HKLM "${ARP}"

  ${If} $Purge == "1"
    Delete "$APPDATA\CybX\Network Scanner\config.json"
    RMDir "$APPDATA\CybX\Network Scanner"
    ; Removed only if empty - the Insights collector feed may live beside it.
    RMDir "$APPDATA\CybX"
    DetailPrint "Settings removed."
  ${Else}
    DetailPrint "Settings kept: $APPDATA\CybX\Network Scanner\config.json"
  ${EndIf}

  DetailPrint "Scan reports in Documents > ${APPNAME} were left in place."
  DetailPrint "Npcap was left installed - other tools may use it. Remove it from Settings > Apps if it is no longer needed."
SectionEnd
