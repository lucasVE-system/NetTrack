; NetTrack NSIS Installer
; Compile: makensis installer.nsi
; Requires dist\NetTrack.exe to exist (run build.py first)
;
; Uses standard NSIS MUI2 — no third-party plugins needed.

!include "MUI2.nsh"
!include "x64.nsh"

;--------------------------------
; Definitions

!define APP_NAME        "NetTrack"
!define APP_VERSION     "1.3.0"
!define APP_PUBLISHER   "lucasVE-system"
!define APP_URL         "https://github.com/lucasVE-system/NetTrack"
!define APP_EXE         "NetTrack.exe"
!define APP_UNINSTALLER "Uninstall.exe"
!define REG_UNINSTALL   "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

;--------------------------------
; General

Name "${APP_NAME} ${APP_VERSION}"
OutFile "dist-installer\NetTrack-Setup-${APP_VERSION}-nsis.exe"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "${REG_UNINSTALL}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; Verify the exe exists at compile time
!if !FileExists("dist\${APP_EXE}")
  !error "dist\NetTrack.exe not found. Run build.py first."
!endif

;--------------------------------
; MUI Pages

!define MUI_ABORTWARNING

; Welcome page
!define MUI_WELCOMEPAGE_TITLE      "Welcome to ${APP_NAME} ${APP_VERSION} Setup"
!define MUI_WELCOMEPAGE_TEXT       "This wizard will install ${APP_NAME} on your computer.$\r$\n$\r$\nNetTrack runs a local web dashboard at http://127.0.0.1:5000 — it is not reachable from other devices on your network.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "LICENSE"

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Components page
!insertmacro MUI_PAGE_COMPONENTS

; Install files page
!insertmacro MUI_PAGE_INSTFILES

; Finish page — offer to launch
!define MUI_FINISHPAGE_RUN          "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT     "Launch ${APP_NAME} now"
!define MUI_FINISHPAGE_LINK         "Visit the NetTrack GitHub page"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_URL}"
!insertmacro MUI_PAGE_FINISH

; Uninstall pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Components

Section "NetTrack (required)" SecMain
  SectionIn RO   ; cannot be deselected
  SetOutPath "$INSTDIR"

  ; Install the main executable (embedded at compile time)
  File "dist\${APP_EXE}"
  File "LICENSE"
  File "install-welcome.txt"

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\${APP_UNINSTALLER}"

  ; Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortCut  "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"   "$INSTDIR\${APP_EXE}"
  CreateShortCut  "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"     "$INSTDIR\${APP_UNINSTALLER}"

  ; Add/Remove Programs registration
  WriteRegStr   HKLM "${REG_UNINSTALL}" "DisplayName"          "${APP_NAME}"
  WriteRegStr   HKLM "${REG_UNINSTALL}" "DisplayVersion"       "${APP_VERSION}"
  WriteRegStr   HKLM "${REG_UNINSTALL}" "Publisher"            "${APP_PUBLISHER}"
  WriteRegStr   HKLM "${REG_UNINSTALL}" "URLInfoAbout"         "${APP_URL}"
  WriteRegStr   HKLM "${REG_UNINSTALL}" "InstallLocation"      "$INSTDIR"
  WriteRegStr   HKLM "${REG_UNINSTALL}" "UninstallString"      "$INSTDIR\${APP_UNINSTALLER}"
  WriteRegStr   HKLM "${REG_UNINSTALL}" "QuietUninstallString" "$INSTDIR\${APP_UNINSTALLER} /S"
  WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoModify"             1
  WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoRepair"             1

SectionEnd

Section "Desktop Shortcut" SecDesktop
  CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
SectionEnd

;--------------------------------
; Component descriptions

LangString DESC_SecMain    ${LANG_ENGLISH} "NetTrack application (required)."
LangString DESC_SecDesktop ${LANG_ENGLISH} "Add a shortcut to your Desktop."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain}    $(DESC_SecMain)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} $(DESC_SecDesktop)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
; Uninstall Section

Section "Uninstall"
  ; Remove application files
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\${APP_UNINSTALLER}"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\install-welcome.txt"

  ; Optionally remove user data — commented out to preserve scan history
  ; Delete "$INSTDIR\devices.json"
  ; Delete "$INSTDIR\topology.json"
  ; Delete "$INSTDIR\snmp_config.json"

  RMDir  "$INSTDIR"

  ; Remove shortcuts
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
  RMDir  "$SMPROGRAMS\${APP_NAME}"
  Delete "$DESKTOP\${APP_NAME}.lnk"

  ; Remove registry entries
  DeleteRegKey HKLM "${REG_UNINSTALL}"

SectionEnd
