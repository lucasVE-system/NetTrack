; NetTrack Installer Script

!include "MUI2.nsh"
!include "x64.nsh"

; Basic Settings
Name "NetTrack"
OutFile "NetTrack-Setup.exe"
InstallDir "$PROGRAMFILES\NetTrack"
RequestExecutionLevel admin

; UI Settings
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Installation Section
Section "Install NetTrack"
  SetOutPath "$INSTDIR"
  
  ; Download latest NetTrack.exe from GitHub Releases
  DetailPrint "Downloading NetTrack from GitHub..."
  NSClientDL::HTTP GET "https://github.com/lucasVE-system/NetTrack/releases/download/latest/NetTrack.exe" "$INSTDIR\NetTrack.exe"
  Pop $0
  
  ${If} $0 == "success"
    DetailPrint "Download successful!"
  ${Else}
    DetailPrint "Download failed: $0"
    MessageBox MB_OK "Failed to download NetTrack. Please check your internet connection."
    Abort
  ${EndIf}
  
  ; Create Start Menu Shortcut
  CreateDirectory "$SMPROGRAMS\NetTrack"
  CreateShortCut "$SMPROGRAMS\NetTrack\NetTrack.lnk" "$INSTDIR\NetTrack.exe"
  
  ; Create Desktop Shortcut
  CreateShortCut "$DESKTOP\NetTrack.lnk" "$INSTDIR\NetTrack.exe"
  
  ; Create Uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortCut "$SMPROGRAMS\NetTrack\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

SectionEnd

; Uninstall Section
Section "Uninstall"
  Delete "$INSTDIR\NetTrack.exe"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$DESKTOP\NetTrack.lnk"
  Delete "$SMPROGRAMS\NetTrack\NetTrack.lnk"
  Delete "$SMPROGRAMS\NetTrack\Uninstall.lnk"
  RMDir "$SMPROGRAMS\NetTrack"
  RMDir "$INSTDIR"
SectionEnd
