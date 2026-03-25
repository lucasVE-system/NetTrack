; NetTrack Inno Setup 6 installer
; Build: ISCC.exe NetTrack.iss
; Requires dist\NetTrack.exe to exist (run build.py first)
; Optional: place NetTrack.ico in the same folder for a branded setup icon

#define MyAppName      "NetTrack"
#define MyAppVersion   "1.3.0"
#define MyAppPublisher "lucasVE-system"
#define MyAppURL       "https://github.com/lucasVE-system/NetTrack"
#define MyAppExeName   "NetTrack.exe"
#define MyAppExePath   "dist\NetTrack.exe"

[Setup]
AppId={{A7F3C2D1-4E8B-4F9A-B2C3-D4E5F6A7B8C9}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases

; Install to 64-bit Program Files
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes

; Installer output
OutputDir=dist-installer
OutputBaseFilename=NetTrack-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64

; Require the exe to exist at build time
#if !FileExists(MyAppExePath)
  #error "dist\NetTrack.exe not found. Run build.py first."
#endif

; Branding — uncomment if NetTrack.ico is present
; SetupIconFile=NetTrack.ico
; WizardImageFile=wizard_image.bmp   ; 164x314 px
; WizardSmallImageFile=wizard_small.bmp ; 55x55 px

; Privileges and UI
PrivilegesRequired=admin
ShowLanguageDialog=no
WizardStyle=modern

; Version metadata on the setup exe
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

; Logging (written to %TEMP%\NetTrack_Setup_Log.txt)
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "Create a &desktop shortcut";    GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "startupicon";   Description: "Launch NetTrack at &Windows startup"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; Main executable — built by build.py / PyInstaller
Source: "{#MyAppExePath}"; DestDir: "{app}"; Flags: ignoreversion

; License and welcome text shipped alongside the app
Source: "LICENSE";              DestDir: "{app}"; Flags: ignoreversion
Source: "install-welcome.txt";  DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}";             Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}";   Filename: "{uninstallexe}"

; Desktop shortcut (optional task)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; Startup (optional task)
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
; Offer to launch after install
Filename: "{app}\{#MyAppExeName}"; \
  Description: "Launch {#MyAppName} now"; \
  Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up data files created at runtime (optional — comment out to preserve user data)
; Type: files; Name: "{app}\devices.json"
; Type: files; Name: "{app}\topology.json"
; Type: files; Name: "{app}\snmp_config.json"

[Registry]
; Add/Remove Programs metadata
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; \
  ValueType: string; ValueName: "DisplayName";    ValueData: "{#MyAppName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; \
  ValueType: string; ValueName: "DisplayVersion"; ValueData: "{#MyAppVersion}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; \
  ValueType: string; ValueName: "Publisher";      ValueData: "{#MyAppPublisher}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; \
  ValueType: string; ValueName: "URLInfoAbout";   ValueData: "{#MyAppURL}"

[Messages]
; Custom welcome message
WelcomeLabel2=This will install [name/ver] on your computer.%n%nNetTrack runs a local web dashboard at http://127.0.0.1:5000 — it is not accessible from other devices on your network.%n%nIt is recommended to run NetTrack as Administrator for full discovery features (SNMP, LLDP, passive capture).%n%nClick Next to continue.

FinishedLabel=Setup has finished installing [name] on your computer.%n%nOpen NetTrack from the Start Menu or the desktop shortcut. Your scan data and settings are stored in the installation folder.%n%nFor advanced discovery (SNMP, mDNS, LLDP), run as Administrator when prompted.
