; Inno Setup script: builds Output\OneEye-Setup-0.3.0.exe from dist\OneEye (run build_exe.bat first).
;   winget install JRSoftware.InnoSetup
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer.iss
; Installs to Program Files: only admins can modify it, so other programs can't tamper with One Eye.

[Setup]
AppName=One Eye
AppVersion=0.3.0
AppPublisher=One Eye authors
DefaultDirName={autopf}\OneEye
DefaultGroupName=One Eye
OutputBaseFilename=OneEye-Setup-0.3.0
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\OneEye.exe
LicenseFile=LICENSE
SetupIconFile=assets/icon.ico

[Files]
Source: "dist\OneEye\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\One Eye"; Filename: "{app}\OneEye.exe"
Name: "{group}\Uninstall One Eye"; Filename: "{uninstallexe}"
Name: "{autodesktop}\One Eye"; Filename: "{app}\OneEye.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\OneEye.exe"; Description: "Start One Eye"; Flags: nowait postinstall skipifsilent
