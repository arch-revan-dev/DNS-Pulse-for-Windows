#ifndef Arch
  #define Arch "win-x64"
#endif

#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif

#define MyAppName "DNS Pulse"
#define MyAppPublisher "DNS Pulse Open Source Contributors"
#define MyAppURL "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows"
#define MyAppExeName "DnsPulse.exe"
#define MyServiceExeName "DnsPulse.Service.exe"
#define MyServiceName "DnsPulseService"

#if Arch == "win-arm64"
  #define InnoArchAllowed "arm64"
  #define InnoArch64Bit "arm64"
#else
  #define InnoArchAllowed "x64compatible"
  #define InnoArch64Bit "x64compatible"
#endif

[Setup]
AppId={{8D6B5F2E-7C41-4A19-9E5A-6E1F2A8D4C90}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppVerName={#MyAppName} {#AppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\DNS Pulse
DefaultGroupName=DNS Pulse
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\artifacts
OutputBaseFilename=DNS-Pulse-{#Arch}-setup
SetupIconFile=..\src\DnsPulse.App\Assets\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=yes
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed={#InnoArchAllowed}
ArchitecturesInstallIn64BitMode={#InnoArch64Bit}
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0.19041

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.EmergencyRestore=Emergency Network Restore
russian.EmergencyRestore=Экстренное восстановление сети
english.TaskAutostart=Launch DNS Pulse minimized on Windows startup
russian.TaskAutostart=Запускать DNS Pulse свёрнутым при входе в Windows
english.TaskInstallService=Install & start DnsPulse Windows Service (requires Administrator)
russian.TaskInstallService=Установить и запустить службу DnsPulse Windows Service (требуются права администратора)

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "installservice"; Description: "{cm:TaskInstallService}"; GroupDescription: "PulseCore Service:"; Flags: unchecked; Check: IsAdminInstallMode

[Files]
Source: "..\artifacts\{#Arch}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\artifacts\{#Arch}\{#MyServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\artifacts\{#Arch}\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Registry]
Root: HKCU; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "DnsPulse"; ValueData: """{app}\{#MyAppExeName}"" --autostart --minimized"; Flags: uninsdeletevalue; Tasks: autostart

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:EmergencyRestore}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--restore-network"; Comment: "Restore original Windows DNS, NRPT, SMHNR, and WinINet PAC settings"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Stop existing service cleanly during upgrade before re-registering
Filename: "sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden waituntilterminated; Check: IsAdminInstallMode and ServiceExists('{#MyServiceName}')
Filename: "sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden waituntilterminated; Check: IsAdminInstallMode and ServiceExists('{#MyServiceName}')
; Register and start DnsPulseService when requested by an elevated installer
Filename: "sc.exe"; Parameters: "create {#MyServiceName} binPath= ""\""{app}\{#MyServiceExeName}\"""" start= auto DisplayName= ""DNS Pulse Core Service"""; Flags: runhidden waituntilterminated; Tasks: installservice; Check: FileExists(ExpandConstant('{app}\{#MyServiceExeName}'))
Filename: "sc.exe"; Parameters: "description {#MyServiceName} ""PulseCore local encrypted DNS router, TLS-split sidecar, and Dead-Man's Switch recovery service."""; Flags: runhidden waituntilterminated; Tasks: installservice; Check: FileExists(ExpandConstant('{app}\{#MyServiceExeName}'))
Filename: "sc.exe"; Parameters: "failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/none/0"; Flags: runhidden waituntilterminated; Tasks: installservice; Check: FileExists(ExpandConstant('{app}\{#MyServiceExeName}'))
Filename: "sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden waituntilterminated; Tasks: installservice; Check: FileExists(ExpandConstant('{app}\{#MyServiceExeName}'))
; Launch UI after setup
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; CRITICAL: Restore original Windows DNS, NRPT, SMHNR, and PAC settings BEFORE deleting files
Filename: "sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopPulseService"; Check: IsAdminInstallMode
Filename: "{app}\{#MyAppExeName}"; Parameters: "--restore-network"; Flags: runhidden waituntilterminated; RunOnceId: "RestoreNetworkOnUninstall"
Filename: "sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeletePulseService"; Check: IsAdminInstallMode
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""DnsPulse_PulseCore_DNS_UDP"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanFwDnsUdp"; Check: IsAdminInstallMode
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""DnsPulse_PulseCore_DNS_TCP"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanFwDnsTcp"; Check: IsAdminInstallMode
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""DnsPulse_PulseCore_DoH_TCP"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanFwDohTcp"; Check: IsAdminInstallMode
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""DnsPulse_PulseCore_Sidecar_PAC_TCP"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanFwPacTcp"; Check: IsAdminInstallMode
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""DnsPulse_PulseCore_Sidecar_Proxy_TCP"""; Flags: runhidden waituntilterminated; RunOnceId: "CleanFwProxyTcp"; Check: IsAdminInstallMode

[Code]
function ServiceExists(const ServiceName: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query "' + ServiceName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;
