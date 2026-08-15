#ifndef AppVersion
  #error AppVersion must be supplied by the Phase 12 build script.
#endif
#ifndef SourceRoot
  #error SourceRoot must be supplied by the Phase 12 build script.
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the Phase 12 build script.
#endif

#define ProductName "QuietShield Windows"
#define ProductPublisher "QuietShield"
#define ProductAppId "{6D13D40D-0A66-49F7-A422-235A2B89DA61}"

[Setup]
AppId={{#ProductAppId}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher={#ProductPublisher}
DefaultDirName={autopf}\QuietShield
DisableDirPage=yes
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.22000
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
OutputDir={#OutputDir}
OutputBaseFilename=QuietShield-Windows-x64-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
AllowNoIcons=yes
UninstallDisplayIcon={app}\App\{#AppVersion}\QuietShield.App.exe
Uninstallable=yes
ChangesAssociations=no
ChangesEnvironment=no
AlwaysRestart=no
RestartIfNeededByRun=no
#ifdef QuietShieldSignTool
SignTool={#QuietShieldSignTool}
SignedUninstaller=yes
#else
SignedUninstaller=no
#endif

[Dirs]
Name: "{commonappdata}\QuietShield\Service"; Permissions: system-full admins-full

[Files]
; R4.2.22 pre-copy service quiesce bootstrap
Source: "{#SourceRoot}\installer\Prepare-QuietShieldProductionUpgrade.ps1"; Flags: dontcopy noencryption
Source: "{#SourceRoot}\installer\QuietShield.Installer.Common.ps1"; Flags: dontcopy noencryption
Source: "{#SourceRoot}\installer\QuietShield.Script.Common.ps1"; Flags: dontcopy noencryption
Source: "{#SourceRoot}\installer\ServiceActivation.Script.Common.ps1"; Flags: dontcopy noencryption

Source: "{#SourceRoot}\app\*"; DestDir: "{app}\App\{#AppVersion}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb,*.dbg,*.xml"
Source: "{#SourceRoot}\service\*"; DestDir: "{app}\Service\{#AppVersion}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb,*.dbg,appsettings.Development.json"
Source: "{#SourceRoot}\installer\*"; DestDir: "{app}\Installer"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\QuietShield Windows"; Filename: "{app}\App\{#AppVersion}\QuietShield.App.exe"; WorkingDir: "{app}\App\{#AppVersion}"

[Code]
function InstallerPowerShellPath(): String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

function QuoteArgument(Value: String): String;
begin
  Result := '"' + Value + '"';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Parameters: String;
  ResultCode: Integer;
begin
  Result := '';
  NeedsRestart := False;
  ExtractTemporaryFile('Prepare-QuietShieldProductionUpgrade.ps1');
  ExtractTemporaryFile('QuietShield.Installer.Common.ps1');
  ExtractTemporaryFile('QuietShield.Script.Common.ps1');
  ExtractTemporaryFile('ServiceActivation.Script.Common.ps1');
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    QuoteArgument(ExpandConstant('{tmp}\Prepare-QuietShieldProductionUpgrade.ps1')) +
    ' -ApprovedInstallerServiceQuiesce -Version ' + QuoteArgument('{#AppVersion}') +
    ' -ProductRoot ' + QuoteArgument(ExpandConstant('{app}')) +
    ' -StateRoot ' + QuoteArgument(ExpandConstant('{commonappdata}\QuietShield\Service'));
  if not Exec(InstallerPowerShellPath(), Parameters, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) then begin
    Result := 'QuietShield could not start its owned-service pre-copy quiesce helper.';
    exit;
  end;
  if ResultCode <> 0 then
    Result := Format('QuietShield could not safely stop the existing owned service before file replacement (exit code %d).', [ResultCode]);
end;
procedure RunProductionServiceInstall();
var
  Parameters: String;
  ResultCode: Integer;
begin
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    QuoteArgument(ExpandConstant('{app}\Installer\Install-QuietShieldProductionService.ps1')) +
    ' -ApprovedInstallerServiceRegistration -Version ' + QuoteArgument('{#AppVersion}') +
    ' -ProductRoot ' + QuoteArgument(ExpandConstant('{app}')) +
    ' -StateRoot ' + QuoteArgument(ExpandConstant('{commonappdata}\QuietShield\Service'));
  if not Exec(InstallerPowerShellPath(), Parameters, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) then
    RaiseException('The exact QuietShield production service registration could not be started.');
  if ResultCode <> 0 then
    RaiseException(Format('The exact QuietShield production service registration failed with exit code %d.', [ResultCode]));
end;

procedure RunProductionServiceUninstall();
var
  Parameters: String;
  ResultCode: Integer;
begin
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    QuoteArgument(ExpandConstant('{app}\Installer\Uninstall-QuietShieldProductionService.ps1')) +
    ' -ApprovedInstallerServiceUninstall -Version ' + QuoteArgument('{#AppVersion}') +
    ' -ProductRoot ' + QuoteArgument(ExpandConstant('{app}')) +
    ' -StateRoot ' + QuoteArgument(ExpandConstant('{commonappdata}\QuietShield\Service'));
  if not Exec(InstallerPowerShellPath(), Parameters, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) then
    RaiseException('The exact QuietShield production service uninstall could not be started.');
  if ResultCode <> 0 then
    RaiseException(Format('The exact QuietShield production service uninstall failed with exit code %d.', [ResultCode]));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RunProductionServiceInstall();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RunProductionServiceUninstall();
end;
