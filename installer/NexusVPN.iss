; NexusVPN Pro installer (Inno Setup 6).
; ISCC /DAppVersion=2.1.0.17 /DSourceDir="dist\NexusVPN Pro" installer\NexusVPN.iss

#ifndef AppVersion
  #define AppVersion "2.1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\NexusVPN Pro"
#endif
#define AppName "NexusVPN Pro"
#define AppExe "NexusVPN Pro.exe"

[Setup]
AppId={{6F1C2E7A-5B4D-4C8E-9A3F-0E7D2B1C4A55}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=NexusVPN
AppComments=Профессиональный VPN-клиент для Windows с интеллектуальной самообучающейся маршрутизацией
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} — установка
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\installer_out
OutputBaseFilename=NexusVPN-Pro-Setup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать значок на рабочем столе"; GroupDescription: "Значки:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; files of the previous version that a new build no longer ships
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; also runs after a silent in-app update (no skipifsilent) so the program comes back by itself
Filename: "{app}\{#AppExe}"; Description: "Запустить {#AppName}"; Flags: nowait postinstall

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  KeepData: Boolean;

function HasParam(const Name: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Name) = 0 then
      Result := True;
end;

procedure StopProgram(const Args: String);
var
  Code: Integer;
  Exe: String;
begin
  Exe := ExpandConstant('{app}\{#AppExe}');
  if FileExists(Exe) then
    Exec(Exe, Args, '', SW_HIDE, ewWaitUntilTerminated, Code);
  { fallback if the graceful stop did not finish }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM "{#AppExe}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopProgram('--stop');
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  KeepData := HasParam('/KEEPDATA');
  if not UninstallSilent and not KeepData then
    KeepData := MsgBox('Сохранить настройки, подписки и изученные правила?' + #13#10 +
      'Они пригодятся, если вы установите NexusVPN Pro снова.' + #13#10#13#10 +
      'Нет — удалить программу полностью.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    { proxy, autostart task, firewall rules, IKEv2 connections, running cores }
    if KeepData then
      StopProgram('--cleanup')
    else
      StopProgram('--cleanup --purge');
  end;
  if (CurUninstallStep = usPostUninstall) and not KeepData then
    DelTree(ExpandConstant('{localappdata}\{#AppName}'), True, True, True);
end;
