; LAN Call Windows 安装包（NSIS）
; 构建：NSISDIR=<nsis-dir> <makensis> installer.nsi
; 说明：electron-builder 在 Linux 下构建 NSIS 需要 wine（抽取卸载程序步骤），
;       本环境无 wine，故用原生 makensis + 本脚本产出同样的安装包。

!include "MUI2.nsh"

Name "LAN Call"
OutFile "dist/LAN-Call-Setup-0.2.3-win-x64.exe"
InstallDir "$LOCALAPPDATA\LAN Call"
InstallDirRegKey HKCU "Software\LAN Call" "InstallDir"
RequestExecutionLevel user

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Section "LAN Call" SecMain
  SetOutPath "$INSTDIR"
  File /r "dist\win-unpacked\*.*"

  WriteRegStr HKCU "Software\LAN Call" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\LAN Call"
  CreateShortcut "$SMPROGRAMS\LAN Call\LAN Call.lnk" "$INSTDIR\LAN Call.exe"
  CreateShortcut "$SMPROGRAMS\LAN Call\卸载 LAN Call.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\LAN Call.lnk" "$INSTDIR\LAN Call.exe"

  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call" \
    "DisplayName" "LAN Call"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call" \
    "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call" \
    "DisplayVersion" "0.2.0"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call" \
    "Publisher" "HAICE"
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call" \
    "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call" \
    "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$INSTDIR"

  Delete "$SMPROGRAMS\LAN Call\LAN Call.lnk"
  Delete "$SMPROGRAMS\LAN Call\卸载 LAN Call.lnk"
  RMDir "$SMPROGRAMS\LAN Call"
  Delete "$DESKTOP\LAN Call.lnk"

  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAN Call"
  DeleteRegKey HKCU "Software\LAN Call"
SectionEnd
