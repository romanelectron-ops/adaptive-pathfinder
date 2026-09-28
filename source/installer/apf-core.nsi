; apf-core.nsi — CORE-ONLY вариант установщика APF для ЭТОГО хоста.
;
; Сгенерирован из apf.nsi для БЕЗОПАСНОЙ установки на рабочую машину:
;   • БЕЗ секции TUN-службы (apf-svc) — LocalSystem-служба на хосте рвёт связь
;     хосту (правило проекта: APF нельзя запускать на рабочей машине);
;   • БЕЗ авто-запуска APF на финише (нет MUI_FINISHPAGE_RUN);
;   • БЕЗ секции автозапуска при входе в Windows.
; Ставит только APF.exe + sing-box + ярлыки → полный W3-UI в режиме
; SOCKS5/HTTP-прокси. Полный TUN/VPN-режим требует apf-svc — его ставить на
; ОТДЕЛЬНОМ ПК/стенде полным installer\apf.nsi.
;
; Сборка: makensis /INPUTCHARSET UTF8 installer\apf-core.nsi
; Результат: dist\APF-Setup-<версия>-core.exe

Unicode true

!define APP_NAME      "APF"
!define APP_NAME_FULL "APF — Adaptive PathFinder (core)"
!define APP_VERSION   "1.1.9"
!define APP_PUBLISHER "APF Project"
!define APP_EXE       "APF.exe"
!define SVC_EXE       "apf-svc.exe"
!define UNINST_KEY    "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

Name "${APP_NAME_FULL}"
OutFile "..\dist\APF-Setup-${APP_VERSION}-core.exe"
InstallDir "$PROGRAMFILES64\APF"
InstallDirRegKey HKLM "Software\APF" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON   "..\gui\build\windows\icon.ico"
!define MUI_UNICON "..\gui\build\windows\icon.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
; ВНИМАНИЕ: MUI_FINISHPAGE_RUN намеренно НЕ определён — APF не запускается
; автоматически по завершении (запуск app на хосте запрещён правилом проекта).
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; ─── Основные файлы (обязательно) ──────────────────────────────────────────
Section "APF (обязательно)" SecCore
  SectionIn RO
  ; Апгрейд поверх уже запущенного APF: APF.exe заблокирован работающим
  ; процессом (трей). Закрываем перед копированием — на чистой установке
  ; процесса нет, taskkill просто ничего не найдёт.
  nsExec::ExecToLog 'taskkill /IM "${APP_EXE}" /F'
  Pop $0
  SetOutPath "$INSTDIR"
  File "..\gui\build\bin\APF.exe"
  File "..\gui\build\windows\icon.ico"
  SetOutPath "$INSTDIR\bin"
  File "..\..\windows\bin\sing-box.exe"
  File "..\..\windows\bin\libcronet.dll"
  SetOutPath "$INSTDIR"

  CreateDirectory "$SMPROGRAMS\APF"
  CreateShortcut "$SMPROGRAMS\APF\APF.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\APF\Удалить APF.lnk" "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\APF" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayName"     "${APP_NAME_FULL}"
  WriteRegStr   HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr   HKLM "${UNINST_KEY}" "InstallLocation"  "$INSTDIR"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayIcon"      "$INSTDIR\icon.ico"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayVersion"   "${APP_VERSION}"
  WriteRegStr   HKLM "${UNINST_KEY}" "Publisher"        "${APP_PUBLISHER}"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Ярлык на рабочем столе" SecDesktop
  CreateShortcut "$DESKTOP\APF.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\icon.ico"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Приложение APF (интерфейс + трей) и sing-box. Режим SOCKS5/HTTP-прокси. TUN/VPN-службы в этом варианте нет."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Ярлык APF на рабочем столе."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ─── Удаление ───────────────────────────────────────────────────────────────
Section "Uninstall"
  ; Служба этим вариантом не ставится. Но если на машине раньше стоял ПОЛНЫЙ
  ; установщик — корректно снимем и её (тот же путь, что в apf.nsi).
  IfFileExists "$INSTDIR\${SVC_EXE}" 0 +4
    ExecWait '"$INSTDIR\${SVC_EXE}" remove' $0
    DetailPrint "apf-svc remove: код возврата $0"
    Sleep 500

  Delete "$INSTDIR\${SVC_EXE}"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\bin\sing-box.exe"
  Delete "$INSTDIR\bin\libcronet.dll"
  Delete "$INSTDIR\bin\wintun.dll"
  RMDir  "$INSTDIR\bin"
  Delete "$INSTDIR\uninstall.exe"
  RMDir  "$INSTDIR"

  Delete "$SMPROGRAMS\APF\APF.lnk"
  Delete "$SMPROGRAMS\APF\Удалить APF.lnk"
  RMDir  "$SMPROGRAMS\APF"
  Delete "$DESKTOP\APF.lnk"
  Delete "$SMSTARTUP\APF.lnk"

  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\APF"
SectionEnd
