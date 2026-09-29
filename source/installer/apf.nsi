; apf.nsi — установщик APF (Adaptive PathFinder) для Windows.
;
; Собирается NSIS (makensis). Требует ПРЕДВАРИТЕЛЬНО собранных бинарников:
;   gui\build\bin\APF.exe        — wails build -platform windows/amd64 (в gui\)
;   gui\build\windows\icon.ico   — генерируется тем же wails build
;   bin\apf-svc.exe              — go build ./cmd/apf-svc
;   ..\windows\bin\sing-box.exe  — внешняя зависимость (не собирается этим репо)
;   ..\windows\bin\libcronet.dll — то же
;   vendor\...\wintun\amd64\wintun.dll — вендорится вместе с sing-tun; нужен
;     РЯДОМ с sing-box.exe (тот же каталог), иначе sing-box не сможет открыть
;     TUN-интерфейс в VPN-режиме (Windows ищет DLL в каталоге запущенного exe)
;
; Сборка: makensis /INPUTCHARSET UTF8 installer\apf.nsi   (из source\)
; Результат: dist\APF-Setup-<версия>.exe

Unicode true

!define APP_NAME      "APF"
!define APP_NAME_FULL "APF — Adaptive PathFinder"
!define APP_VERSION   "1.1.10"
!define APP_PUBLISHER "APF Project"
!define APP_EXE       "APF.exe"
!define SVC_EXE       "apf-svc.exe"
!define UNINST_KEY    "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

Name "${APP_NAME_FULL}"
OutFile "..\dist\APF-Setup-${APP_VERSION}.exe"
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
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить APF"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; ─── Основные файлы (обязательно) ──────────────────────────────────────────
Section "APF (обязательно)" SecCore
  SectionIn RO
  ; Апгрейд поверх уже запущенного APF: APF.exe заблокирован работающим
  ; процессом (трей), File поверх него либо тихо не срабатывает, либо не
  ; заменяет код в памяти. Закрываем перед копированием — на чистой
  ; установке процесса нет, taskkill просто ничего не найдёт.
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

; ─── Служба apf-svc (полноценный VPN/TUN-режим) ────────────────────────────
; Архитектурное решение Э-Win-TUN-1 (docs/TZ_WINDOWS_TUN_VPN_v1.0.md): TUN-адаптер
; создаёт привилегированная служба apf-svc (LocalSystem), не разовая UAC-эскалация
; GUI. Без этого компонента APF всё равно работает — но только в режиме
; SOCKS5/HTTP-прокси (переключатель "Режим VPN" в настройках работать не будет,
; см. PatchConfig в internal/engine/engine.go). apf-svc.exe install/remove — его
; собственная подкоманда (cmd/apf-svc/main.go), не отдельный сервис-хелпер.
Section "Служба TUN/VPN-режима (apf-svc)" SecService
  ; Апгрейд поверх уже установленной и ЗАПУЩЕННОЙ службы: файл apf-svc.exe
  ; заблокирован работающим процессом, File поверх него не заменяет код в
  ; памяти службы (реальный баг, найден живым прогоном 2026-08-19). `net stop`
  ; ждёт до факта Stopped через SCM — но это НЕ гарантирует, что ОС уже
  ; освободила файловый хендл: SCM получает SERVICE_STOPPED из недр
  ; svc.Handler'а (golang.org/x/sys/windows/svc) ДО того, как сам процесс
  ; реально завершится (доразворачивание рантайма Go, освобождение image
  ; section) — живой прогон подтвердил именно это: net_stop_exit=0, File
  ; выполнился без ошибки, но байты на диске остались старые (тихий skip
  ; NSIS при попытке перезаписать ещё занятый файл в /S-режиме, без вывода
  ; ошибки). Sleep — простой и надёжный запас на этот хвост.
  nsExec::ExecToLog 'net stop APFService'
  Pop $0
  Sleep 1000
  SetOutPath "$INSTDIR"
  File "..\bin\apf-svc.exe"
  SetOutPath "$INSTDIR\bin"
  File "..\vendor\github.com\sagernet\sing-tun\internal\wintun\amd64\wintun.dll"
  SetOutPath "$INSTDIR"
  DetailPrint "Регистрирую службу APFService..."
  ExecWait '"$INSTDIR\${SVC_EXE}" install' $0
  DetailPrint "apf-svc install: код возврата $0"
  ExecWait '"$INSTDIR\${SVC_EXE}" start' $1
  DetailPrint "apf-svc start: код возврата $1"
SectionEnd

Section "Ярлык на рабочем столе" SecDesktop
  CreateShortcut "$DESKTOP\APF.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\icon.ico"
SectionEnd

; Не отмечена по умолчанию (/o) — автозапуск при входе в Windows пользователь
; должен выбрать явно, установщик не включает его молча.
Section /o "Запуск APF при входе в Windows" SecAutostart
  CreateShortcut "$SMSTARTUP\APF.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\icon.ico"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Приложение APF (интерфейс + системный трей) и sing-box — обязательные файлы."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Системная служба для настоящего VPN-режима (TUN-адаптер, весь трафик ОС). Без неё доступен только SOCKS5/HTTP-прокси."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Ярлык APF на рабочем столе."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAutostart} "APF запустится автоматически при входе в Windows и будет ждать в трее."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ─── Удаление ───────────────────────────────────────────────────────────────
Section "Uninstall"
  ; Сначала служба — пока apf-svc.exe ещё на диске (remove читает свой же путь
  ; из уже зарегистрированной службы, но сам процесс должен быть запускаемым).
  ; removeService() (cmd/apf-svc/main.go) теперь сам ждёт настоящий Stopped перед
  ; Delete() — тот же фикс, что у stopService() для установщика (живой прогон
  ; 2026-08-19/20). Sleep здесь — тот же запас на хвост освобождения ОС хендла
  ; файла, что и в SecService при установке: без него на APF-STAND апф-svc.exe и
  ; каталог оставались на диске (RMDir на непустую папку — тихий no-op в /S).
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
