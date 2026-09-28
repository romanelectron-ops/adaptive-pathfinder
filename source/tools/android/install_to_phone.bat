@echo off
chcp 65001 >nul
title APF - установка на телефон Android
setlocal

REM Установщик «в один клик»: проверка предпосылок, сборка APK, установка на телефон.
REM Прав администратора НЕ требует. Телефон должен быть подключён по USB с
REM разрешённой отладкой; на MIUI дополнительно нужна «Установка через USB».

set "HERE=%~dp0"

echo.
echo  == APF: установка на телефон ==
echo.

echo  [1/4] Проверяю телефон...
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%apf_phone.ps1" -Action Check
if errorlevel 1 (
    echo.
    echo  Телефон не готов. Подключите его по USB и разрешите отладку.
    goto :end
)

echo.
echo  [2/4] Проверяю предпосылки сборки...
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%build_apk.ps1" -CheckOnly
if errorlevel 1 (
    echo.
    echo  Не хватает компонентов сборки - список выше.
    echo  Мост:     tools\android\build_aar.ps1 -Apply
    echo  sing-box: tools\android\fetch_singbox.ps1 -Apply
    goto :end
)

echo.
echo  [3/4] Собираю APK...
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%build_apk.ps1"
if errorlevel 1 (
    echo.
    echo  Сборка не удалась - смотрите вывод выше.
    goto :end
)

echo.
echo  [4/4] Ставлю на телефон...
for /f "delims=" %%A in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem '%HERE%..\..\..\android\android-project\app\build\outputs\apk' -Filter *.apk -Recurse -ErrorAction SilentlyContinue ^| Sort-Object LastWriteTime -Descending ^| Select-Object -First 1 -ExpandProperty FullName"') do set "APK=%%A"

if not defined APK (
    echo  APK не найден.
    goto :end
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%apf_phone.ps1" -Action Install -ApkPath "%APK%"
if errorlevel 1 goto :end

echo.
echo  Готово. Приложение установлено.
echo.
echo  ВАЖНО: на первом этапе доступен только режим «Прокси» - туннель не создаётся,
echo  и потерять интернет на телефоне невозможно. Режим VPN включится на этапе Э-4.
echo.
echo  Если связь на телефоне всё же пропадёт:
echo     tools\android\apf_phone.ps1 -Action Restore
echo.

:end
echo.
pause
endlocal
