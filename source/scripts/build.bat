@echo off
REM build.bat — сборка APF для Windows
REM Запускать из корня проекта: scripts\build.bat
setlocal EnableDelayedExpansion

set APP=apf
set OUT=dist\windows

REM P3 (аудит 2026-09-01): версия читается из internal/version/version.go — единственного
REM источника истины (см. док-комментарий этого пакета).
REM
REM Раньше здесь стояло "set VERSION=1.0.2-hotfix", и это число врало дважды. Во-первых,
REM оно отстало от version.go на две минорные версии. Во-вторых, попытка внедрить его в
REM бинарник (-X main.version=%VERSION%) не работала в принципе: main.version объявлен как
REM `var version = appver.Version`, то есть инициализируется выражением, а -X линкера
REM действует только на переменные со строковой КОНСТАНТОЙ в инициализаторе. Сборка всегда
REM получала версию из version.go, а баннер печатал постороннее число — человек, собравший
REM бинарник, неверно опознавал, что именно у него на руках. Ldflags-подмена убрана как
REM неработавшая, вместо неё — честное чтение того значения, которое реально попадёт в exe.
set VERSION=
REM Строка в version.go: `var Version = "1.1.0"` → 4-й токен по пробелам = "1.1.0",
REM %%~v снимает кавычки. Так обходимся без экранирования кавычки-разделителя.
for /f "tokens=4" %%v in ('findstr /r /c:"^var Version = " internal\version\version.go') do set VERSION=%%~v
if "%VERSION%"=="" (
    echo  [ERROR] Не удалось прочитать версию из internal\version\version.go
    echo          Запускать скрипт нужно ИЗ КОРНЯ ПРОЕКТА: scripts\build.bat
    pause & exit /b 1
)

echo.
echo  === APF Build Script v%VERSION% ===
echo.

REM Проверяем Go
where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Go не найден!
    echo          Установи Go 1.22+ с https://go.dev/dl/
    pause & exit /b 1
)
echo  Go: & go version

echo.
mkdir "%OUT%\bin" 2>nul

REM Загружаем зависимости
echo  [1/3] Downloading dependencies...
go mod tidy
if %ERRORLEVEL% NEQ 0 ( echo  [ERROR] go mod tidy failed & pause & exit /b 1 )
go mod download
if %ERRORLEVEL% NEQ 0 ( echo  [ERROR] go mod download failed & pause & exit /b 1 )

REM Сборка
echo  [2/3] Building APF Windows AMD64...
set GOOS=windows
set GOARCH=amd64
REM Без -X: версия уже зашита через internal/version (см. комментарий у set VERSION выше).
go build -ldflags="-s -w" -o "%OUT%\%APP%.exe" ./cmd/apf/
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERROR] BUILD FAILED!
    pause & exit /b 1
)
echo         OK: %OUT%\%APP%.exe

REM Создаём лаунчер APF_Start.bat рядом с exe
echo  [3/3] Creating launcher...
(
echo @echo off
echo REM APF Launcher — запускает APF с Web UI
echo REM Двойной клик = запуск, браузер откроется автоматически
echo.
echo cd /d "%%~dp0"
echo.
echo REM Проверяем sing-box
echo if not exist "bin\sing-box.exe" ^(
echo     echo.
echo     echo  [!] sing-box.exe не найден в папке bin\
echo     echo  [!] Скачай с: https://github.com/SagerNet/sing-box/releases
echo     echo  [!] Положи sing-box.exe в папку bin\
echo     echo.
echo     pause
echo ^)
echo.
echo REM Запускаем APF ^(без параметров = автостарт^)
echo echo Запуск APF...
echo echo Web UI откроется на http://localhost:9090
echo echo Закрой это окно чтобы остановить APF.
echo echo.
echo start "" "http://localhost:9090"
echo %APP%.exe
echo pause
) > "%OUT%\APF_Start.bat"
echo         OK: %OUT%\APF_Start.bat

REM Проверяем sing-box
echo.
if exist "%OUT%\bin\sing-box.exe" (
    echo  [OK] sing-box.exe найден в %OUT%\bin\
) else (
    echo  [!] sing-box.exe НЕ найден в %OUT%\bin\
    echo      Скопируй sing-box.exe из папки windows\bin\ или
    echo      скачай с github.com/SagerNet/sing-box/releases
)

echo.
echo  ══════════════════════════════════════
echo  Build complete!
echo.
echo  Запуск:
echo    Дважды кликни на %OUT%\APF_Start.bat
echo    Или запусти:  %OUT%\%APP%.exe
echo.
echo  Web UI:  http://localhost:9090
echo  SOCKS5:  127.0.0.1:10808
echo  ══════════════════════════════════════
echo.
pause
