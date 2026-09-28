@echo off
REM diagnose.bat — диагностика проблем запуска APF
REM Запусти этот файл если APF не запускается
setlocal
cd /d "%~dp0.."

echo.
echo  ╔══════════════════════════════════════╗
echo  ║   APF Диагностика                  ║
echo  ╚══════════════════════════════════════╝
echo.

set "ERRORS=0"
set "DIST=dist\windows"

REM [1] Проверяем apf.exe
echo  [1] APF исполняемый файл...
if exist "%DIST%\apf.exe" (
    echo      OK: %DIST%\apf.exe найден
    for %%F in ("%DIST%\apf.exe") do echo         Размер: %%~zF байт
) else (
    echo      FAIL: apf.exe не найден в %DIST%\
    echo      Решение: запусти scripts\build.bat
    set "ERRORS=1"
)

REM [2] Проверяем sing-box
echo.
echo  [2] sing-box...
if exist "%DIST%\bin\sing-box.exe" (
    echo      OK: bin\sing-box.exe найден
    for %%F in ("%DIST%\bin\sing-box.exe") do echo         Размер: %%~zF байт
) else if exist "bin\sing-box.exe" (
    echo      OK: bin\sing-box.exe найден (в корне)
) else (
    echo      WARN: sing-box.exe не найден
    echo      APF запустится, но соединение через туннель работать не будет.
    echo      Скачай: https://github.com/SagerNet/sing-box/releases
)

REM [3] Проверяем порт 9090
echo.
echo  [3] Порт 9090 (Web UI)...
netstat -an 2>nul | findstr ":9090 " >nul
if %ERRORLEVEL% EQU 0 (
    echo      ЗАНЯТ: порт 9090 уже используется другим процессом!
    echo      Это значит APF уже запущен, или другая программа занимает порт.
    netstat -ano 2>nul | findstr ":9090 "
    echo      Открой http://localhost:9090 в браузере.
) else (
    echo      OK: порт 9090 свободен
)

REM [4] Проверяем порт 10808
echo.
echo  [4] Порт 10808 (SOCKS5)...
netstat -an 2>nul | findstr ":10808 " >nul
if %ERRORLEVEL% EQU 0 (
    echo      ЗАНЯТ: порт 10808 уже используется
    netstat -ano 2>nul | findstr ":10808 "
) else (
    echo      OK: порт 10808 свободен
)

REM [5] Проверяем Go
echo.
echo  [5] Go...
where go >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo      OK: & go version
) else (
    echo      INFO: Go не найден (нужен только для сборки, не для запуска)
)

REM [6] Проверяем антивирус/файрвол
echo.
echo  [6] Проверка блокировки...
netsh advfirewall firewall show rule name="APF*" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo      INFO: Найдены правила APF в файрволе Windows
    netsh advfirewall firewall show rule name="APF*" | findstr "Rule Name\|Action\|Enabled"
) else (
    echo      INFO: Правил APF в файрволе нет
)

REM [7] Пробуем запустить и проверить через 3 секунды
echo.
echo  [7] Тест запуска APF...
if exist "%DIST%\apf.exe" (
    echo      Запускаем APF в фоне на 5 секунд...
    start /b "" "%DIST%\apf.exe" >"%TEMP%\apf_test.log" 2>&1
    set "APF_PID="
    timeout /t 3 /nobreak >nul

    REM Проверяем что порт занялся
    netstat -an 2>nul | findstr ":9090 " >nul
    if %ERRORLEVEL% EQU 0 (
        echo      OK: APF запустился, порт 9090 активен!
        echo      Открывай: http://localhost:9090
    ) else (
        echo      FAIL: APF не занял порт 9090 за 3 секунды
        echo      Лог запуска:
        type "%TEMP%\apf_test.log" 2>nul
    )

    REM Останавливаем тестовый процесс
    taskkill /f /im apf.exe >nul 2>&1
) else (
    echo      SKIP: apf.exe не найден
)

echo.
echo  ══════════════════════════════════════
if "%ERRORS%"=="0" (
    echo  Диагностика завершена без критических ошибок.
    echo.
    echo  Если Web UI не открывается:
    echo    1. Запусти: %DIST%\APF_Start.bat
    echo    2. Подожди 3-5 секунд
    echo    3. Открой браузер: http://localhost:9090
) else (
    echo  Найдены проблемы. Следуй инструкциям выше.
)
echo  ══════════════════════════════════════
echo.
pause
