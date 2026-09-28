@echo off
REM build-installer.bat - build the Windows installer for APF (NSIS).
REM Requirements: Go 1.22+, Node.js 18+, NSIS (makensis in PATH).
REM TZ v1.4 I-3 / I-9: this pipeline never invokes the Wails command-line tool and
REM never auto-installs a tool from the network (see build-gui.bat for details).
REM makensis (NSIS) is a separate, pre-installed tool this script only shells out
REM to when a human runs the full build; it is not part of what this lot owns.
REM Run from the project root (source\): scripts\build-installer.bat
setlocal

REM I-6: version comes from internal\version\version.go - the single source of
REM truth. installer\apf.nsi keeps its own APP_VERSION in sync manually (owned by
REM L3-PC); this script does not edit apf.nsi, only reports the value it read.
set VERSION=
for /f "tokens=4" %%v in ('findstr /r /c:"^var Version = " internal\version\version.go') do set VERSION=%%~v
if "%VERSION%"=="" (
    echo [ERROR] Could not read version from internal\version\version.go
    echo         Run this script FROM THE PROJECT ROOT: scripts\build-installer.bat
    pause & exit /b 1
)

echo === APF Installer Build Script (v%VERSION%) ===
echo.

where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Go not found. Install from https://go.dev/dl/
    pause & exit /b 1
)

where makensis >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] NSIS ^(makensis^) not found. Install from https://nsis.sourceforge.io/
    pause & exit /b 1
)

if not exist "..\windows\bin\sing-box.exe" (
    echo [ERROR] ..\windows\bin\sing-box.exe not found.
    echo         Get sing-box from github.com/SagerNet/sing-box/releases
    echo         and place it with libcronet.dll in windows\bin\ next to source\
    pause & exit /b 1
)

echo [1/3] Building APF GUI (go build - see build-gui.bat)...
call scripts\build-gui.bat
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] GUI build failed & exit /b 1 )

if not exist "gui\build\windows\icon.ico" (
    echo [WARN] gui\build\windows\icon.ico not found - installer\apf.nsi expects it.
    echo        Place the icon manually before makensis runs ^(TZ I-4^); continuing anyway.
)

echo.
echo [2/3] Building apf-svc.exe (TUN/VPN service)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o "bin\apf-svc.exe" ./cmd/apf-svc
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] apf-svc build failed & pause & exit /b 1 )
echo        OK: bin\apf-svc.exe

echo.
echo [3/3] Building installer (NSIS)...
if not exist "dist" mkdir "dist"
makensis /INPUTCHARSET UTF8 installer\apf.nsi
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] makensis failed & pause & exit /b 1 )

echo.
echo === Build complete ===
echo Output: dist\APF-Setup-%VERSION%.exe
echo.
pause
