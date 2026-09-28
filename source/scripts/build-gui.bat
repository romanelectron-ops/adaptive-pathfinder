@echo off
REM build-gui.bat - build APF Desktop GUI (Windows), safe recipe (TZ v1.4 I-3 / I-9).
REM Requirements: Go 1.22+, Node.js 18+.
REM
REM This script intentionally does NOT invoke the Wails command-line tool at all
REM (none of its subcommands run here), and does NOT auto-install any tool from
REM the network. That tool is known to launch the real APF app process on this
REM machine, which is forbidden here (see project safety notes on this risk).
REM The GUI binary is produced with a plain "go build" using the same
REM "desktop,production" tags instead - no extra runtime is started.
REM Run from the project root (source\): scripts\build-gui.bat
setlocal

set APP=APF

echo === APF GUI Build Script ===
echo.

REM Check Go
where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Go not found. Install from https://go.dev/dl/
    pause & exit /b 1
)

REM Check Node.js
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js not found. Install from https://nodejs.org/
    pause & exit /b 1
)

REM I-6: version comes from internal\version\version.go - the single source of
REM truth for the whole project. No literal version number is kept here; if the
REM read fails, the script stops with a clear error instead of guessing.
set VERSION=
for /f "tokens=4" %%v in ('findstr /r /c:"^var Version = " internal\version\version.go') do set VERSION=%%~v
if "%VERSION%"=="" (
    echo [ERROR] Could not read version from internal\version\version.go
    echo         Run this script FROM THE PROJECT ROOT: scripts\build-gui.bat
    pause & exit /b 1
)

echo Go:      & go version
echo Node:    & node --version
echo Version: %VERSION%
echo.

cd gui

REM [1/3] Frontend build (plain npm/vite - no wails involved at any step).
echo [1/3] Building frontend (npm)...
cd frontend
call npm install
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] npm install failed & cd ..\.. & pause & exit /b 1 )
call npm run build
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] npm run build failed & cd ..\.. & pause & exit /b 1 )
cd ..

REM [2/3] APF.exe via plain "go build" - direct replacement for the old GUI
REM toolkit's packaging step, same tags/flags, no extra runtime is started.
echo [2/3] Building %APP%.exe (go build)...
set GOOS=windows
set GOARCH=amd64
go build -tags "desktop,production" -ldflags "-w -s -H windowsgui" -o build\bin\%APP%.exe .
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] go build failed & cd .. & pause & exit /b 1 )

if not exist "build\windows\icon.ico" (
    echo [WARN] gui\build\windows\icon.ico not found - installer\apf.nsi needs it.
    echo        Place the icon manually before running build-installer.bat ^(TZ I-4^).
)

REM [3/3] Copy result out of gui\
echo [3/3] Packaging...
if not exist "..\dist\gui" mkdir "..\dist\gui"
copy "build\bin\%APP%.exe" "..\dist\gui\%APP%.exe"

cd ..

echo.
echo === Build complete (v%VERSION%) ===
echo Output: dist\gui\%APP%.exe
echo.
echo Remember to place sing-box.exe in the bin\ folder next to %APP%.exe
pause
