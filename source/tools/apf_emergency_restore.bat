@echo off
REM ============================================================================
REM  APF Kill Switch - EMERGENCY INTERNET RESTORE (ultimate manual fallback).
REM  Pure netsh, no PowerShell. Double-click, or run as Administrator.
REM  Idempotent and safe to run anytime (on a default machine it is a no-op).
REM ============================================================================
echo [APF] Emergency restore: allowing outbound and removing Kill Switch rules...

netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

REM  Rule names are written out in FULL literal form on purpose (P1-10, audit 2026-09-01).
REM  Previously this loop built them as "APF-KillSwitch-%%R", which the sync guard
REM  (rules_guard_test.go) could not match - so this file silently fell out of the check and
REM  drifted: it was missing APF-KillSwitch-allow-vpn6. Keep names literal so the guard can
REM  see them.
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-loopback >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-lan >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-vpn >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-vpn6 >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-tun >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-probe >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-probe6 >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-block-tcp >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-block-udp >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-block-out >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-local >nul 2>&1
netsh advfirewall firewall delete rule name=APF-KillSwitch-allow-dns >nul 2>&1

REM Stop APF / sing-box so they cannot re-apply Kill Switch right after restore.
for %%P in (sing-box.exe apf.exe apf-tray.exe apf-svc.exe) do (
  taskkill /F /IM %%P >nul 2>&1
)

ipconfig /flushdns >nul 2>&1

REM P1 (аудит 2026-09-01, security-раздел, LOW находка №24): было жёстко "D:\APF_KS_SAFETY" —
REM диска D: на машине пользователя может не быть вовсе (частый случай на ноутбуках с одним
REM системным диском), и логирование аварийного восстановления молча отваливалось (mkdir и
REM echo >> оба падают тихо, >nul 2>&1). Сама РАБОТА скрипта (netsh-команды выше) от этого не
REM страдала — страдал только след о том, что восстановление вообще происходило. %TEMP%
REM гарантированно существует на любой Windows-машине.
if not exist "%TEMP%\APF_KS_SAFETY" mkdir "%TEMP%\APF_KS_SAFETY" >nul 2>&1
echo %DATE% %TIME%  apf_emergency_restore.bat executed >> "%TEMP%\APF_KS_SAFETY\restore.log"

echo [APF] Done. Outbound allowed, APF-KillSwitch rules removed, APF/sing-box stopped.
echo [APF] If this window was opened by double-click, you can close it now.
