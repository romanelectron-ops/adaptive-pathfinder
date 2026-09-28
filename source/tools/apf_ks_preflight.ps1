# apf_ks_preflight.ps1 — СХ-6: GO/NO-GO проверка ПЕРЕД любым реальным включением Kill Switch.
# Убеждаемся, что автономная страховка на месте. Ничего не меняет (read-only).

. "$PSScriptRoot\apf_safety_lib.ps1"

$issues = @(); $warn = @()

$admin = Test-IsAdmin
if (-not $admin) { $issues += "НЕ администратор — реальный restore/scheduled task не сработают (нужен admin/SYSTEM)." }

$wt = Get-ScheduledTask -TaskName "APF-KS-Watchdog" -ErrorAction SilentlyContinue
if (-not $wt) { $issues += "Watchdog-задача не установлена → 'apf_ks_watchdog.ps1 -Mode install' (от админа)." }

$bat = Join-Path $PSScriptRoot "apf_emergency_restore.bat"
if (-not (Test-Path $bat)) { $issues += "Нет apf_emergency_restore.bat (ручной последний рубеж)." }

if (-not (Test-EgressUp)) { $warn += "Сейчас НЕТ выхода в интернет — восстанови/проверь сеть ДО теста." }

$ls = Get-LeaseStatus
if ($ls.armed) { $warn += "Аренда УЖЕ вооружена (возможно, идёт другой тест) — проверь." }

Write-Host "==== APF KS PREFLIGHT ====" -ForegroundColor Cyan
Write-Host ("admin={0}  watchdog_task={1}  emergency_bat={2}  egress={3}" -f $admin, [bool]$wt, (Test-Path $bat), (Test-EgressUp))
foreach ($w in $warn)  { Write-Host "[WARN] $w" -ForegroundColor Yellow }
foreach ($i in $issues){ Write-Host "[STOP] $i" -ForegroundColor Red }

if ($issues.Count -eq 0) {
  Write-Host "`n[GO] Страховка на месте. Можно вооружать аренду и запускать тест." -ForegroundColor Green
  exit 0
} else {
  Write-Host "`n[NO-GO] Устрани [STOP] выше перед реальным включением Kill Switch." -ForegroundColor Red
  exit 1
}



