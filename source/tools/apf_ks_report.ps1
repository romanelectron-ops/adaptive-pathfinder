# apf_ks_report.ps1 — пост-мортем: сводка «что случилось» после срабатывания сторожа.
# Read-only. Запускать, когда канал управления вернулся, чтобы быстро изучить проблему.

param([int]$DiagTail = 40)

. "$PSScriptRoot\apf_safety_lib.ps1"

function Section($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }

Write-Host "APF KS SAFETY REPORT  ($(Get-Date -Format o))" -ForegroundColor Green
Write-Host "safetyDir: $script:SafetyDir   egress_now: $(Test-EgressUp)"

Section "LAST_INCIDENT"
$li = Join-Path $script:SafetyDir "LAST_INCIDENT.txt"
if (Test-Path $li) { Get-Content $li } else { Write-Host "инцидентов не зафиксировано" -ForegroundColor Yellow }

Section "История инцидентов (incidents.jsonl)"
$ij = Join-Path $script:SafetyDir "incidents.jsonl"
if (Test-Path $ij) { Get-Content $ij -Tail 10 } else { Write-Host "нет" }

Section "restore.log (хвост)"
$rl = Join-Path $script:SafetyDir "restore.log"
if (Test-Path $rl) { Get-Content $rl -Tail 15 } else { Write-Host "нет" }

Section "watchdog.log (хвост)"
$wl = Join-Path $script:SafetyDir "watchdog.log"
if (Test-Path $wl) { Get-Content $wl -Tail 15 } else { Write-Host "нет" }

Section "Последний diag: переходы egress + срабатывания"
$diag = Get-ChildItem (Join-Path $script:SafetyDir "diag") -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
if ($diag) {
  Write-Host "файл: $($diag.Name)"
  # показываем строки состояния (armed/egress) и хвост
  Get-Content $diag.FullName | Select-String -Pattern "armed=|FIRED|egress_ping" | Select-Object -Last $DiagTail
} else { Write-Host "нет diag-логов" }

Section "Текущее состояние сети"
Write-Host (Get-NetState)

