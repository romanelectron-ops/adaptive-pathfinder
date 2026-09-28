# apf_ks_safe_run.ps1 — СХ-7: одна команда «сделать опасный шаг под защитой».
# Вооружает аренду + backstop, запускает сторожа, выполняет действие, ГАРАНТИРОВАННО снимает защиту
# в finally. Действие выполняется локально; если оно заблокирует сеть — сторож восстановит автономно.
#
# Рекомендуется запускать В ФОНЕ (Start-Process ... -WindowStyle Hidden), чтобы не блокировать оператора:
#   .\apf_ks_safe_run.ps1 -ActionScript "C:\...\some_ks_step.ps1" -Seconds 60 -HardMaxMinutes 10
#
# Предохранители: аренда истечёт даже если действие зависнет; backstop и watchdog вернут сеть.

param(
  [Parameter(Mandatory=$true)][string]$ActionScript,
  [string[]]$ActionArgs = @(),
  [int]$Seconds = 60,
  [int]$HardMaxMinutes = 10,
  [switch]$SkipPreflight
)

$here = $PSScriptRoot
. "$here\apf_safety_lib.ps1"

if (-not $SkipPreflight) {
  & "$here\apf_ks_preflight.ps1" | Out-Host
  if ($LASTEXITCODE -ne 0) { Write-Host "[safe_run] Preflight NO-GO — прерываю. Используй -SkipPreflight чтобы форсировать." -ForegroundColor Red; exit 1 }
}

if (-not (Test-Path $ActionScript)) { Write-Host "[safe_run] Не найден ActionScript: $ActionScript" -ForegroundColor Red; exit 1 }

Write-Host "[safe_run] Вооружаю защиту (lease=$Seconds c, hard_max=$HardMaxMinutes мин)..." -ForegroundColor Cyan
& "$here\apf_ks_lease.ps1" -Mode arm -Seconds $Seconds -HardMaxMinutes $HardMaxMinutes -Note "safe_run:$([IO.Path]::GetFileName($ActionScript))" | Out-Host
& "$here\apf_ks_watchdog.ps1" -Mode start | Out-Host

try {
  Write-SafetyLog $script:WatchLog "safe_run: START action=$ActionScript"
  Write-Host "[safe_run] Выполняю действие: $ActionScript $($ActionArgs -join ' ')" -ForegroundColor Cyan
  & $ActionScript @ActionArgs
  Write-SafetyLog $script:WatchLog "safe_run: action returned exit=$LASTEXITCODE"
}
catch {
  Write-SafetyLog $script:WatchLog "safe_run: action ERROR: $($_.Exception.Message)"
  Write-Host "[safe_run] Ошибка действия: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
  Write-Host "[safe_run] Снимаю защиту..." -ForegroundColor Cyan
  & "$here\apf_ks_lease.ps1" -Mode disarm | Out-Host
  & "$here\apf_ks_watchdog.ps1" -Mode stop | Out-Host
  Write-SafetyLog $script:WatchLog "safe_run: DONE (disarmed)"
}
exit 0



