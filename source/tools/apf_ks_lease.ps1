# apf_ks_lease.ps1 — СХ-5: управление арендой (heartbeat) + one-shot backstop-task.
#
#   arm    — вооружить: записать аренду (expiry=now+Seconds, hard_max=now+HardMaxMinutes) +
#            зарегистрировать one-shot задачу APF-KS-Backstop на now+HardMax (независимый рубеж,
#            сработает даже если петля-сторож умерла).
#   renew  — продлить expiry (мой heartbeat; не дальше hard_max).
#   disarm — снять аренду + удалить backstop-task (+ опц. -RestoreOnDisarm вернуть сеть).
#   status — показать аренду.
#
# Использование:
#   .\apf_ks_lease.ps1 -Mode arm -Seconds 90 -HardMaxMinutes 10
#   .\apf_ks_lease.ps1 -Mode renew -Seconds 90
#   .\apf_ks_lease.ps1 -Mode disarm
#   .\apf_ks_lease.ps1 -Mode status

param(
  [ValidateSet("arm","renew","disarm","status")] [string]$Mode,
  [int]$Seconds = 90,
  [int]$HardMaxMinutes = 10,
  [string]$Note = "",
  [switch]$RestoreOnDisarm
)

. "$PSScriptRoot\apf_safety_lib.ps1"
$backstop = "APF-KS-Backstop"
$batPath  = Join-Path $PSScriptRoot "apf_emergency_restore.bat"

switch ($Mode) {

  "arm" {
    Write-Lease -Seconds $Seconds -HardMaxMinutes $HardMaxMinutes -Note $Note
    Write-Host "[OK] Аренда вооружена: expiry +$Seconds c, hard_max +$HardMaxMinutes мин." -ForegroundColor Green
    if (Test-IsAdmin) {
      try {
        $when = (Get-Date).AddMinutes($HardMaxMinutes)
        $a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$batPath`""
        $t = New-ScheduledTaskTrigger -Once -At $when
        $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $backstop -Action $a -Trigger $t -Principal $p -Force | Out-Null
        Write-Host "[OK] Backstop-задача '$backstop' на $($when.ToString('HH:mm:ss')) (SYSTEM)." -ForegroundColor Green
      } catch { Write-Host "[!] Не удалось зарегистрировать backstop-задачу: $($_.Exception.Message)" -ForegroundColor Yellow }
    } else {
      Write-Host "[!] Не админ — backstop-задача не создана. ЗАПУСТИ ОТ АДМИНА для полной защиты." -ForegroundColor Yellow
    }
  }

  "renew" {
    if (Renew-Lease -Seconds $Seconds) { Write-Host "[OK] Аренда продлена на +$Seconds c (в пределах hard_max)." -ForegroundColor Green }
    else { Write-Host "[!] Аренды нет — сначала -Mode arm." -ForegroundColor Yellow }
  }

  "disarm" {
    Clear-Lease
    Unregister-ScheduledTask -TaskName $backstop -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[OK] Аренда снята, backstop удалён." -ForegroundColor Green
    if ($RestoreOnDisarm) { Restore-Internet; Write-Host "[OK] Сеть восстановлена (disarm)." -ForegroundColor Green }
  }

  "status" {
    Get-LeaseStatus | ConvertTo-Json
    $t = Get-ScheduledTask -TaskName $backstop -ErrorAction SilentlyContinue
    if ($t) { Write-Host "backstop: зарегистрирован" } else { Write-Host "backstop: нет" }
  }
}




