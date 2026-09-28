# apf_ks_heartbeat.ps1 — авто-renew компаньон (СХ-8). Снимает с оператора ручной renew.
#
# Модель: я (агент) периодически «касаюсь» heartbeat-файла (-Mode touch). Компаньон (-Mode run,
# в фоне) продлевает аренду, ПОКА касание свежее (age <= Ttl). Как только я замёрз и перестал
# касаться → компаньон перестаёт продлевать → аренда истекает → сторож восстанавливает сеть.
# Так heartbeat отражает МОЮ живость (uplink), а не живость локального процесса.
#
# Использование:
#   .\apf_ks_heartbeat.ps1 -Mode touch                      # мой «пульс» (вызывать между шагами)
#   Start-Process powershell -WindowStyle Hidden -Args ... -File apf_ks_heartbeat.ps1 -Mode run -Ttl 30 -RenewSeconds 90

param(
  [ValidateSet("touch","run","status")] [string]$Mode = "touch",
  [int]$Ttl = 30,               # макс. возраст касания, при котором ещё продлеваем (c)
  [int]$RenewSeconds = 90,      # на сколько продлевать аренду
  [int]$Interval = 5,           # период проверки (c)
  [int]$MaxRuntimeMinutes = 30  # самоограничение компаньона
)

. "$PSScriptRoot\apf_safety_lib.ps1"
$hb = Join-Path $script:SafetyDir "heartbeat.touch"

function HeartbeatAgeSec {
  if (-not (Test-Path $hb)) { return [double]::PositiveInfinity }
  ((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds
}

switch ($Mode) {
  "touch" {
    Ensure-SafetyDir
    Set-Content -Path $hb -Value (Get-Date -Format o) -Encoding UTF8
    Write-Host "[hb] touched $(Get-Date -Format o)"
  }
  "status" {
    Write-Host ("heartbeat_age_sec={0}  lease_armed={1}" -f ([math]::Round((HeartbeatAgeSec),1)), (Get-LeaseStatus).armed)
  }
  "run" {
    Write-SafetyLog $script:WatchLog "heartbeat companion START ttl=$Ttl renew=$RenewSeconds interval=$Interval"
    $deadline = (Get-Date).AddMinutes($MaxRuntimeMinutes)
    while ((Get-Date) -lt $deadline) {
      try {
        $age = HeartbeatAgeSec
        if ($age -le $Ttl) {
          if (Renew-Lease -Seconds $RenewSeconds) { } # продлеваем, пока касание свежее
        }
        # если age > Ttl — НЕ продлеваем: аренда истечёт, сторож восстановит сеть.
      } catch { try { Write-SafetyLog $script:WatchLog "hb ERROR: $($_.Exception.Message)" } catch {} }
      Start-Sleep -Seconds $Interval
    }
    Write-SafetyLog $script:WatchLog "heartbeat companion EXIT (max runtime)"
  }
}

