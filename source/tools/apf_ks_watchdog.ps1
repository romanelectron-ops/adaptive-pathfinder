# apf_ks_watchdog.ps1 — СХ-4: автономный сторож (dead-man's switch) + управление scheduled task.
#
# ТРИГГЕРЫ восстановления (любой → Restore-Internet + инцидент + снятие аренды):
#   1) LEASE_EXPIRED — истекла аренда (я перестал продлевать: канал управления умер);
#   2) HARD_MAX      — превышен абсолютный потолок аренды;
#   3) EGRESS_LOSS   — интернет не выходит N тиков подряд (быстрый триггер на опасное состояние).
# Каждый тик пишет снимок сети в diag-лог. Работает локально → восстанавливает даже при блокировке.
#
# Использование:
#   (от админа, один раз) .\apf_ks_watchdog.ps1 -Mode install
#   .\apf_ks_watchdog.ps1 -Mode start | stop | status | remove
#   .\apf_ks_watchdog.ps1 -Mode run                 # петля (обычно из task)
#   .\apf_ks_watchdog.ps1 -Mode run -SelfTest -ForceEgressDown  # БЕЗОПАСНО: проверка логики без netsh

param(
  [ValidateSet("run","install","remove","start","stop","status")] [string]$Mode = "run",
  [int]$TickSeconds = 5,
  [int]$MaxRuntimeMinutes = 60,
  [int]$EgressGraceTicks = 4,     # сколько тиков подряд без интернета до срабатывания EGRESS_LOSS
  [switch]$NoEgressTrigger,       # отключить триггер по потере интернета (оставить только аренду)
  [switch]$AllowNuclear,          # разрешить ядерный тир restore (advfirewall reset) как последний рубеж
  [switch]$NoStopApf,             # не останавливать APF/sing-box при restore
  [switch]$SelfTest,              # вместо реального restore писать маркер (безопасная проверка)
  [switch]$ForceEgressDown        # (self-test) считать интернет заблокированным
)

. "$PSScriptRoot\apf_safety_lib.ps1"
$taskName = "APF-KS-Watchdog"
$self = $MyInvocation.MyCommand.Path

switch ($Mode) {

  "install" {
    if (-not (Test-IsAdmin)) { Write-Host "[!] Нужны права администратора для регистрации задачи." -ForegroundColor Yellow; exit 1 }
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$self`" -Mode run -TickSeconds $TickSeconds -MaxRuntimeMinutes $MaxRuntimeMinutes -EgressGraceTicks $EgressGraceTicks"
    $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
    $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName $taskName -Action $a -Principal $p -Settings $s -Force | Out-Null
    Write-Host "[OK] Задача '$taskName' зарегистрирована (SYSTEM). Запуск: -Mode start" -ForegroundColor Green
  }

  "remove" { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue; Write-Host "[OK] Задача снята." }

  "start"  { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop; Write-Host "[OK] Сторож запущен." -ForegroundColor Green }

  "stop"   { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; Write-Host "[OK] Сторож остановлен." }

  "status" {
    $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $t) { Write-Host "Задача '$taskName' не зарегистрирована." -ForegroundColor Yellow }
    else { Get-ScheduledTaskInfo -TaskName $taskName | Select-Object TaskName,LastRunTime,LastTaskResult,NextRunTime | Format-List }
    Write-Host "Аренда:"; Get-LeaseStatus | ConvertTo-Json
  }

  "run" {
    Write-SafetyLog $script:WatchLog "watchdog RUN start tick=$TickSeconds maxRun=$MaxRuntimeMinutes grace=$EgressGraceTicks noEgress=$NoEgressTrigger selftest=$SelfTest"
    $deadline = (Get-Date).AddMinutes($MaxRuntimeMinutes)
    $runId = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $diagFile = Join-Path $script:DiagDir "diag_$runId.log"
    $down = 0
    while ((Get-Date) -lt $deadline) {
      try {
        $st = Get-LeaseStatus
        $egressOk = if ($ForceEgressDown) { $false } else { Test-EgressUp }
        if ($egressOk) { $down = 0 } else { $down++ }
        Add-Content -Path $diagFile -Encoding UTF8 -Value ("{0}  armed={1} expired={2} hardOver={3} egressOk={4} downTicks={5}" -f (Get-Date -Format o), $st.armed, $st.expired, $st.hardOver, $egressOk, $down)
        Add-Content -Path $diagFile -Encoding UTF8 -Value (Get-NetState)
        Add-Content -Path $diagFile -Encoding UTF8 -Value "----"

        $fire = $null
        if ($st.armed) {
          if     ($st.hardOver) { $fire = "HARD_MAX" }
          elseif ($st.expired)  { $fire = "LEASE_EXPIRED" }
          elseif ((-not $NoEgressTrigger) -and ($down -ge $EgressGraceTicks)) { $fire = "EGRESS_LOSS" }
        }

        if ($fire) {
          Write-SafetyLog $script:WatchLog "WATCHDOG FIRED reason=$fire downTicks=$down"
          $pre = Get-NetState
          $tier = -99
          if ($SelfTest) {
            Set-Content -Path (Join-Path $script:SafetyDir "selftest_fired.txt") -Encoding UTF8 -Value ("fired $fire at " + (Get-Date -Format o))
          } else {
            $tier = Restore-Internet -StopApf:(-not $NoStopApf) -AllowNuclear:$AllowNuclear
          }
          $post = Get-NetState
          Write-Incident -Reason $fire -RestoreTier $tier -Pre $pre -Post $post
          if (-not $SelfTest) { Notify-Incident -Reason $fire -Tier $tier }
          Clear-Lease
          $down = 0
          Write-SafetyLog $script:WatchLog "post-fire restored_at_tier=$tier"
        }
      } catch {
        try { Write-SafetyLog $script:WatchLog "TICK ERROR: $($_.Exception.Message)" } catch {}
      }
      Start-Sleep -Seconds $TickSeconds
    }
    Write-SafetyLog $script:WatchLog "watchdog RUN exit (max runtime reached)"
  }
}



