# apf_safety_lib.ps1 — общая библиотека безопасности KS-тестов.
# Dot-source: . "$PSScriptRoot\apf_safety_lib.ps1"
# ВСЕ функции ЛОКАЛЬНЫЕ (netsh/файлы) — работают даже когда Kill Switch заблокировал интернет.

$ErrorActionPreference = "Continue"

# P1 (аудит 2026-09-01, security-раздел, LOW находка №24): дефолт был жёстко "D:\APF_KS_SAFETY"
# — диска D: на машине пользователя может не быть вовсе, и логирование аварийного
# восстановления/watchdog молча отваливалось бы (все Ensure-SafetyDir/Set-Content ниже
# используют это же место). $env:TEMP гарантированно существует на любой Windows-машине;
# явное переопределение через APF_KS_SAFETY_DIR по-прежнему в приоритете, как и раньше.
if ($env:APF_KS_SAFETY_DIR) { $script:SafetyDir = $env:APF_KS_SAFETY_DIR } else { $script:SafetyDir = Join-Path $env:TEMP "APF_KS_SAFETY" }
$script:LeaseFile  = Join-Path $script:SafetyDir "lease.json"
$script:DiagDir    = Join-Path $script:SafetyDir "diag"
$script:RestoreLog = Join-Path $script:SafetyDir "restore.log"
$script:WatchLog   = Join-Path $script:SafetyDir "watchdog.log"
$script:APF_RULE   = "APF-KillSwitch"
# P1-10 (аудит 2026-09-01): имена правил перечислены ПОЛНОСТЬЮ, а не собираются как
# "$($script:APF_RULE)$s". Прежняя форма была невидима для стража синхронизации
# (rules_guard_test.go искал литеральное "APF-KillSwitch-<суффикс>"), из-за чего этот файл
# молча выпал из проверки и разошёлся с Go-списком — в нём не хватало APF-KillSwitch-allow-vpn6.
# Держать имена литеральными: только так страж способен их увидеть.
$script:APF_RULES = @(
  "APF-KillSwitch-allow-loopback",
  "APF-KillSwitch-allow-lan",
  "APF-KillSwitch-allow-vpn",
  "APF-KillSwitch-allow-vpn6",
  "APF-KillSwitch-allow-tun",
  "APF-KillSwitch-allow-probe",
  "APF-KillSwitch-allow-probe6",
  "APF-KillSwitch-block-tcp",
  "APF-KillSwitch-block-udp",
  "APF-KillSwitch-block-out",
  "APF-KillSwitch-allow-local",
  "APF-KillSwitch-allow-dns"
)

function Ensure-SafetyDir {
  foreach ($d in @($script:SafetyDir, $script:DiagDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
  }
}

function Write-SafetyLog {
  param([string]$File, [string]$Msg)
  Ensure-SafetyDir
  try { Add-Content -Path $File -Value ("{0}  {1}" -f (Get-Date -Format o), $Msg) -Encoding UTF8 } catch {}
}

# Invoke-Netsh — изолируем netsh через cmd /c, чтобы PS 5.1 не превращал stderr в NativeCommandError.
function Invoke-Netsh { param([string]$ArgLine)
  cmd /c "netsh $ArgLine" 2>&1 | Out-Null
}

# --- СХ-3: диагностика (read-only) ---
function Test-PingHost { param([string]$Target,[int]$TimeoutMs=1500)
  if (-not $Target) { return "n/a" }
  try {
    $p = New-Object System.Net.NetworkInformation.Ping
    $r = $p.Send($Target, $TimeoutMs)
    if ($r.Status -eq "Success") { return "OK($($r.RoundtripTime)ms)" } else { return "FAIL($($r.Status))" }
  } catch { return "ERR" }
}
function Test-TcpPort { param([string]$Target,[int]$Port,[int]$TimeoutMs=1500)
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    $iar = $c.BeginConnect($Target, $Port, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs)
    $res = if ($ok -and $c.Connected) { "OPEN" } else { "CLOSED" }
    $c.Close(); return $res
  } catch { return "ERR" }
}
function Test-DnsResolve { param([string]$Name="one.one.one.one")
  try { if (Resolve-DnsName -Name $Name -QuickTimeout -ErrorAction SilentlyContinue) { "OK" } else { "FAIL" } } catch { "ERR" }
}
function Get-DefaultGateway {
  try { (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop } catch { $null }
}
# Test-EgressUp — есть ли ВЫХОД в интернет (ICMP к публичным IP, затем TCP443 как запасной сигнал).
# Инжектируется в self-test через $script:EgressProbeOverride (для проверки логики без реальной сети).
function Test-EgressUp {
  if ($null -ne $script:EgressProbeOverride) { return [bool]$script:EgressProbeOverride }
  foreach ($t in @("1.1.1.1","8.8.8.8")) { if ((Test-PingHost $t 1000) -like "OK*") { return $true } }
  if ((Test-TcpPort "1.1.1.1" 443 1000) -eq "OPEN") { return $true }
  return $false
}
function Get-NetState {
  $gw  = Get-DefaultGateway
  $apf = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "$($script:APF_RULE)*" })
  $pol = (cmd /c "netsh advfirewall show allprofiles" 2>&1 | Select-String -Pattern "Firewall Policy|Politika" | Out-String).Trim()
  $lines = @()
  $lines += "APF_rule_count=$($apf.Count)"
  foreach ($r in $apf) { $lines += "  rule: $($r.DisplayName) $($r.Direction) $($r.Action) enabled=$($r.Enabled)" }
  $lines += "gateway=$gw ping=" + (Test-PingHost $gw)
  $lines += "egress_ping_1.1.1.1=" + (Test-PingHost "1.1.1.1")
  $lines += "dns_resolve=" + (Test-DnsResolve)
  $lines += "tcp443_1.1.1.1=" + (Test-TcpPort "1.1.1.1" 443)
  if ($pol) { $lines += "firewall_policy: $pol" }
  return ($lines -join "`n")
}

# --- СХ-1: восстановление с ВЕРИФИКАЦИЕЙ и ЭСКАЛАЦИЕЙ (гарантия возврата сети) ---
# Invoke-RestoreEscalation прогоняет тиры по очереди; после каждого проверяет VerifyFn; останавливается
# на первом успешном. Возвращает номер сработавшего тира (1..N) или -1. Чистая логика (тиры/verify — блоки),
# поэтому тестируется фейковыми тирами и фейковым verify БЕЗ реального фаервола.
function Invoke-RestoreEscalation {
  param([System.Collections.IEnumerable]$Tiers, [ScriptBlock]$VerifyFn, [int]$DelayMs = 1500, [ScriptBlock]$LogFn)
  $i = 0
  foreach ($tier in $Tiers) {
    $i++
    if ($LogFn) { & $LogFn "restore tier ${i}: running" }
    try { & $tier } catch { if ($LogFn) { & $LogFn "tier $i error: $($_.Exception.Message)" } }
    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
    $ok = $false
    try { $ok = [bool](& $VerifyFn) } catch { $ok = $false }
    if ($LogFn) { & $LogFn "restore tier ${i}: egress_ok=$ok" }
    if ($ok) { return $i }
  }
  return -1
}

# Restore-Internet — тиры: 1) фаервол(+стоп APF)+flushdns → 2) сброс DNS на DHCP → 3) advfirewall reset
# (ЯДЕРНЫЙ, сносит и чужие правила, только при -AllowNuclear). Возвращает № тира, вернувшего сеть, или -1.
function Restore-Internet {
  param([switch]$StopApf, [switch]$AllowNuclear, [ScriptBlock]$VerifyFn, [int]$DelayMs = 1500)
  Ensure-SafetyDir
  Write-SafetyLog $script:RestoreLog "=== RESTORE start (StopApf=$StopApf AllowNuclear=$AllowNuclear) ==="
  if (-not $VerifyFn) { $VerifyFn = { Test-EgressUp } }
  $logFn = { param($m) Write-SafetyLog $script:RestoreLog $m }
  $tiers = New-Object System.Collections.ArrayList
  [void]$tiers.Add({
    Invoke-Netsh "advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    foreach ($r in $script:APF_RULES) { Invoke-Netsh "advfirewall firewall delete rule name=$r" }
    if ($StopApf) {
      foreach ($p in @("sing-box","apf","apf-tray","apf-svc")) {
        Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
      }
    }
    cmd /c "ipconfig /flushdns" 2>&1 | Out-Null
  })
  [void]$tiers.Add({
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      ForEach-Object { try { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue } catch {} }
    cmd /c "ipconfig /flushdns" 2>&1 | Out-Null
  })
  if ($AllowNuclear) {
    [void]$tiers.Add({ Invoke-Netsh "advfirewall reset" })   # ВНИМАНИЕ: сносит ВСЕ правила фаервола
  }
  $tier = Invoke-RestoreEscalation -Tiers $tiers -VerifyFn $VerifyFn -DelayMs $DelayMs -LogFn $logFn
  Write-SafetyLog $script:RestoreLog "=== RESTORE done (restored_at_tier=$tier) ==="
  return $tier
}

# Write-Incident — краткий отчёт «что случилось», чтобы агент/оператор сразу понял ситуацию.
function Write-Incident {
  param([string]$Reason,[int]$RestoreTier=-99,[string]$Pre="",[string]$Post="")
  Ensure-SafetyDir
  $t = (Get-Date).ToString("o")
  $body = @(
    "=== APF KS SAFETY INCIDENT ===",
    "time:             $t",
    "reason:           $Reason",
    "restored_at_tier: $RestoreTier  (-1=не удалось, -99=self-test/без restore)",
    "egress_after:     $(Test-EgressUp)",
    "",
    "--- PRE (до восстановления) ---", $Pre,
    "",
    "--- POST (после) ---", $Post
  ) -join "`n"
  $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
  Set-Content -Path (Join-Path $script:SafetyDir "incident_$stamp.txt") -Value $body -Encoding UTF8
  Set-Content -Path (Join-Path $script:SafetyDir "LAST_INCIDENT.txt") -Value $body -Encoding UTF8
  ([ordered]@{ time=$t; reason=$Reason; restored_at_tier=$RestoreTier } | ConvertTo-Json -Compress) |
    Add-Content -Path (Join-Path $script:SafetyDir "incidents.jsonl") -Encoding UTF8
}

# Notify-Incident — уведомить оператора у машины (best-effort). Работает и из SYSTEM-задачи:
# msg.exe шлёт в интерактивную сессию; beep — если есть звук. Все ошибки проглатываются.
function Notify-Incident {
  param([string]$Reason,[int]$Tier=-99)
  $msg = "APF Kill Switch: сторож восстановил интернет (reason=$Reason, tier=$Tier). Детали: D:\APF_KS_SAFETY\LAST_INCIDENT.txt"
  try { cmd /c "msg * `"$msg`"" 2>&1 | Out-Null } catch {}
  try { [console]::Beep(880,200); [console]::Beep(660,200); [console]::Beep(988,350) } catch {}
}

# --- СХ-2: аренда (lease) ---
function Write-Lease { param([int]$Seconds=90,[int]$HardMaxMinutes=10,[string]$Note="")
  Ensure-SafetyDir
  $now = Get-Date
  $o = [ordered]@{
    armed_at = $now.ToString("o")
    expiry   = $now.AddSeconds($Seconds).ToString("o")
    hard_max = $now.AddMinutes($HardMaxMinutes).ToString("o")
    owner_pid = $PID
    note     = $Note
  }
  ($o | ConvertTo-Json -Compress) | Set-Content -Path $script:LeaseFile -Encoding UTF8
}
function Read-Lease {
  if (Test-Path $script:LeaseFile) { try { Get-Content $script:LeaseFile -Raw | ConvertFrom-Json } catch { $null } } else { $null }
}
function Renew-Lease { param([int]$Seconds=90)
  $l = Read-Lease; if (-not $l) { return $false }
  $now = Get-Date; $hm = [datetime]::Parse($l.hard_max)
  $newExp = $now.AddSeconds($Seconds); if ($newExp -gt $hm) { $newExp = $hm }
  $l.expiry = $newExp.ToString("o")
  ($l | ConvertTo-Json -Compress) | Set-Content -Path $script:LeaseFile -Encoding UTF8
  return $true
}
function Clear-Lease { Remove-Item $script:LeaseFile -Force -ErrorAction SilentlyContinue }
function Get-LeaseStatus {
  $l = Read-Lease
  if (-not $l) { return [ordered]@{ armed=$false } }
  $now = Get-Date; $exp = [datetime]::Parse($l.expiry); $hm = [datetime]::Parse($l.hard_max)
  [ordered]@{ armed=$true; expired=($now -gt $exp); hardOver=($now -gt $hm); expiry=$exp; hard_max=$hm; note=$l.note }
}

function Test-IsAdmin {
  try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) } catch { $false }
}



