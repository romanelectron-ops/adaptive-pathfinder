# part_b_killswitch_tg1.ps1 — АВТОМАТИЗАЦИЯ ИНВАРИАНТА TG-1 (B-0402.3, Gate A).
#
# TG-1: 100×(Enable→Disable) → 0 остаточных правил APF-*, ЧУЖОЕ правило и политика OUTPUT целы.
#
# Скрипт воспроизводит ТОЧНО тот же набор netsh-команд, что и боевой Kill Switch (D-31, §6.1:
# default-block-outbound + только allow). Зеркалит internal/killswitch/killswitch.go
# (ksApplyCommands / ksCleanupCommands) — при изменении там ОБНОВИТЬ здесь.
#
# !!! ВНИМАНИЕ: с -Execute скрипт РЕАЛЬНО меняет фаервол (в каждом цикле кратко ставит
#     blockoutbound). Запускать ТОЛЬКО от администратора и ТОЛЬКО на чистой Windows-VM (snapshot).
#     Без -Execute — сухой прогон (печатает команды, ничего не меняет).
#
# Использование:
#   .\part_b_killswitch_tg1.ps1                       # dry-run (безопасно, ничего не трогает)
#   .\part_b_killswitch_tg1.ps1 -Execute              # 100 циклов на VM (от админа)
#   .\part_b_killswitch_tg1.ps1 -Execute -Cycles 100 -VpnIP 203.0.113.7

param(
  [int]$Cycles = 100,
  [string]$VpnIP = "203.0.113.7",   # тестовый allow-IP (TEST-NET-3, RFC 5737)
  [switch]$Execute
)

$ErrorActionPreference = "Continue"
$RULE = "APF-KillSwitch"
$TUN_SUBNET = "172.19.0.0/30"        # зеркалит ksTunSubnet (singbox apf0 172.19.0.1/30)
$FOREIGN = "ZZZ-KStest-foreign-DONOTREMOVE"

# Полные имена правил APF (зеркалит windowsRuleSuffixes: current + legacy).
#
# P1-10 (аудит 2026-09-01): имена литеральные, а не "$RULE$s". Прежняя форма была невидима для
# стража синхронизации (rules_guard_test.go), и этот файл молча разошёлся с Go-списком — в нём
# не хватало APF-KillSwitch-allow-vpn6, то есть прогон TG-1 оставлял бы после себя правило,
# которое сам же и не удалил.
$RULES = @(
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

function Invoke-Netsh([string[]]$a) {
  if ($Execute) { & netsh @a 2>&1 | Out-Null }
  else          { Write-Host "    netsh $($a -join ' ')" -ForegroundColor DarkGray }
}

# --- набор ENABLE (D-31): очистка → allow×4 → политика blockoutbound (последней) ---
function KS-Enable {
  foreach ($r in $RULES) { Invoke-Netsh @("advfirewall","firewall","delete","rule","name=$r") }
  Invoke-Netsh @("advfirewall","firewall","add","rule","name=$RULE-allow-loopback","dir=out","action=allow","protocol=any","remoteip=127.0.0.1","profile=any")
  Invoke-Netsh @("advfirewall","firewall","add","rule","name=$RULE-allow-lan","dir=out","action=allow","protocol=any","remoteip=localsubnet","profile=any")
  if ($VpnIP) { Invoke-Netsh @("advfirewall","firewall","add","rule","name=$RULE-allow-vpn","dir=out","action=allow","protocol=any","remoteip=$VpnIP","profile=any") }
  Invoke-Netsh @("advfirewall","firewall","add","rule","name=$RULE-allow-tun","dir=out","action=allow","protocol=any","remoteip=$TUN_SUBNET","profile=any")
  Invoke-Netsh @("advfirewall","set","allprofiles","firewallpolicy","blockinbound,blockoutbound")
}

# --- набор DISABLE (D-31): вернуть allowoutbound → удалить все APF-правила ---
function KS-Disable {
  Invoke-Netsh @("advfirewall","set","allprofiles","firewallpolicy","blockinbound,allowoutbound")
  foreach ($r in $RULES) { Invoke-Netsh @("advfirewall","firewall","delete","rule","name=$r") }
}

function Count-APF {
  (Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "$RULE*" }).Count
}
function Foreign-Exists {
  [bool](Get-NetFirewallRule -DisplayName $FOREIGN -ErrorAction SilentlyContinue)
}

Write-Host "=== TG-1: $Cycles циклов Enable/Disable ($(if($Execute){'EXECUTE'}else{'DRY-RUN'})) ===" -ForegroundColor Cyan

if (-not $Execute) {
  Write-Host "`n[DRY-RUN] Ниже — команды ОДНОГО цикла (реально ничего не меняется):" -ForegroundColor Yellow
  Write-Host "  --- Enable ---"; KS-Enable
  Write-Host "  --- Disable ---"; KS-Disable
  Write-Host "`nЗапусти с -Execute на ЧИСТОЙ VM от администратора для реального прогона TG-1." -ForegroundColor Yellow
  return
}

# --- реальный прогон (только -Execute) ---
$pass = $true
try {
  # 1) Заводим ЧУЖОЕ правило и фиксируем исходную политику.
  & netsh advfirewall firewall add rule name=$FOREIGN dir=out action=allow protocol=any remoteip=198.51.100.42 profile=any 2>&1 | Out-Null
  $polBefore = (& netsh advfirewall show allprofiles state) -join "`n"
  $apf0 = Count-APF
  Write-Host "Старт: APF-правил=$apf0, чужое правило создано=$(Foreign-Exists)"

  # 2) Цикл.
  for ($i = 1; $i -le $Cycles; $i++) {
    KS-Enable
    KS-Disable
    if ($i % 10 -eq 0) { Write-Host "  ...цикл $i/$Cycles" }
  }

  # 3) Инварианты.
  $apfAfter = Count-APF
  $polAfter = (& netsh advfirewall show allprofiles state) -join "`n"
  $foreign = Foreign-Exists

  Write-Host "`n=== РЕЗУЛЬТАТ ==="
  if ($apfAfter -ne 0) { Write-Host "[FAIL] Остаточных APF-правил: $apfAfter (ожидалось 0)" -ForegroundColor Red; $pass=$false }
  else { Write-Host "[OK] 0 остаточных правил APF-*" -ForegroundColor Green }
  if (-not $foreign) { Write-Host "[FAIL] Чужое правило '$FOREIGN' исчезло!" -ForegroundColor Red; $pass=$false }
  else { Write-Host "[OK] Чужое правило цело" -ForegroundColor Green }
  if ($polBefore -ne $polAfter) { Write-Host "[FAIL] Политика OUTPUT изменилась (before != after)" -ForegroundColor Red; $pass=$false }
  else { Write-Host "[OK] Политика фаервола восстановлена как до теста" -ForegroundColor Green }
}
finally {
  # Гарантированная уборка: вернуть allowoutbound, снять APF-* и чужое тест-правило.
  & netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>&1 | Out-Null
  foreach ($r in $RULES) { & netsh advfirewall firewall delete rule name=$r 2>&1 | Out-Null }
  & netsh advfirewall firewall delete rule name=$FOREIGN 2>&1 | Out-Null
}

if ($pass) { Write-Host "`n[PASS] TG-1 пройден." -ForegroundColor Green; exit 0 }
else       { Write-Host "`n[FAIL] TG-1 НЕ пройден — см. выше." -ForegroundColor Red; exit 1 }

