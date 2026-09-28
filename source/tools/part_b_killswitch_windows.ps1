# Часть B — полуавтоматическая проверка Kill Switch на Windows (методика B1/B5).
# Запускать ОТ АДМИНИСТРАТОРА в PowerShell. Скрипт сам не управляет APF — он фиксирует
# состояние системы ДО/ПОСЛЕ и проверяет инварианты. Шаги с APF выполняешь вручную по подсказкам.
#
# Использование:
#   1) .\part_b_killswitch_windows.ps1 -Phase before     # до включения Kill Switch
#   2) (вручную) включить Kill Switch в APF и подключиться
#   3) .\part_b_killswitch_windows.ps1 -Phase during      # при активном KS
#   4) (вручную) выключить KS / выйти из APF
#   5) .\part_b_killswitch_windows.ps1 -Phase after        # после выхода
#   6) .\part_b_killswitch_windows.ps1 -Phase compare      # сверка before vs after

param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("before","during","after","compare")]
  [string]$Phase
)

$ErrorActionPreference = "Continue"
$dir = Join-Path $env:TEMP "apf_ks_test"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

function Snapshot($name) {
  $f = Join-Path $dir "$name.txt"
  "=== Snapshot: $name @ $(Get-Date -Format o) ===" | Out-File $f
  "--- Системный прокси ---" | Out-File $f -Append
  netsh winhttp show proxy 2>&1 | Out-File $f -Append
  (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue |
    Select-Object ProxyEnable, ProxyServer | Out-String) | Out-File $f -Append
  "--- Правила Windows Firewall с APF в имени ---" | Out-File $f -Append
  (Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*APF*" } |
    Select-Object DisplayName, Enabled, Direction, Action | Out-String) | Out-File $f -Append
  "--- Всего вкл. исходящих firewall-правил (для сверки целостности) ---" | Out-File $f -Append
  $cnt = (Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' }).Count
  "OutboundEnabledCount=$cnt" | Out-File $f -Append
  "--- Внешний IP (через текущее соединение) ---" | Out-File $f -Append
  try { (Invoke-WebRequest -UseBasicParsing -Uri "https://ifconfig.me/ip" -TimeoutSec 8).Content.Trim() | Out-File $f -Append }
  catch { "IP недоступен (это ОЖИДАЕМО, если KS режет трафик при мёртвом туннеле): $($_.Exception.Message)" | Out-File $f -Append }
  Write-Host "[OK] Снимок '$name' сохранён: $f" -ForegroundColor Green
  Get-Content $f
}

switch ($Phase) {
  "before" {
    Write-Host "`n=== ФАЗА BEFORE: фиксирую исходное состояние ===" -ForegroundColor Cyan
    Snapshot "before"
    Write-Host "`nДальше: включи Kill Switch в APF, подключись к узлу, затем запусти -Phase during" -ForegroundColor Yellow
  }
  "during" {
    Write-Host "`n=== ФАЗА DURING: KS активен ===" -ForegroundColor Cyan
    Snapshot "during"
    Write-Host "`nПРОВЕРЬ ВРУЧНУЮ:" -ForegroundColor Yellow
    Write-Host "  - Внешний IP сменился (не твой ISP)" 
    Write-Host "  - Теперь УБЕЙ процесс sing-box (Task Manager) и проверь, что интернет ПРОПАЛ (нет утечки)"
    Write-Host "  - Затем выключи KS / выйди из APF и запусти -Phase after"
  }
  "after" {
    Write-Host "`n=== ФАЗА AFTER: после выхода из APF ===" -ForegroundColor Cyan
    Snapshot "after"
    Write-Host "`nДалее: -Phase compare для сверки" -ForegroundColor Yellow
  }
  "compare" {
    Write-Host "`n=== СВЕРКА before vs after (инвариант D3/B-04.2: ничего чужого не сломано) ===" -ForegroundColor Cyan
    $b = Join-Path $dir "before.txt"; $a = Join-Path $dir "after.txt"
    if (!(Test-Path $b) -or !(Test-Path $a)) { Write-Host "Нет before/after снимков" -ForegroundColor Red; exit 1 }
    $bCount = (Select-String -Path $b -Pattern "OutboundEnabledCount=(\d+)").Matches.Groups[1].Value
    $aCount = (Select-String -Path $a -Pattern "OutboundEnabledCount=(\d+)").Matches.Groups[1].Value
    $apfAfter = (Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*APF*" }).Count
    Write-Host "Исходящих firewall-правил: before=$bCount after=$aCount"
    Write-Host "Остаточных APF-правил после выхода: $apfAfter"
    $ok = $true
    if ($apfAfter -ne 0) { Write-Host "[FAIL] Остались APF-правила после выхода — KS не убрал за собой!" -ForegroundColor Red; $ok=$false }
    if ($bCount -ne $aCount) { Write-Host "[WARN] Число исходящих правил изменилось ($bCount→$aCount) — проверь, не задеты ли чужие" -ForegroundColor Yellow }
    if ($ok) { Write-Host "[PASS] Чисто: APF-правил не осталось, число правил совпадает" -ForegroundColor Green }
  }
}
