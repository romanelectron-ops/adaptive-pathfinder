<#
apf_host_watchdog.ps1 — страховочный "dead man's switch" для живого запуска APF
на реальной рабочей машине (не в изолированном стенде).

Идея: пока APF работает на хосте в proxy/VPN-режиме, Claude периодически "пульсирует"
(обновляет $HeartbeatFile). Если пульса не было дольше $StaleThresholdMinutes минут
(по умолчанию 10 = 2 пропущенных пятиминутки, как попросил пользователь) — считаем,
что контроль потерян, и принудительно возвращаем хосту рабочий интернет.

Что именно ломает интернет и почему сброшено именно так (см. код APF):
  - internal/killswitch/wfp_windows.go: ОДИН из двух бэкендов Kill Switch (для
    привилегированной службы apf-svc) регистрирует правила в WFP dynamic session —
    Windows САМА снимает их, когда процесс, открывший сессию, завершается
    (crash-safe design, D-33). Убить процессы APF уже снимает эту блокировку.
  - internal/killswitch/elevate_windows.go + ks_rules.json: ВТОРОЙ бэкенд (когда
    служба apf-svc НЕ установлена — как раз наш случай при первом реальном тесте) —
    через одноразовый UAC создаёт КЛАССИЧЕСКИЕ правила netsh advfirewall с именами
    APF-KillSwitch-*. Эти правила НЕ самоочищаются при завершении процесса —
    persist до явного удаления. Список имён — единственный источник истины,
    сгенерирован из windowsRuleSuffixes (internal/killswitch/killswitch.go).
  - internal/sysproxy/sysproxy_windows.go: SetHTTPProxy пишет ProxyServer/ProxyEnable=1
    в HKCU\...\Internet Settings НАПРЯМУЮ в реестр — это НЕ снимается само по себе при
    завершении процесса. Собственный комментарий в коде: "если по этому адресу никто
    не слушает — у пользователя мгновенно «пропадает интернет» во всех приложениях".
    Главный практический риск в proxy-режиме.
  - internal/leakguard/ipv6.go: на Windows IPv6Guard осознанно НЕ трогает ОС-настройки
    (раньше ломало таблицу политик префиксов) — сбрасывать нечего.
  - DNS: leakguard только тестирует утечку, системные DNS-серверы не переключает.
    Но internal/killswitch/reset.go::resetDNSSafe() defensively проверяет и сбрасывает
    статический DNS 8.8.8.8/8.8.4.4/1.1.1.1/1.0.0.1 на DHCP, если он вдруг найден на
    подключённом адаптере — на случай будущей/скрытой фичи, которая его выставляет.
    Повторено здесь той же логикой для полного паритета с ResetAll().

ВАЖНО (найдено при повторном изучении internal/killswitch/killswitch.go и reset.go —
исходная версия этого скрипта это пропустила): классический (non-service) бэкенд
Kill Switch НЕ ТОЛЬКО добавляет 10 именованных allow/block-правил — последним шагом
Enable() он меняет саму ПОЛИТИКУ файрвола на "netsh advfirewall set allprofiles
firewallpolicy blockinbound,blockoutbound" (killswitch.go:205). Удаления одних только
именованных правил НЕДОСТАТОЧНО: если процесс убит до того, как штатный disable()
успел вернуть политику на allowoutbound, весь исходящий трафик остаётся заблокирован
на уровне политики независимо от того, что стало с правилами. Подтверждено, что это
уже случалось по-настоящему: apf_fw_cleanup.log в корне хендоффа показывает ручной
прогон скрипта сброса каждые ~3 минуты почти 40 минут подряд 2026-06-03 ночью —
ровно этот сценарий. Официальный полный сброс — internal/killswitch/reset.go::
ResetAll() (routing: rules → policy → DNS → flushdns) — теперь воспроизведён здесь
шаг в шаг.

Регистрируется как Scheduled Task (см. tools/host_watchdog/register_watchdog_task.ps1),
запускается каждую минуту от имени текущего интерактивного пользователя (нужен
корректный HKCU именно этого пользователя для сброса прокси).
#>

param(
    [string]$HeartbeatFile = "$env:ProgramData\APF\watchdog\heartbeat.txt",
    [string]$AlertLog      = "$env:ProgramData\APF\watchdog\alerts.log",
    [string]$RunLog        = "$env:ProgramData\APF\watchdog\run.log",
    [int]$StaleThresholdMinutes = 10,
    [switch]$ForceTrigger  # ручной прогон для проверки самого механизма сброса без реального инцидента
)

$dir = Split-Path $HeartbeatFile
New-Item -ItemType Directory -Path $dir -Force | Out-Null

function Write-WatchdogLog {
    param([string]$Path, [string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
    Add-Content -Path $Path -Value $line
}

if (-not $ForceTrigger) {
    if (-not (Test-Path $HeartbeatFile)) {
        # Найдено ревью: раньше "файла нет" всегда означало тихий no-op - неотличимо
        # от "пульс ещё не запускался" (безопасно) и "файл удалён/затёрт посреди
        # активной сессии" (опасно, ровно то, от чего должен защищать watchdog).
        # Различаем по факту: если процессы APF сейчас реально работают, а файла
        # heartbeat нет - считаем это тревогой, а не "нечего защищать".
        $anyRunning = Get-Process -Name "apf", "apf-svc", "apf-tray", "sing-box" -ErrorAction SilentlyContinue
        if ($anyRunning) {
            $reason = "heartbeat file missing while APF process(es) are running - treating as loss of control"
        } else {
            Write-WatchdogLog $RunLog "Heartbeat file not found and no APF process running - nothing to protect, skipping."
            exit 0
        }
    } else {
        $lastPulse = (Get-Item $HeartbeatFile).LastWriteTime
        $ageMinutes = ((Get-Date) - $lastPulse).TotalMinutes

        if ($ageMinutes -lt $StaleThresholdMinutes) {
            Write-WatchdogLog $RunLog ("OK: heartbeat age {0:N1} min (< {1} min threshold)" -f $ageMinutes, $StaleThresholdMinutes)
            exit 0
        }
        $reason = "heartbeat stale for {0:N1} minutes (threshold {1})" -f $ageMinutes, $StaleThresholdMinutes
    }
} else {
    $reason = "manual -ForceTrigger test run"
}

# --- СРАБОТАЛО: возвращаем хосту рабочий интернет ---
Write-WatchdogLog $AlertLog "TRIGGERED: $reason - resetting host network"

# 1. Убить процессы APF - снимает WFP kill-switch фильтры автоматически (dynamic session).
$procNames = "apf", "apf-svc", "apf-tray", "sing-box"
foreach ($p in $procNames) {
    $running = Get-Process -Name $p -ErrorAction SilentlyContinue
    if ($running) {
        $pids = ($running | Select-Object -ExpandProperty Id) -join ","
        Write-WatchdogLog $AlertLog "Killing process: $p (PID $pids)"
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 2

# 1b. Удалить персистентные правила netsh advfirewall от второго (non-service) бэкенда
#     Kill Switch - они НЕ снимаются автоматически, в отличие от WFP dynamic session.
#     Список - единственный источник истины из internal/killswitch/ks_rules.json.
$ksRules = @(
    "APF-KillSwitch-allow-loopback", "APF-KillSwitch-allow-lan",
    "APF-KillSwitch-allow-vpn", "APF-KillSwitch-allow-vpn6",
    "APF-KillSwitch-allow-tun", "APF-KillSwitch-allow-probe",
    "APF-KillSwitch-allow-probe6", "APF-KillSwitch-block-tcp",
    "APF-KillSwitch-block-udp", "APF-KillSwitch-block-out",
    "APF-KillSwitch-allow-local", "APF-KillSwitch-allow-dns"
)
$removedRules = 0
foreach ($rule in $ksRules) {
    $existing = netsh advfirewall firewall show rule name="$rule" 2>&1
    if ($LASTEXITCODE -eq 0 -and $existing -notmatch "No rules match") {
        netsh advfirewall firewall delete rule name="$rule" | Out-Null
        $removedRules++
    }
}
if ($removedRules -gt 0) {
    Write-WatchdogLog $AlertLog "Removed $removedRules stale APF-KillSwitch advfirewall rule(s)"
}

# 1c. КРИТИЧНО (найдено при повторном изучении killswitch.go:205 - см. заголовок файла):
#     вернуть саму ПОЛИТИКУ файрвола на allowoutbound. Классический бэкенд Kill Switch
#     переключает её на blockinbound,blockoutbound последним шагом Enable() - удаления
#     одних именованных правил недостаточно, если процесс убит до штатного disable().
try {
    $out = & netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>&1
    Write-WatchdogLog $AlertLog "Reset firewall policy to blockinbound,allowoutbound: $out"
} catch {
    Write-WatchdogLog $AlertLog "WARNING: failed to reset firewall policy: $_"
}

# 1d. Безопасный сброс DNS на DHCP - ТОЛЬКО если на подключённом адаптере обнаружен
#     статический DNS 8.8.8.8/8.8.4.4/1.1.1.1/1.0.0.1 (та же проверка, что и в
#     killswitch/reset.go::resetDNSSafe() - паритет с официальным ResetAll()).
#     Не трогает адаптеры с обычным DHCP DNS, не перезапускает адаптер.
try {
    $ifaceLines = (netsh interface show interface 2>&1) -split "`r?`n"
    foreach ($line in $ifaceLines) {
        $line = $line.Trim()
        if ($line -notmatch 'Connected|Подключен|Enabled') { continue }
        $fields = $line -split '\s+'
        if ($fields.Count -lt 4) { continue }
        $iface = ($fields[3..($fields.Count - 1)] -join ' ').Trim()
        if (-not $iface) { continue }

        $dnsOut = (netsh interface ip show dns name="$iface" 2>&1) -join "`n"
        $isStaticAPF = ($dnsOut -match 'Statically|статически') -and
                       ($dnsOut -match '8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1')
        if ($isStaticAPF) {
            netsh interface ip set dns name="$iface" source=dhcp | Out-Null
            Write-WatchdogLog $AlertLog "Reset static DNS to DHCP on adapter: $iface"
        }
    }
} catch {
    Write-WatchdogLog $AlertLog "WARNING: DNS-safe-reset check failed: $_"
}

# 2. Сбросить системный HTTP-прокси (HKCU) - единственное состояние, НЕ снимаемое
#    автоматически при завершении процесса.
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
        -Name ProxyEnable -Value 0 -ErrorAction Stop
    Write-WatchdogLog $AlertLog "Reset HKCU ProxyEnable=0"
} catch {
    Write-WatchdogLog $AlertLog "WARNING: failed to reset ProxyEnable: $_"
}

# 3. Сбросить WinHTTP-прокси (отдельная от WinINet цепочка, её используют некоторые
#    системные службы и .NET-приложения) - defense in depth.
try {
    $out = & netsh winhttp reset proxy 2>&1
    Write-WatchdogLog $AlertLog "netsh winhttp reset proxy: $out"
} catch {
    Write-WatchdogLog $AlertLog "WARNING: netsh winhttp reset proxy failed: $_"
}

# 4. Проверить, что интернет реально восстановлен.
Start-Sleep -Seconds 2
$connOK = Test-Connection -ComputerName 1.1.1.1 -Count 2 -Quiet -ErrorAction SilentlyContinue
Write-WatchdogLog $AlertLog "Post-reset connectivity check (ping 1.1.1.1): $connOK"

# Помечаем heartbeat как "обработано", чтобы не убивать процессы каждую минуту подряд,
# если Claude действительно надолго пропал - следующее срабатывание будет через
# ещё StaleThresholdMinutes минут тишины, а не немедленно.
if (-not $ForceTrigger) {
    Set-Content -Path $HeartbeatFile -Value (Get-Date -Format 'o')
}
Write-WatchdogLog $AlertLog "Watchdog cycle complete (connectivity_ok=$connOK)."
