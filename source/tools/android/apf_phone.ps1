#Requires -Version 5.1
<#
.SYNOPSIS
    Единая точка работы со стендом APF на смартфоне Android (этап Э-0 из
    docs/TZ_ANDROID_STAND_v1.1.md).

.DESCRIPTION
    Прав администратора НЕ требует. Работает через adb по USB.

    Почему телефон безопаснее ПК: ADB по USB не проходит через сетевой стек телефона.
    Даже полная потеря интернета на устройстве, «always-on VPN с блокировкой» и мёртвый
    TUN не рвут канал управления. Поэтому Restore ниже работает всегда.

    Действия (-Action):
      Check      устройство, версия, свободное место, состояние отладки. Ничего не меняет.
      Snapshot   снимок состояния сети и APF на телефоне в файл на D:. Ничего не меняет.
      Diff       сравнение двух снимков. Код возврата 2 = состояние разошлось.
      Test       проверка связности: сам телефон и трафик через SOCKS приложения.
      Logcat     фильтрованный лог APF с телефона.
      Install    установка APK (единственное действие, ставящее приложение).
      Uninstall  удаление приложения вместе с данными.
      Restore    АВАРИЙНОЕ восстановление связи на телефоне (см. §8 ТЗ).

    Все файлы пишутся только на диск D: — жёсткое правило проекта.

.EXAMPLE
    .\apf_phone.ps1 -Action Check
    .\apf_phone.ps1 -Action Snapshot -Name before
    .\apf_phone.ps1 -Action Diff -From before -To after
    .\apf_phone.ps1 -Action Restore
#>
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Snapshot', 'Diff', 'Test', 'Logcat', 'Install', 'Uninstall', 'Restore')]
    [string]$Action = 'Check',

    # Серийный номер устройства. Нужен, только если подключено больше одного.
    [string]$Serial,

    # Имя снимка для Snapshot; From/To — для Diff.
    [string]$Name = 'snap',
    [string]$From,
    [string]$To,

    # Куда складывать снимки и логи (внутри папки проекта — правило проекта).
    [string]$WorkDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand\phone')),

    # Путь к APK для Install.
    [string]$ApkPath,

    [string]$Package = 'com.apf.app',

    # Локальный порт SOCKS приложения для проверки Test.
    [int]$SocksPort = 10808,

    # Не спрашивать подтверждение (Restore, Uninstall).
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ─── Поиск adb ────────────────────────────────────────────────────────────────

function Resolve-Adb {
    $cmd = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        (Join-Path $env:ANDROID_HOME 'platform-tools\adb.exe'),
        'C:\Android\Sdk\platform-tools\adb.exe',
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe')
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

$adb = Resolve-Adb
if (-not $adb) {
    Write-Host '  adb не найден. Установите Android SDK Platform-Tools либо задайте ANDROID_HOME.' -ForegroundColor Red
    exit 1
}

# ─── Безопасный вызов adb ─────────────────────────────────────────────────────
#
# ПОЧЕМУ ЗДЕСЬ ГАСИТСЯ ErrorActionPreference (дефект D-T2). В PowerShell 5.1 при
# $ErrorActionPreference = 'Stop' любая строка, которую нативная программа пишет в stderr,
# оборачивается в ErrorRecord и ПРЕРЫВАЕТ скрипт. adb пишет туда не только отказы, но и
# обычные сообщения — например «* daemon not running; starting now at tcp:5037» при первом
# за сеанс вызове. Для этих обёрток вывод adb — это ДАННЫЕ, а не событие отказа; решение об
# успехе принимает вызывающая ветка.
#
# Invoke-AdbRaw существует отдельно от Invoke-Adb потому, что поиск устройств происходит ДО
# того, как устройство выбрано, и добавлять «-s <серийник>» там нечем. Раньше Get-Devices
# звал adb напрямую, мимо защиты, и запуск демона убивал скрипт на первом же действии.
function Invoke-AdbRaw {
    param([string[]]$AdbArgs)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # ErrorRecord разворачивается через Exception.Message, а не через "$_": у записей
        # NativeCommandError строковое представление даёт имя типа
        # (System.Management.Automation.RemoteException), и в выводе появлялась строка-мусор,
        # похожая на настоящую ошибку. Пустые строки отбрасываются.
        & $adb @AdbArgs 2>&1 | ForEach-Object {
            $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
            if ($line -and $line.Trim()) { $line }
        }
    } finally {
        $ErrorActionPreference = $old
    }
}

# ─── Выбор устройства ─────────────────────────────────────────────────────────

function Get-Devices {
    # Демон поднимается явно и заранее: иначе его приветствие попадёт в вывод «devices»
    # вперемешку со списком устройств.
    $null = Invoke-AdbRaw -AdbArgs @('start-server')
    $out = Invoke-AdbRaw -AdbArgs @('devices')
    $list = @()
    foreach ($line in $out) {
        if ($line -match '^(\S+)\s+(device|unauthorized|offline)\s*$') {
            $list += [pscustomobject]@{ Serial = $Matches[1]; State = $Matches[2] }
        }
    }
    return $list
}

function Resolve-Serial {
    $devices = @(Get-Devices)
    if ($devices.Count -eq 0) {
        Write-Host '  Устройств не найдено. Подключите телефон по USB и разрешите отладку.' -ForegroundColor Red
        exit 1
    }
    $bad = @($devices | Where-Object { $_.State -ne 'device' })
    foreach ($b in $bad) {
        Write-Host ('  Устройство {0}: состояние "{1}" — подтвердите отладку на экране телефона.' -f $b.Serial, $b.State) -ForegroundColor Yellow
    }
    $ok = @($devices | Where-Object { $_.State -eq 'device' })
    if ($ok.Count -eq 0) { Write-Host '  Нет ни одного готового устройства.' -ForegroundColor Red; exit 1 }

    if ($Serial) {
        if ($ok.Serial -notcontains $Serial) {
            Write-Host ('  Устройство {0} не найдено среди готовых.' -f $Serial) -ForegroundColor Red
            exit 1
        }
        return $Serial
    }
    if ($ok.Count -gt 1) {
        Write-Host '  Подключено несколько устройств — укажите -Serial:' -ForegroundColor Red
        $ok | ForEach-Object { Write-Host ('    {0}' -f $_.Serial) }
        exit 1
    }
    return $ok[0].Serial
}

$dev = Resolve-Serial

# Обёртка с привязкой к выбранному устройству. Защита от stderr — в Invoke-AdbRaw выше.
#
# Из-за отсутствия этой защиты при неудачной установке скрипт умирал прямо в обёртке: ветка
# диагностики (подсказка про запрет установки по USB в MIUI) не успевала напечататься, а
# вместо неё пользователь получал стек PowerShell. Тот же изъян обрывал бы аварийный Restore
# на середине — а он обязан доработать до конца всегда.
#
# Параметр НЕ называется Args: $Args — автоматическая переменная PowerShell, и объявление
# одноимённого параметра ломает привязку — adb получал пустой список и печатал свою справку.
function Invoke-Adb {
    param([string[]]$AdbArgs)
    Invoke-AdbRaw -AdbArgs (@('-s', $dev) + $AdbArgs)
}

function Adb    { param([Parameter(ValueFromRemainingArguments = $true)]$a) Invoke-Adb -AdbArgs $a }
function Shell  { param([string]$cmd) (Invoke-Adb -AdbArgs @('shell', $cmd)) -join "`n" }
function Shell1 { param([string]$cmd) (Shell $cmd).Trim() }

function Say     { param([string]$s) Write-Host $s }
function SayOK   { param([string]$s) Write-Host $s -ForegroundColor Green }
function SayWarn { param([string]$s) Write-Host $s -ForegroundColor Yellow }
function SayErr  { param([string]$s) Write-Host $s -ForegroundColor Red }

Write-Host ''
Write-Host ('=== APF · телефон {0} : {1} ===' -f $dev, $Action) -ForegroundColor Cyan
Write-Host ''

# ─── Снимок состояния ─────────────────────────────────────────────────────────

# Снимаем ровно то, что APF способен изменить. Каждая строка — «ключ<TAB>значение»,
# чтобы Diff был построчным и человекочитаемым.
function New-Snapshot {
    $lines = New-Object System.Collections.Generic.List[string]
    function Add($k, $v) {
        $val = ($v -replace '\s+', ' ').Trim()
        if (-not $val) { $val = '<пусто>' }
        $lines.Add(("{0}`t{1}" -f $k, $val)) | Out-Null
    }

    Add 'device.model'          (Shell1 'getprop ro.product.model')
    Add 'device.android'        (Shell1 'getprop ro.build.version.release')

    # Системная защита — то, что на Android заменяет Kill Switch.
    Add 'vpn.always_on_app'     (Shell1 'settings get secure always_on_vpn_app')
    Add 'vpn.always_on_lockdown' (Shell1 'settings get secure always_on_vpn_lockdown')

    # Глобальный HTTP-прокси устройства.
    Add 'proxy.http'            (Shell1 'settings get global http_proxy')

    # Туннельные интерфейсы: их наличие вне сеанса испытания — остаточное состояние.
    Add 'net.tun'               (Shell1 "ip -o link show 2>/dev/null | grep -E 'tun|ppp' | awk '{print `$2}' | tr -d ':' | sort | tr '\n' ','")
    # Маршрут по умолчанию (дефект D-T1). «ip route show default» на Android возвращает
    # НЕ маршрут по умолчанию: система держит его в отдельной таблице на каждую сеть
    # (multinetwork routing), а в main-таблице лежит лишь link-маршрут подсети. Снимок
    # фиксировал этот link-маршрут, поэтому пропажу настоящего default он бы не заметил —
    # то есть главный признак «телефон остался без связи» не попадал в Diff вовсе.
    # Номер таблицы вырезается: он равен netId и меняется при каждом переподключении Wi-Fi,
    # из-за чего давал бы расхождения на пустом месте.
    Add 'net.default_route'     (Shell1 "ip route show table all 2>/dev/null | grep '^default' | sed 's/ table [0-9]*//' | sort -u | tr '\n' ';'")
    Add 'net.wifi_state'        (Shell1 'settings get global wifi_on')
    Add 'net.airplane'          (Shell1 'settings get global airplane_mode_on')

    # Приложение и его процессы.
    Add 'apf.installed'         (Shell1 ("pm list packages {0} | head -n 1" -f $Package))
    Add 'apf.version'           (Shell1 ("dumpsys package {0} | grep versionName | head -n 1" -f $Package))
    Add 'apf.processes'         (Shell1 "ps -A 2>/dev/null | grep -E 'singbox|sing-box|com.apf' | wc -l")

    return $lines
}

function Snapshot-Path { param([string]$n) Join-Path $WorkDir ("snapshot_{0}.txt" -f $n) }

# ─── Действия ─────────────────────────────────────────────────────────────────

switch ($Action) {

'Check' {
    Say ('  adb:              {0}' -f $adb)
    Say ('  Устройство:       {0}' -f $dev)
    Say ('  Модель:           {0} {1}' -f (Shell1 'getprop ro.product.manufacturer'), (Shell1 'getprop ro.product.model'))
    Say ('  Android:          {0} (API {1})' -f (Shell1 'getprop ro.build.version.release'), (Shell1 'getprop ro.build.version.sdk'))
    Say ('  Прошивка:         {0}' -f (Shell1 'getprop ro.build.version.incremental'))
    Say ('  ABI:              {0}' -f (Shell1 'getprop ro.product.cpu.abi'))
    Say ''
    Say ('  Свободно в /data: {0}' -f (Shell1 "df -h /data | tail -n 1 | awk '{print `$4}'"))
    Say ('  APF установлен:   {0}' -f $(if ((Shell1 ("pm list packages {0}" -f $Package))) { 'да' } else { 'нет' }))
    Say ('  always-on VPN:    {0} (lockdown: {1})' -f (Shell1 'settings get secure always_on_vpn_app'), (Shell1 'settings get secure always_on_vpn_lockdown'))
    $tun = Shell1 "ip -o link show 2>/dev/null | grep -E 'tun|ppp' | wc -l"
    Say ('  tun-интерфейсов:  {0}' -f $tun)
    Say ''
    if ($tun -ne '0') { SayWarn '  ! На телефоне уже есть туннельный интерфейс — возможно, работает другой VPN.' }
    SayOK '  Устройство готово к работе.'
    Write-Host ''
}

'Snapshot' {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $lines = New-Snapshot
    $path = Snapshot-Path $Name
    $lines | Out-File -FilePath $path -Encoding utf8
    $lines | ForEach-Object { Say ('  {0}' -f $_) }
    Write-Host ''
    SayOK ('  Снимок "{0}" сохранён: {1}' -f $Name, $path)
    Write-Host ''
}

'Diff' {
    if (-not $From -or -not $To) { SayErr '  Нужны -From и -To (имена снимков).'; exit 1 }
    $pf = Snapshot-Path $From
    $pt = Snapshot-Path $To
    foreach ($p in @($pf, $pt)) {
        if (-not (Test-Path $p)) { SayErr ('  Нет снимка: {0}' -f $p); exit 1 }
    }

    $a = @{}; Get-Content $pf -Encoding UTF8 | ForEach-Object { $kv = $_ -split "`t", 2; if ($kv.Count -eq 2) { $a[$kv[0]] = $kv[1] } }
    $b = @{}; Get-Content $pt -Encoding UTF8 | ForEach-Object { $kv = $_ -split "`t", 2; if ($kv.Count -eq 2) { $b[$kv[0]] = $kv[1] } }

    $keys = @($a.Keys + $b.Keys | Sort-Object -Unique)
    $diff = 0
    foreach ($k in $keys) {
        $va = $a[$k]; $vb = $b[$k]
        if ($va -ne $vb) {
            $diff++
            SayWarn ('  {0}' -f $k)
            Say     ('      было:  {0}' -f $va)
            Say     ('      стало: {0}' -f $vb)
        }
    }
    Write-Host ''
    if ($diff -eq 0) { SayOK ('  СОСТОЯНИЕ СОВПАДАЕТ: {0} → {1}, расхождений 0.' -f $From, $To); Write-Host ''; exit 0 }
    SayErr ('  РАСХОЖДЕНИЙ: {0}. Остаточное состояние на телефоне после испытания.' -f $diff)
    Write-Host ''
    exit 2
}

'Test' {
    # 1. Своя связь телефона — ICMP, не требует посторонних бинарников в системе.
    Say '  [1/3] Связь самого телефона:'
    $ping = Shell 'ping -c 2 -W 3 1.1.1.1'
    if ($ping -match '(\d+)% packet loss' -and [int]$Matches[1] -lt 100) {
        SayOK ('        IP-связь есть ({0}% потерь)' -f $Matches[1])
    } else {
        SayErr '        IP-СВЯЗИ НЕТ'
        Say ('        {0}' -f ($ping -split "`n" | Select-Object -First 3 | Out-String).Trim()
        )
    }

    Say '  [2/3] Разрешение имён:'
    $dns = Shell 'ping -c 1 -W 3 dns.google'
    # Скобки берутся ПЕРВЫЕ, а не последние (дефект D-T4). Ответ ping выглядит так:
    #   PING dns.google (8.8.8.8) 56(84) bytes of data.
    # Жадная «.*» доходила до последней скобки и метрика печатала «84» — размер пакета
    # вместо разрешённого адреса. Доказательство работы DNS от этого не страдало, но в
    # протокол приёмки попадало бессмысленное число. [^(]* не даёт уйти за первую скобку.
    if ($dns -match 'PING [^(]*\(([\d\.]+)\)') { SayOK ('        DNS работает: dns.google → {0}' -f $Matches[1]) }
    else { SayErr '        DNS НЕ РАБОТАЕТ' }

    # 3. Трафик через SOCKS приложения. Проверяем С ПК: пробрасываем порт по USB
    # и ходим curl-ом Windows. На телефоне никаких дополнительных программ не нужно.
    Say ('  [3/3] Прокси APF (127.0.0.1:{0} на телефоне):' -f $SocksPort)
    $localPort = $SocksPort
    $null = Adb forward ("tcp:{0}" -f $localPort) ("tcp:{0}" -f $SocksPort)
    try {
        $direct = (& curl.exe -s --max-time 15 https://api.ipify.org) 2>&1
        $viaSocks = (& curl.exe -s --max-time 20 --socks5-hostname ("127.0.0.1:{0}" -f $localPort) https://api.ipify.org) 2>&1
        Say ('        внешний IP этого ПК напрямую: {0}' -f $(if ($direct) { $direct } else { '<не получен>' }))
        Say ('        внешний IP через прокси APF:  {0}' -f $(if ($viaSocks) { $viaSocks } else { '<не получен>' }))
        if ($viaSocks -and $direct -and $viaSocks -ne $direct) {
            SayOK '        ПРОКСИ РАБОТАЕТ: адрес отличается от прямого.'
        } elseif ($viaSocks -and $direct -and $viaSocks -eq $direct) {
            SayWarn '        Адреса совпали — трафик, похоже, идёт мимо туннеля.'
        } else {
            SayErr '        Через прокси ответа нет: APF не подключён либо слушатель не поднят.'
        }
    } finally {
        $null = Adb forward --remove ("tcp:{0}" -f $localPort)
    }
    Write-Host ''
}

'Logcat' {
    Say '  Ctrl+C для выхода. Показываются только записи APF.'
    Write-Host ''
    & $adb -s $dev logcat -v time APFVpnService:V APFMain:V APFBoot:V GoLog:V '*:S'
}

'Install' {
    if (-not $ApkPath) { SayErr '  Нужен -ApkPath <файл.apk>.'; exit 1 }
    if (-not (Test-Path $ApkPath)) { SayErr ('  Файл не найден: {0}' -f $ApkPath); exit 1 }
    Say ('  Ставлю {0} ({1:N1} МБ) ...' -f $ApkPath, ((Get-Item $ApkPath).Length / 1MB))
    $out = Adb install -r -t $ApkPath
    $out | ForEach-Object { Say ('    {0}' -f $_) }
    if ($out -match 'Success') {
        SayOK '  Установлено.'
        Write-Host ''
        exit 0
    }
    SayErr '  Установка не удалась.'
    if ($out -match 'INSTALL_FAILED_USER_RESTRICTED') {
        Write-Host ''
        SayWarn '  Причина не в APK — установку запрещает прошивка.'
        SayWarn '  Проверено: ограничений Android (dumpsys user) на устройстве нет, запрет ставит MIUI.'
        Write-Host ''
        Say     '  ПУТЬ 1 (основной). Включите на телефоне:'
        Say     '    Настройки → Расширенные настройки → Для разработчиков →'
        Say     '    «Установка через USB» (Install via USB)'
        Write-Host ''
        Say     '  Если переключатель не поддаётся:'
        Say     '    • нужен вход в аккаунт Xiaomi и вставленная SIM-карта;'
        Say     '    • на некоторых прошивках включается только при интернете через мобильную сеть;'
        Say     '    • рядом полезно включить «Отключить проверку MIUI оптимизации».'
        Write-Host ''

        # Путь 2. MIUI запрещает установку ИМЕННО ПО USB — это отдельный хук в установщике,
        # завязанный на пункт меню разработчика. Установка тем же установщиком из файла,
        # уже лежащего на устройстве, идёт другой дорогой и часто проходит. Файл кладём
        # заранее, чтобы человеку осталось одно касание. Запустить установку за него нельзя
        # и не нужно: подтверждение всё равно спрашивается на экране телефона.
        $onDevice = '/sdcard/Download/apf-debug.apk'
        Say     '  ПУТЬ 2 (в обход USB). Кладу файл на телефон ...'
        $null = Adb push $ApkPath $onDevice
        $check = Shell ("ls -l {0} 2>/dev/null" -f $onDevice)
        if ($check -match 'apf-debug\.apk') {
            SayOK ('    Готово: {0}' -f $onDevice)
            Write-Host ''
            Say   '    На телефоне: Проводник → Загрузки → apf-debug.apk → Установить.'
            Say   '    Установщик спросит разрешение «Устанавливать неизвестные приложения»'
            Say   '    для Проводника — его нужно выдать.'
        } else {
            SayWarn '    Не удалось положить файл на устройство.'
        }
        Write-Host ''
        Say     '  Установить с ПК без участия человека нельзя: проверка серверная.'
    } elseif ($out -match 'INSTALL_FAILED_UPDATE_INCOMPATIBLE|INSTALL_FAILED_VERSION_DOWNGRADE') {
        SayWarn '  На телефоне стоит сборка с другой подписью или более высокой версией.'
        SayWarn ('  Удалите её: {0} -Action Uninstall -Force' -f $MyInvocation.MyCommand.Name)
    } elseif ($out -match 'INSTALL_FAILED_NO_MATCHING_ABIS') {
        SayWarn '  APK собран под другую архитектуру. Сборка рассчитана на arm64-v8a.'
    } elseif ($out -match 'INSTALL_FAILED_INSUFFICIENT_STORAGE') {
        SayWarn '  Не хватает места в /data. Освободите не менее 100 МБ.'
    }
    Write-Host ''
    exit 1
}

'Uninstall' {
    if (-not $Force) {
        $ans = Read-Host ('  Удалить {0} вместе с данными? (yes/no)' -f $Package)
        if ($ans -ne 'yes') { SayWarn '  Отменено.'; exit 0 }
    }
    Adb uninstall $Package | ForEach-Object { Say ('    {0}' -f $_) }
    SayOK '  Удалено.'
    Write-Host ''
}

'Restore' {
    # Аварийное восстановление. Работает и тогда, когда интернета на телефоне нет вовсе:
    # всё идёт по USB, а не по сети.
    if (-not $Force) {
        SayWarn '  Будет выполнено:'
        Say     '    1) остановка приложения APF'
        Say     '    2) снятие «Always-on VPN» и блокировки соединений без VPN'
        Say     '    3) сброс глобального HTTP-прокси устройства'
        Say     '    4) очистка данных приложения APF'
        Write-Host ''
        $ans = Read-Host '  Продолжить? (yes/no)'
        if ($ans -ne 'yes') { SayWarn '  Отменено.'; exit 0 }
    }

    Say '  [1/4] Останавливаю APF ...'
    $null = Shell ("am force-stop {0}" -f $Package)

    Say '  [2/4] Снимаю always-on VPN ...'
    $null = Shell 'settings put secure always_on_vpn_lockdown 0'
    $null = Shell 'settings delete secure always_on_vpn_app'

    Say '  [3/4] Сбрасываю глобальный прокси ...'
    $null = Shell 'settings put global http_proxy :0'

    Say '  [4/4] Чищу данные приложения ...'
    $null = Shell ("pm clear {0}" -f $Package)

    Write-Host ''
    Say '  Проверка связи:'
    $ping = Shell 'ping -c 2 -W 3 1.1.1.1'
    if ($ping -match '(\d+)% packet loss' -and [int]$Matches[1] -lt 100) {
        SayOK '  СВЯЗЬ ВОССТАНОВЛЕНА.'
    } else {
        SayErr '  Связи всё ещё нет. Дальше вручную на телефоне:'
        Say    '    Настройки → Подключение и общий доступ → VPN → выключить APF'
        Say    '    и снять «Блокировать соединения без VPN».'
        Say    ('    Если не помогло: {0} -Action Uninstall -Force' -f $MyInvocation.MyCommand.Name)
        Write-Host ''
        exit 2
    }
    Write-Host ''
}

}

exit 0
