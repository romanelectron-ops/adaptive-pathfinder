#Requires -Version 5.1
<#
.SYNOPSIS
    Снимок сетевого состояния ХОСТА + сравнение двух снимков (детектор утечек мутаций).

.DESCRIPTION
    Создан после инцидента: `go test ./internal/...` включал системный HTTP-прокси на
    127.0.0.1:<порт>, где sing-box не слушал, и на машине пропадал интернет во всех приложениях,
    читающих системные настройки Windows. Барьер hostguard закрывает это на уровне кода, но
    доверять коду «на слово» нельзя — снимок проверяет ФАКТ.

    Покрывает ровно те параметры, которые APF умеет менять:
      * системный HTTP-прокси (HKCU Internet Settings)  <- убивало сеть
      * таблица политик префиксов IPv6 (RFC 6724)       <- ломала выбор адреса назначения
      * политика Windows Firewall + правила APF-*       <- Kill Switch
      * DNS-серверы адаптеров
      * привязка IPv6 к адаптерам
      * автозапуск APF (HKCU Run)
      * слушатели портов APF и живые процессы
      * каталог данных APF в профиле пользователя (%APPDATA%\APF)

.EXAMPLE
    .\apf_host_snapshot.ps1 -Save before
    # ... прогон ...
    .\apf_host_snapshot.ps1 -Save after
    .\apf_host_snapshot.ps1 -Diff before,after

.EXAMPLE
    # Обёртка: снимок → команда → снимок → диф, с ненулевым кодом возврата при расхождении
    .\apf_host_snapshot.ps1 -Guard { go test ./internal/... }
#>
[CmdletBinding(DefaultParameterSetName = 'Show')]
param(
    [Parameter(ParameterSetName = 'Save', Mandatory)]
    [string]$Save,

    [Parameter(ParameterSetName = 'Diff', Mandatory)]
    [string[]]$Diff,

    [Parameter(ParameterSetName = 'Guard', Mandatory)]
    [scriptblock]$Guard,

    # Строковый эквивалент -Guard. Нужен потому, что `powershell -File` НЕ умеет передавать
    # scriptblock (он приходит строкой и падает на приведении типа). Для запуска из .bat/CI
    # используйте -Run "go test ./internal/...".
    [Parameter(ParameterSetName = 'Run', Mandatory)]
    [string]$Run,

    [string]$Dir = (Join-Path $env:TEMP 'apf_host_snapshots')
)

$ErrorActionPreference = 'Continue'

function Get-HostNetState {
    $s = [ordered]@{}

    # 1. Системный прокси (HKCU) — самый опасный параметр: не требует прав администратора
    #    и мгновенно обрывает весь WinINET/WinHTTP-трафик машины.
    $isKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try {
        $p = Get-ItemProperty -Path $isKey -ErrorAction Stop
        $s['proxy.enable']   = [string]$p.ProxyEnable
        $s['proxy.server']   = [string]$p.ProxyServer
        $s['proxy.autocfg']  = [string]$p.AutoConfigURL
    } catch {
        $s['proxy.enable'] = 'ERR'; $s['proxy.server'] = 'ERR'; $s['proxy.autocfg'] = 'ERR'
    }

    # 2. Таблица политик префиксов IPv6 (машинная, постоянная).
    try {
        $pp = Get-NetPrefixPolicy -ErrorAction Stop |
              Sort-Object Prefix |
              ForEach-Object { '{0}|{1}|{2}' -f $_.Prefix, $_.Precedence, $_.Label }
        $s['ipv6.prefixpolicy'] = ($pp -join ' ; ')
        $s['ipv6.prefixpolicy.count'] = [string]$pp.Count
    } catch {
        $s['ipv6.prefixpolicy'] = 'ERR'; $s['ipv6.prefixpolicy.count'] = 'ERR'
    }

    # 3. Firewall: политика профилей + правила APF-*
    try {
        $pol = (netsh advfirewall show allprofiles firewallpolicy) 2>$null |
               Select-String -Pattern 'Policy|политик' |
               ForEach-Object { ($_ -replace '\s+', ' ').Trim() }
        $s['fw.policy'] = ($pol -join ' ; ')
    } catch { $s['fw.policy'] = 'ERR' }
    try {
        $s['fw.apfRules'] = [string](Get-NetFirewallRule -DisplayName 'APF-*' -ErrorAction SilentlyContinue |
                                     Measure-Object).Count
    } catch { $s['fw.apfRules'] = 'ERR' }

    # 4. DNS-серверы адаптеров
    try {
        $dns = Get-DnsClientServerAddress -ErrorAction Stop |
               Where-Object { $_.ServerAddresses.Count -gt 0 } |
               Sort-Object InterfaceAlias, AddressFamily |
               ForEach-Object { '{0}/{1}={2}' -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ',') }
        $s['dns.servers'] = ($dns -join ' ; ')
    } catch { $s['dns.servers'] = 'ERR' }

    # 5. Привязка IPv6 к адаптерам
    try {
        $b6 = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
              Sort-Object Name |
              ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }
        $s['ipv6.binding'] = ($b6 -join ' ; ')
    } catch { $s['ipv6.binding'] = 'ERR' }

    # 6. Автозапуск APF
    try {
        $run = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction Stop
        $s['autorun.apf'] = [string]$run.APF
    } catch { $s['autorun.apf'] = '' }

    # 7. Живые процессы и слушатели портов APF
    try {
        $procs = Get-Process -Name 'sing-box', 'apf', 'apf-tray', 'apf-svc' -ErrorAction SilentlyContinue |
                 Sort-Object Name | ForEach-Object { $_.Name }
        $s['proc.apf'] = ($procs -join ',')
    } catch { $s['proc.apf'] = 'ERR' }
    try {
        $lst = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
               Where-Object { $_.LocalPort -in 1080, 1081, 8080, 9090 } |
               Sort-Object LocalPort | ForEach-Object { $_.LocalPort }
        $s['ports.listen'] = (($lst | Select-Object -Unique) -join ',')
    } catch { $s['ports.listen'] = 'ERR' }

    # 8. Интерфейс TUN
    try {
        $s['iface.apf0'] = [string](Get-NetAdapter -Name 'apf0' -ErrorAction SilentlyContinue).Status
    } catch { $s['iface.apf0'] = '' }

    # 9. Каталог данных APF в профиле пользователя (дефект D-E1).
    #
    #    Снимок объявлял «хост не изменён», хотя прогон тестов записывал в
    #    %APPDATA%\APF конфигурацию и трёхмегабайтный кэш узлов: сюда он просто
    #    не смотрел. Заявление о чистоте хоста было шире того, что проверялось,
    #    а на этом заявлении держится вся безопасность прогонов.
    #
    #    Сравниваем имена и размеры, а не содержимое: этого хватает, чтобы увидеть
    #    и появление файла, и его перезапись, и остаётся дёшево при кэше в мегабайты.
    foreach ($pair in @(
        @{ Key = 'data.appdata';   Path = (Join-Path $env:APPDATA      'APF') },
        @{ Key = 'data.localapp';  Path = (Join-Path $env:LOCALAPPDATA 'APF') },
        @{ Key = 'data.programdata'; Path = (Join-Path $env:ProgramData 'APF') }
    )) {
        try {
            if (Test-Path $pair.Path) {
                $files = Get-ChildItem $pair.Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                         Sort-Object FullName |
                         ForEach-Object { '{0}={1}' -f $_.FullName.Substring($pair.Path.Length).TrimStart('\'), $_.Length }
                $s[$pair.Key] = ($files -join ' ; ')
            } else {
                $s[$pair.Key] = '(нет каталога)'
            }
        } catch { $s[$pair.Key] = 'ERR' }
    }

    return $s
}

function Save-Snapshot([string]$name) {
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
    $state = Get-HostNetState
    $path = Join-Path $Dir "$name.json"
    ($state | ConvertTo-Json -Depth 4) | Out-File -FilePath $path -Encoding utf8
    Write-Host "Снимок сохранён: $path" -ForegroundColor Cyan
    return $path
}

function Compare-Snapshots($a, $b) {
    $keys = @($a.Keys) + @($b.Keys) | Select-Object -Unique | Sort-Object
    $changed = @()
    foreach ($k in $keys) {
        $va = [string]$a[$k]
        $vb = [string]$b[$k]
        if ($va -ne $vb) { $changed += [pscustomobject]@{ Key = $k; Before = $va; After = $vb } }
    }
    return $changed
}

function Show-Diff($changed) {
    if ($changed.Count -eq 0) {
        Write-Host "`n  ХОСТ НЕ ИЗМЕНЁН — 0 расхождений. Барьер держит.`n" -ForegroundColor Green
        return $true
    }
    Write-Host "`n  !!! ХОСТ ИЗМЕНЁН: $($changed.Count) расхождений !!!`n" -ForegroundColor Red
    foreach ($c in $changed) {
        Write-Host ("  [{0}]" -f $c.Key) -ForegroundColor Yellow
        Write-Host ("      было:  {0}" -f $c.Before)
        Write-Host ("      стало: {0}" -f $c.After)
    }
    Write-Host ""
    Write-Host "  Восстановление: source\tools\apf_emergency_restore.bat" -ForegroundColor Cyan
    Write-Host ""
    return $false
}

switch ($PSCmdlet.ParameterSetName) {

    'Save' { Save-Snapshot $Save | Out-Null }

    'Diff' {
        if ($Diff.Count -ne 2) { throw "-Diff требует ровно два имени снимка: -Diff before,after" }
        $pa = Join-Path $Dir "$($Diff[0]).json"
        $pb = Join-Path $Dir "$($Diff[1]).json"
        foreach ($p in @($pa, $pb)) { if (-not (Test-Path $p)) { throw "Нет снимка: $p" } }
        $a = @{}; (Get-Content $pa -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $a[$_.Name] = $_.Value }
        $b = @{}; (Get-Content $pb -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $b[$_.Name] = $_.Value }
        $ok = Show-Diff @(Compare-Snapshots $a $b)
        if (-not $ok) { exit 2 }
    }

    { $_ -in 'Guard', 'Run' } {
        Write-Host "=== СНИМОК ДО ===" -ForegroundColor Cyan
        $before = Get-HostNetState
        $before.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-26} {1}" -f $_.Key, $_.Value) }

        Write-Host "`n=== ВЫПОЛНЕНИЕ ===" -ForegroundColor Cyan
        $exitCode = 0
        try {
            if ($PSCmdlet.ParameterSetName -eq 'Guard') { & $Guard } else { Invoke-Expression $Run }
            $exitCode = $LASTEXITCODE
            if ($null -eq $exitCode) { $exitCode = 0 }
        } catch {
            Write-Host "Команда упала: $_" -ForegroundColor Red
            $exitCode = 1
        }

        Write-Host "`n=== СНИМОК ПОСЛЕ ===" -ForegroundColor Cyan
        $after = Get-HostNetState
        $ok = Show-Diff @(Compare-Snapshots $before $after)

        if (-not $ok) {
            Write-Host "ВЕРДИКТ: прогон ИЗМЕНИЛ состояние хоста — это дефект, а не норма." -ForegroundColor Red
            exit 2
        }
        Write-Host ("ВЕРДИКТ: хост чист. Код возврата команды: {0}" -f $exitCode) -ForegroundColor Green
        exit $exitCode
    }

    default {
        (Get-HostNetState).GetEnumerator() | ForEach-Object { Write-Host ("  {0,-26} {1}" -f $_.Key, $_.Value) }
    }
}

