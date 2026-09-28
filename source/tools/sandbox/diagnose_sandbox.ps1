#Requires -Version 5.1
<#
.SYNOPSIS
    Диагностика: почему не включается Windows Sandbox (Containers-DisposableClientVM),
    и есть ли готовая замена стенда (Hyper-V).

.DESCRIPTION
    ТРЕБУЕТ ПРАВ АДМИНИСТРАТОРА. НИЧЕГО НЕ МЕНЯЕТ — только читает состояние.
    Весь вывод пишется в файл-отчёт на диске D:, поэтому результат виден и тогда,
    когда окно с повышением прав закрылось.

    Каждый раздел обёрнут в try/catch: сбой одного раздела не должен уносить отчёт
    целиком. Скрипт, который умирает молча, бесполезен — этот отказывается так делать.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\diagnose_sandbox.ps1
#>
[CmdletBinding()]
param(
    # Путь отчёта. Пусто — рядом со скриптом (см. ниже, почему не в значении по умолчанию).
    [string]$OutFile,
    # Префикс времени для выборки из CBS.log (когда был сбой включения).
    [string]$CbsTimePrefix = '2026-08-04 01:5'
)

# Намеренно НЕ 'Stop': разделы независимы, отчёт должен дойти до конца.
$ErrorActionPreference = 'Continue'

# $PSScriptRoot на этапе привязки параметров пуст (PowerShell 5.1, запуск через -File),
# поэтому `Join-Path $PSScriptRoot ...` в значении по умолчанию валит скрипт до первой строки.
# Путь считаем в теле, с двумя запасными источниками.
if (-not $OutFile) {
    $root = $PSScriptRoot
    if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Definition }
    if (-not $root) { $root = (Get-Location).Path }
    $OutFile = Join-Path $root 'sandbox_diagnosis.txt'
}

$report = New-Object System.Collections.Generic.List[string]
function Add-Line { param([string]$s = '') ; $report.Add($s) | Out-Null ; Write-Host $s }
function Add-Section {
    param([string]$Title, [scriptblock]$Body)
    Add-Line ''
    Add-Line ('=== {0} ===' -f $Title)
    try { & $Body }
    catch { Add-Line ('  [РАЗДЕЛ УПАЛ] {0}' -f $_.Exception.Message) }
}

Add-Line ('Отчёт диагностики Windows Sandbox. Машина: {0}' -f $env:COMPUTERNAME)

Add-Section 'Права и ОС' {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
    Add-Line ('  Администратор:  {0}' -f $admin)
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Line ('  Редакция:       {0}' -f $os.Caption)
    Add-Line ('  Сборка:         {0}.{1}' -f $os.BuildNumber, (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)
    Add-Line ('  Загружена:      {0}' -f $os.LastBootUpTime)
    if (-not $admin) { Add-Line '  ! Без прав администратора большая часть разделов пуста.' }
}

Add-Section 'Состояние компонентов' {
    $names = @(
        'Containers-DisposableClientVM',
        'VirtualMachinePlatform',
        'HypervisorPlatform',
        'Microsoft-Hyper-V',
        'Microsoft-Hyper-V-All',
        'Microsoft-Hyper-V-Management-PowerShell'
    )
    foreach ($n in $names) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction Stop
            Add-Line ('  {0,-42} {1}' -f $n, $f.State)
        } catch {
            Add-Line ('  {0,-42} ОШИБКА: {1}' -f $n, $_.Exception.Message)
        }
    }
}

Add-Section 'Целостность хранилища компонентов (CheckHealth — только чтение)' {
    # CheckHealth читает уже записанный флаг повреждения; секунды, ничего не чинит.
    $out = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1
    Add-Line ('  код возврата dism.exe: {0}' -f $LASTEXITCODE)
    $out | ForEach-Object { Add-Line ('  {0}' -f $_) }
}

Add-Section 'Пакеты хранилища, относящиеся к песочнице' {
    $pkgs = Get-WindowsPackage -Online -ErrorAction Stop |
            Where-Object { $_.PackageName -match 'DisposableClientVM|Sandbox' }
    if (-not $pkgs) { Add-Line '  НИ ОДНОГО пакета Containers-DisposableClientVM в хранилище не найдено.' }
    else { $pkgs | ForEach-Object { Add-Line ('  {0,-12} {1}' -f $_.PackageState, $_.PackageName) } }
}

Add-Section 'Политики, способные запретить песочницу' {
    $keys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            Add-Line ('  {0}' -f $k)
            (Get-ItemProperty $k).PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object { Add-Line ('      {0} = {1}' -f $_.Name, ($_.Value -join ',')) }
        } else {
            Add-Line ('  {0}  — нет' -f $k)
        }
    }
}

Add-Section ('CBS.log, окно "{0}"' -f $CbsTimePrefix) {
    $cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    if (-not (Test-Path $cbs)) { Add-Line '  CBS.log отсутствует'; return }
    # Открываем с общим доступом на чтение И запись: службу обслуживания лог держит открытым,
    # обычный Get-Content на нём падает. Именно на этом умер предыдущий заход.
    $fs = [System.IO.File]::Open($cbs, [System.IO.FileMode]::Open,
                                 [System.IO.FileAccess]::Read,
                                 [System.IO.FileShare]::ReadWrite)
    try {
        $sr = New-Object System.IO.StreamReader($fs)
        $inWindow = $false; $kept = 0; $seen = 0
        while (-not $sr.EndOfStream) {
            $line = $sr.ReadLine(); $seen++
            if ($line.StartsWith($CbsTimePrefix)) { $inWindow = $true }
            elseif ($inWindow -and $line -match '^\d{4}-\d{2}-\d{2} ' -and -not $line.StartsWith($CbsTimePrefix)) { $inWindow = $false }
            if ($inWindow -and $line -match 'Error|error|0x80188306|DisposableClientVM|Sandbox|Failed|failure|missing|corrupt|payload|Resolve|denied') {
                if ($kept -lt 60) { Add-Line ('  {0}' -f $line); $kept++ }
            }
        }
        Add-Line ('  (просмотрено строк: {0}, отобрано: {1})' -f $seen, $kept)
        if ($kept -eq 0) { Add-Line '  Совпадений нет — лог мог ротироваться.' }
    } finally { $fs.Dispose() }
}

Add-Section 'Готовность запасного стенда: Hyper-V' {
    $hv = Get-Command Get-VM -ErrorAction SilentlyContinue
    Add-Line ('  Модуль Hyper-V (Get-VM): {0}' -f $(if ($hv) { 'есть' } else { 'НЕТ' }))
    if ($hv) {
        $sw = Get-VMSwitch -ErrorAction SilentlyContinue
        if ($sw) { $sw | ForEach-Object { Add-Line ('    коммутатор: {0,-24} тип {1}' -f $_.Name, $_.SwitchType) } }
        else { Add-Line '    виртуальных коммутаторов нет' }
        $vms = Get-VM -ErrorAction SilentlyContinue
        if ($vms) { $vms | ForEach-Object { Add-Line ('    ВМ: {0,-30} {1}' -f $_.Name, $_.State) } }
        else { Add-Line '    ВМ нет' }
    }
    $svc = Get-Service vmms -ErrorAction SilentlyContinue
    Add-Line ('  Служба vmms:             {0}' -f $(if ($svc) { $svc.Status } else { 'нет' }))
}

$report | Out-File -FilePath $OutFile -Encoding utf8
Write-Host ''
Write-Host ('ОТЧЁТ: {0}' -f $OutFile) -ForegroundColor Green
exit 0
