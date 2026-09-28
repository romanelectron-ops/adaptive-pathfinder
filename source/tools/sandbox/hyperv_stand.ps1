#Requires -Version 5.1
<#
.SYNOPSIS
    Управление изолированным стендом APF на Hyper-V (уровень 3 из tools\sandbox\README.md).

.DESCRIPTION
    ТРЕБУЕТ ПРАВ АДМИНИСТРАТОРА. Управляет ТОЛЬКО виртуальной машиной.
    Этот скрипт НИКОГДА не запускает apf.exe / apf-tray.exe / apf-svc — ни на хосте, ни в госте.
    Запуск APF — ручное действие внутри гостя, после hyperv_bootstrap.ps1.

    Почему уровень 3, а не Windows Sandbox: на этой машине компонент
    Containers-DisposableClientVM включить нельзя — его пакета нет в хранилище компонентов
    (DISM: CBS HRESULT=0x80188306 на финализации; при этом «повреждение хранилища не
    обнаружено», т.е. образ просто урезан). Hyper-V установлен полностью и работает,
    а по README именно он обязателен для финальной приёмки Gate A: только он даёт
    перезагрузки, crash-recovery, персистентность WFP и откат по снимку.

    Действия (-Action):
      Check       предпосылки и текущее состояние (по умолчанию; ничего не меняет)
      Build       собрать бинарники в source\bin (сборка хост не меняет и правилом не запрещена)
      Create      создать ВМ поколения 2 с подключённым установочным ISO
      Provision   упаковать исходники и передать их в гостя по VMBus (без сети)
      Checkpoint  снять снимок 'clean' — точка отката перед прогоном
      Reset       откатиться к снимку 'clean'
      Start/Stop  включить / корректно выключить
      Kill        жёсткое выключение питания (сценарий crash-recovery)
      Remove      удалить ВМ вместе с диском (спрашивает подтверждение)

.EXAMPLE
    # 1. Посмотреть, что есть:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\hyperv_stand.ps1 -Action Check

.EXAMPLE
    # 2. Создать стенд (нужен установочный образ Windows 11):
    .\hyperv_stand.ps1 -Action Create -IsoPath 'D:\iso\Win11_25H2.iso'

.EXAMPLE
    # 3. После установки Windows в госте — передать исходники и снять снимок:
    .\hyperv_stand.ps1 -Action Provision
    .\hyperv_stand.ps1 -Action Checkpoint
#>
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Build', 'Create', 'Provision', 'Checkpoint', 'Reset', 'Start', 'Stop', 'Kill', 'Remove')]
    [string]$Action = 'Check',

    [string]$Name = 'APF-STAND',

    # Установочный образ Windows. Нужен только для -Action Create.
    [string]$IsoPath,

    # ВРЕМЕННО остаётся на D:\APF-Stand (не внутри папки проекта, вопреки общему
    # правилу проекта) — существующая ВМ APF-STAND физически лежит именно там
    # (~35 ГБ: APF-STAND.vhdx + differencing-диск + чекпоинт), а перенести её
    # через Move-VMStorage не вышло 2026-08-31: команда отказала на предварительной
    # проверке места (нужно ~35 ГБ, свободно на D: было ~10.7-29.7 ГБ — не хватило
    # 5-8 ГБ). Перенос отложен явным решением до появления места. Когда ВМ
    # переедет — поменять этот default на такой же (Join-Path $PSScriptRoot
    # '..\..\..\..\..\APF-Stand'), как у остальных скриптов в tools/android/.
    [string]$StandRoot = 'D:\APF-Stand',

    [int]$MemoryGB = 4,
    [int]$DiskGB   = 64,

    # 'Default Switch' — NAT Hyper-V: у гостя есть интернет, но нет доступа в ЛВС хоста.
    [string]$SwitchName = 'Default Switch',

    # Корень исходников для -Action Provision.
    [string]$SourceRoot,

    [string]$CheckpointName = 'clean',

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot пуст на этапе привязки параметров (PS 5.1, запуск через -File),
# поэтому пути, зависящие от расположения скрипта, считаем здесь.
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $SourceRoot) { $SourceRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path }  # ...\apf-dist\source

$vhdPath     = Join-Path $StandRoot ('{0}.vhdx' -f $Name)
$payloadZip  = Join-Path $StandRoot ('{0}-src.zip' -f $Name)
$guestDrop   = 'C:\apf-drop'          # куда кладём файлы внутри гостя
$markerName  = 'APF-STAND.marker'

function Say      { param([string]$s) ; Write-Host $s }
function SayOK    { param([string]$s) ; Write-Host $s -ForegroundColor Green }
function SayWarn  { param([string]$s) ; Write-Host $s -ForegroundColor Yellow }
function SayErr   { param([string]$s) ; Write-Host $s -ForegroundColor Red }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Assert-Ready {
    if (-not (Test-Admin)) {
        SayErr '  ТРЕБУЮТСЯ ПРАВА АДМИНИСТРАТОРА (Hyper-V управляется только из-под них).'
        exit 1
    }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        SayErr '  Модуль Hyper-V недоступен. Включите Microsoft-Hyper-V-All.'
        exit 1
    }
    $svc = Get-Service vmms -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        SayErr ('  Служба vmms не запущена (состояние: {0}).' -f $(if ($svc) { $svc.Status } else { 'нет' }))
        exit 1
    }
}

function Get-Stand { Get-VM -Name $Name -ErrorAction SilentlyContinue }

function Assert-Stand {
    $vm = Get-Stand
    if (-not $vm) {
        SayErr ('  ВМ "{0}" не найдена. Сначала: -Action Create -IsoPath <образ Windows>' -f $Name)
        exit 1
    }
    $vm
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host ('=== Стенд APF на Hyper-V: {0} ===' -f $Action) -ForegroundColor Cyan
Write-Host ''

switch ($Action) {

'Check' {
    Say ('  Администратор:      {0}' -f (Test-Admin))
    $svc = Get-Service vmms -ErrorAction SilentlyContinue
    Say ('  Служба vmms:        {0}' -f $(if ($svc) { $svc.Status } else { 'нет' }))
    if (-not (Test-Admin)) {
        SayWarn '  Без прав администратора дальше только предположения — перезапустите от админа.'
        Write-Host ''
        exit 1
    }
    Assert-Ready

    $free = (Get-PSDrive -Name $StandRoot.Substring(0,1) -ErrorAction SilentlyContinue).Free
    Say ('  Свободно на {0}:     {1} ГБ (диск ВМ растёт по мере наполнения)' -f $StandRoot.Substring(0,2), [math]::Round($free/1GB,1))

    Say ''
    Say '  Виртуальные коммутаторы:'
    Get-VMSwitch | ForEach-Object { Say ('    {0,-26} {1}' -f $_.Name, $_.SwitchType) }
    $sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if (-not $sw) { SayWarn ('  ! Коммутатор "{0}" не найден — задайте -SwitchName' -f $SwitchName) }

    Say ''
    $vm = Get-Stand
    if (-not $vm) {
        SayWarn ('  ВМ "{0}" ещё не создана.' -f $Name)
        Say ''
        Say '  Дальше нужен установочный образ Windows 11 (ISO). Его же можно использовать'
        Say '  как источник для восстановления Windows Sandbox:'
        Say '    DISM /Online /Enable-Feature /FeatureName:Containers-DisposableClientVM /All ^'
        Say '         /Source:wim:<буква>:\sources\install.wim:1 /LimitAccess'
        Say ''
        Say ('  Создание стенда:  .\hyperv_stand.ps1 -Action Create -IsoPath "<путь к ISO>"')
    } else {
        SayOK ('  ВМ "{0}": {1}, поколение {2}, ОЗУ {3} ГБ, ЦП {4}' -f `
            $vm.Name, $vm.State, $vm.Generation, [math]::Round($vm.MemoryStartup/1GB,1), $vm.ProcessorCount)
        Get-VMNetworkAdapter -VMName $Name | ForEach-Object {
            Say ('    сеть: {0} -> {1}' -f $_.Name, $_.SwitchName)
        }
        Get-VMHardDiskDrive -VMName $Name | ForEach-Object { Say ('    диск: {0}' -f $_.Path) }
        Get-VMDvdDrive -VMName $Name | ForEach-Object { Say ('    DVD:  {0}' -f $_.Path) }
        $snaps = Get-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue
        if ($snaps) { $snaps | ForEach-Object { Say ('    снимок: {0}' -f $_.Name) } }
        else { SayWarn '    снимков нет — перед прогоном сделайте -Action Checkpoint' }
        $gs = Get-VMIntegrationService -VMName $Name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
        Say ('    передача файлов по VMBus: {0}' -f $(if ($gs -and $gs.Enabled) { 'включена' } else { 'ВЫКЛЮЧЕНА' }))
    }
    Write-Host ''
}

'Build' {
    # Единственное действие, не требующее прав администратора и не трогающее Hyper-V:
    # сборка бинарников для передачи в гостя. Так в госте не нужен Go — рантайм-приёмке
    # нужны исполняемые файлы, а не компилятор.
    if (-not (Test-Path (Join-Path $SourceRoot 'go.mod'))) {
        SayErr ('  Не похоже на корень модуля: {0}' -f $SourceRoot); exit 1
    }
    if (-not (Get-Command go.exe -ErrorAction SilentlyContinue)) { SayErr '  go.exe не найден в PATH.'; exit 1 }

    $bin = Join-Path $SourceRoot 'bin'
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    $env:GOFLAGS = '-mod=vendor'          # зависимости вендорены — интернет для сборки не нужен
    $env:CGO_ENABLED = '1'
    if (-not (Get-Command gcc.exe -ErrorAction SilentlyContinue)) {
        # Трею нужен CGO; без gcc сборка упадёт с невнятной ошибкой компоновки.
        SayWarn '  gcc не найден в PATH. Для CGO добавьте, например: D:\winlibs\mingw64\bin'
    }

    $cmds = Get-ChildItem (Join-Path $SourceRoot 'cmd') -Directory | Select-Object -ExpandProperty Name
    Say ('  Собираю: {0}' -f ($cmds -join ', '))
    Push-Location $SourceRoot
    $bad = 0
    foreach ($c in $cmds) {
        $out = Join-Path $bin ('{0}.exe' -f $c)
        & go build -o $out ('./cmd/{0}' -f $c) 2>&1 | ForEach-Object { Say ('    {0}' -f $_) }
        if ($LASTEXITCODE -ne 0) { SayErr ('    [СБОЙ] {0}' -f $c); $bad++ }
        else { SayOK ('    [OK] {0} ({1} МБ)' -f $out, [math]::Round((Get-Item $out).Length/1MB,1)) }
    }
    Pop-Location
    Write-Host ''
    if ($bad -gt 0) { SayErr ('  Не собралось: {0}' -f $bad); exit 2 }
    SayOK ('  Бинарники в {0} — попадут в гостя при -Action Provision.' -f $bin)
    Write-Host ''
}

'Create' {
    Assert-Ready
    if (Get-Stand) { SayErr ('  ВМ "{0}" уже существует.' -f $Name); exit 1 }
    if (-not $IsoPath) { SayErr '  Нужен -IsoPath <установочный образ Windows 11>.'; exit 1 }
    if (-not (Test-Path $IsoPath)) { SayErr ('  Образ не найден: {0}' -f $IsoPath); exit 1 }
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        SayErr ('  Коммутатор "{0}" не найден.' -f $SwitchName); exit 1
    }

    New-Item -ItemType Directory -Force -Path $StandRoot | Out-Null

    Say ('  Создаю ВМ {0}: {1} ГБ ОЗУ, диск {2} ГБ (динамический), коммутатор "{3}"' -f $Name, $MemoryGB, $DiskGB, $SwitchName)
    $vm = New-VM -Name $Name -Generation 2 `
                 -MemoryStartupBytes ($MemoryGB * 1GB) `
                 -NewVHDPath $vhdPath -NewVHDSizeBytes ($DiskGB * 1GB) `
                 -SwitchName $SwitchName -Path $StandRoot

    Set-VM -Name $Name -ProcessorCount ([Math]::Min(4, (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors)) `
           -CheckpointType Standard `
           -AutomaticCheckpointsEnabled $false `
           -AutomaticStartAction Nothing `
           -AutomaticStopAction ShutDown
    # Автоснимки выключены намеренно: они меняют состояние между прогонами TG-1
    # и делают результат невоспроизводимым.

    Set-VMMemory -VMName $Name -DynamicMemoryEnabled $true -MinimumBytes 1GB -MaximumBytes ($MemoryGB * 1GB)
    Add-VMDvdDrive -VMName $Name -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $Name
    Set-VMFirmware -VMName $Name -FirstBootDevice $dvd -EnableSecureBoot On
    Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

    SayOK ('  ВМ создана: {0}' -f $vhdPath)
    Say ''
    Say '  Дальше вручную:'
    Say ('    1) .\hyperv_stand.ps1 -Action Start   (или Hyper-V Manager -> Connect)')
    Say  '    2) установить Windows в госте, завести локального пользователя-администратора'
    Say  '    3) .\hyperv_stand.ps1 -Action Provision   — передать исходники'
    Say  '    4) в госте запустить C:\apf-drop\hyperv_bootstrap.ps1'
    Say  '    5) .\hyperv_stand.ps1 -Action Checkpoint  — снимок "clean" ДО первого запуска APF'
    Write-Host ''
}

'Provision' {
    Assert-Ready
    $vm = Assert-Stand
    if ($vm.State -ne 'Running') { SayErr '  ВМ должна быть запущена, а Windows в ней — установлена.'; exit 1 }
    $gs = Get-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'
    if (-not $gs.Enabled) { Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface' }

    if (-not (Test-Path $SourceRoot)) { SayErr ('  Не найдены исходники: {0}' -f $SourceRoot); exit 1 }
    if (-not (Test-Path (Join-Path $SourceRoot 'bin'))) {
        SayWarn '  ПРЕДУПРЕЖДЕНИЕ: нет source\bin — в госте понадобится Go для сборки.'
        SayWarn '  Иначе сначала выполните: .\hyperv_stand.ps1 -Action Build'
    }
    New-Item -ItemType Directory -Force -Path $StandRoot | Out-Null

    Say ('  Упаковываю {0}' -f $SourceRoot)
    if (Test-Path $payloadZip) { Remove-Item $payloadZip -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceRoot, $payloadZip)
    SayOK ('  {0} ({1} МБ)' -f $payloadZip, [math]::Round((Get-Item $payloadZip).Length/1MB,1))

    # Передача идёт по VMBus, а не по сети: стенд остаётся сетево изолированным,
    # и обрыв связи внутри гостя (ожидаемый результат тестов Kill Switch) не мешает доставке.
    Say '  Передаю в гостя по VMBus (сеть не используется) ...'
    Copy-VMFile -Name $Name -SourcePath $payloadZip `
                -DestinationPath (Join-Path $guestDrop (Split-Path $payloadZip -Leaf)) `
                -CreateFullPath -FileSource Host -Force

    $boot = Join-Path $scriptDir 'hyperv_bootstrap.ps1'
    if (Test-Path $boot) {
        Copy-VMFile -Name $Name -SourcePath $boot `
                    -DestinationPath (Join-Path $guestDrop 'hyperv_bootstrap.ps1') `
                    -CreateFullPath -FileSource Host -Force
    } else { SayWarn ('  ПРЕДУПРЕЖДЕНИЕ: не найден {0}' -f $boot) }

    # Маркер — часть защиты гостевого скрипта от запуска на рабочей машине.
    $markerLocal = Join-Path $StandRoot $markerName
    ('APF isolated stand. VM={0}' -f $Name) | Out-File -FilePath $markerLocal -Encoding ascii
    Copy-VMFile -Name $Name -SourcePath $markerLocal `
                -DestinationPath (Join-Path 'C:\' $markerName) `
                -CreateFullPath -FileSource Host -Force

    SayOK ('  Готово. В госте: {0}' -f $guestDrop)
    Say  ('  Внутри ВМ выполните:  powershell -ExecutionPolicy Bypass -File {0}\hyperv_bootstrap.ps1' -f $guestDrop)
    Write-Host ''
}

'Checkpoint' {
    Assert-Ready ; Assert-Stand | Out-Null
    $old = Get-VMSnapshot -VMName $Name -Name $CheckpointName -ErrorAction SilentlyContinue
    if ($old) {
        if (-not $Force) { SayErr ('  Снимок "{0}" уже есть. Перезаписать: добавьте -Force' -f $CheckpointName); exit 1 }
        Remove-VMSnapshot -VMName $Name -Name $CheckpointName -Confirm:$false
    }
    Checkpoint-VM -Name $Name -SnapshotName $CheckpointName
    SayOK ('  Снимок "{0}" снят. Откат: -Action Reset' -f $CheckpointName)
    Write-Host ''
}

'Reset' {
    Assert-Ready ; Assert-Stand | Out-Null
    $snap = Get-VMSnapshot -VMName $Name -Name $CheckpointName -ErrorAction SilentlyContinue
    if (-not $snap) { SayErr ('  Снимка "{0}" нет.' -f $CheckpointName); exit 1 }
    Restore-VMCheckpoint -VMName $Name -Name $CheckpointName -Confirm:$false
    SayOK ('  Откат к "{0}" выполнен.' -f $CheckpointName)
    Write-Host ''
}

'Start' { Assert-Ready ; Assert-Stand | Out-Null ; Start-VM -Name $Name ; SayOK '  Запущена.' ; Write-Host '' }

'Stop'  { Assert-Ready ; Assert-Stand | Out-Null ; Stop-VM -Name $Name ; SayOK '  Выключена штатно.' ; Write-Host '' }

'Kill'  {
    Assert-Ready ; Assert-Stand | Out-Null
    # Сценарий crash-recovery: питание пропало, штатной уборки не было.
    Stop-VM -Name $Name -TurnOff -Force
    SayOK '  Питание снято жёстко. Это входной сценарий проверки crash-recovery.'
    Write-Host ''
}

'Remove' {
    Assert-Ready
    $vm = Assert-Stand
    if (-not $Force) {
        $ans = Read-Host ('  Удалить ВМ "{0}" ВМЕСТЕ С ДИСКОМ? (yes/no)' -f $Name)
        if ($ans -ne 'yes') { SayWarn '  Отменено.' ; exit 0 }
    }
    $disks = Get-VMHardDiskDrive -VMName $Name | Select-Object -ExpandProperty Path
    if ($vm.State -ne 'Off') { Stop-VM -Name $Name -TurnOff -Force }
    Remove-VM -Name $Name -Force
    foreach ($d in $disks) { if (Test-Path $d) { Remove-Item $d -Force ; Say ('  удалён диск {0}' -f $d) } }
    SayOK '  ВМ удалена.'
    Write-Host ''
}

}

exit 0
