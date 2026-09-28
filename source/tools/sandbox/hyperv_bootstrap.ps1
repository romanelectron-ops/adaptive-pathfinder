#Requires -Version 5.1
<#
.SYNOPSIS
    Подготовка стенда APF ВНУТРИ гостевой Hyper-V ВМ (уровень 3).

.DESCRIPTION
    Аналог sandbox_bootstrap.ps1, но для постоянной ВМ, а не одноразовой песочницы.
    Запускается ВРУЧНУЮ внутри гостя после hyperv_stand.ps1 -Action Provision.

    Делает:
      1. Проверяет, что мы действительно в изолированной ВМ (тройная защита, см. ниже).
      2. Распаковывает переданный по VMBus архив исходников в C:\work.
      3. Настраивает Go/MinGW, если они установлены в госте.
      4. Снимает барьер hostguard — законно ТОЛЬКО здесь.
      5. Делает снимок сетевого состояния как точку отсчёта.
      6. Собирает проект и печатает список допустимых действий.

    ЗАЩИТА ОТ ЗАПУСКА НА РАБОЧЕЙ МАШИНЕ. Скрипт снимает единственный барьер, который
    удерживает APF от изменения ОС, поэтому проверок три, и нужны ВСЕ:
      * Win32_ComputerSystem.Model = 'Virtual Machine' и Manufacturer = 'Microsoft Corporation'
        — на физической машине Model равен реальной модели железа; подделать файлом нельзя;
      * маркер C:\APF-STAND.marker, положенный при провижининге;
      * имя машины не входит в список известных рабочих машин.
    Инцидент 2026-07-28 (потеря связи на рабочей машине) произошёл ровно потому,
    что подобной проверки не было.
#>
[CmdletBinding()]
param(
    [string]$Drop = 'C:\apf-drop',
    [string]$Work = 'C:\work'
)

$ErrorActionPreference = 'Continue'

# Рабочие машины, на которых этот скрипт запускать нельзя ни при каких условиях.
$forbiddenHosts = @('<dev-host>')

function Fail { param([string]$m) ; Write-Host '' ; Write-Host ('  ОТКАЗ: {0}' -f $m) -ForegroundColor Red ; Write-Host '' ; Read-Host 'Enter для выхода' ; exit 1 }

Write-Host ''
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host '  APF · ИЗОЛИРОВАННЫЙ СТЕНД (Hyper-V, уровень 3)' -ForegroundColor Cyan
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host ''

# ─── 0. Тройная проверка изоляции ─────────────────────────────────────────────
Write-Host '[0/6] Проверяю, что это изолированная ВМ ...' -ForegroundColor Yellow

$cs = Get-CimInstance Win32_ComputerSystem
$isGuest = ($cs.Model -eq 'Virtual Machine' -and $cs.Manufacturer -eq 'Microsoft Corporation')
Write-Host ('      производитель/модель: {0} / {1}' -f $cs.Manufacturer, $cs.Model)
if (-not $isGuest) {
    Fail 'это не гостевая Hyper-V ВМ. Скрипт снимает защиту хоста и здесь запрещён.'
}

if ($forbiddenHosts -contains $env:COMPUTERNAME) {
    Fail ('имя машины "{0}" в списке рабочих. Запуск запрещён.' -f $env:COMPUTERNAME)
}

$marker = 'C:\APF-STAND.marker'
if (-not (Test-Path $marker)) {
    Fail ('нет маркера {0}. Выполните на хосте: hyperv_stand.ps1 -Action Provision' -f $marker)
}
Write-Host ('      маркер: {0}' -f (Get-Content $marker -First 1)) -ForegroundColor Green
Write-Host '      изоляция подтверждена' -ForegroundColor Green

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) {
    Fail 'нужны права администратора: Kill Switch, WFP и служба без них не проверяются.'
}

# ─── 1. Распаковка исходников ─────────────────────────────────────────────────
Write-Host '[1/6] Распаковываю исходники ...' -ForegroundColor Yellow
$zip = Get-ChildItem -Path $Drop -Filter '*-src.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $zip) { Fail ('в {0} нет архива *-src.zip — выполните на хосте -Action Provision' -f $Drop) }

$source = Join-Path $Work 'source'
if (Test-Path $source) { Remove-Item $source -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Work | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $source)
Write-Host ('      готово: {0}' -f $source) -ForegroundColor Green

# ─── 2. Инструментарий ────────────────────────────────────────────────────────
Write-Host '[2/6] Ищу Go и gcc ...' -ForegroundColor Yellow
$goExe  = Get-Command go.exe  -ErrorAction SilentlyContinue
$gccExe = Get-Command gcc.exe -ErrorAction SilentlyContinue
$canBuild = $false
if ($goExe) {
    $env:GOFLAGS     = '-mod=vendor'   # зависимости вендорены — интернет для сборки не нужен
    $env:CGO_ENABLED = $(if ($gccExe) { '1' } else { '0' })
    $env:GOPATH      = Join-Path $Work 'gopath'
    New-Item -ItemType Directory -Force -Path $env:GOPATH | Out-Null
    Write-Host ('      {0}' -f (& go version)) -ForegroundColor Green
    if ($gccExe) { Write-Host ('      {0}' -f (& gcc --version | Select-Object -First 1)) -ForegroundColor Green }
    else { Write-Host '      gcc не найден: CGO выключен, -race работать не будет' -ForegroundColor Yellow }
    $canBuild = $true
} else {
    Write-Host '      Go в госте не установлен.' -ForegroundColor Yellow
    Write-Host '      Рантайм-приёмке компилятор не нужен, если бинарники собраны на хосте' -ForegroundColor Yellow
    Write-Host '      и лежат в архиве. Go нужен только для go test внутри ВМ.' -ForegroundColor Yellow
}

# ─── 3. Снятие барьера hostguard ──────────────────────────────────────────────
# ЗАКОННО ТОЛЬКО ЗДЕСЬ: состояние этой ВМ откатывается снимком за секунды.
Write-Host '[3/6] Снимаю барьер hostguard ...' -ForegroundColor Yellow
$env:APF_ALLOW_HOST_MUTATION = 'i-know-this-is-an-isolated-vm'
Write-Host '      APF_ALLOW_HOST_MUTATION установлен — мутации ОС здесь разрешены' -ForegroundColor Green
Write-Host '      (переменная живёт только в этом сеансе консоли)' -ForegroundColor Gray

# ─── 4. Точка отсчёта ─────────────────────────────────────────────────────────
Write-Host '[4/6] Снимок исходного состояния сети ...' -ForegroundColor Yellow
$snap = Join-Path $source 'tools\apf_host_snapshot.ps1'
if (Test-Path $snap) {
    & $snap -Save 'stand_baseline' | Out-Null
    Write-Host '      снимок "stand_baseline" сохранён' -ForegroundColor Green
} else {
    Write-Host '      ПРЕДУПРЕЖДЕНИЕ: не найден apf_host_snapshot.ps1' -ForegroundColor Yellow
}

# ─── 5. Сборка ────────────────────────────────────────────────────────────────
Write-Host '[5/6] Сборка ...' -ForegroundColor Yellow
if ($canBuild) {
    Push-Location $source
    & go build ./... 2>&1 | ForEach-Object { Write-Host ('      {0}' -f $_) }
    if ($LASTEXITCODE -eq 0) { Write-Host '      СБОРКА OK' -ForegroundColor Green }
    else { Write-Host '      СБОРКА УПАЛА' -ForegroundColor Red }
    Pop-Location
} else {
    Write-Host '      пропущено (нет Go)' -ForegroundColor Gray
}

# ─── 6. Связь до начала испытаний ─────────────────────────────────────────────
Write-Host '[6/6] Проверяю связь (точка отсчёта для позитивных тестов) ...' -ForegroundColor Yellow
try {
    $r = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 10
    Write-Host ('      СЕТЬ ЕСТЬ (HTTP {0})' -f $r.StatusCode) -ForegroundColor Green
} catch {
    Write-Host ('      СЕТИ НЕТ: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '      Позитивные тесты VPN-режима без связи недействительны.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host '  ЧТО ЗДЕСЬ РАЗРЕШЕНО (и запрещено на рабочей машине)' -ForegroundColor Cyan
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host ('  cd {0}' -f $source) -ForegroundColor White
Write-Host ''
Write-Host '  # прогон тестов с РАЗРЕШЁННЫМИ мутациями ОС' -ForegroundColor Gray
Write-Host '  go test ./internal/...' -ForegroundColor White
Write-Host ''
Write-Host '  # инвариант TG-1: 100 циклов Enable/Disable -> 0 остаточных правил' -ForegroundColor Gray
Write-Host '  .\tools\apf_ks_safe_run.ps1' -ForegroundColor White
Write-Host ''
Write-Host '  # что изменилось с момента старта' -ForegroundColor Gray
Write-Host '  .\tools\apf_host_snapshot.ps1 -Save now; .\tools\apf_host_snapshot.ps1 -Diff stand_baseline,now' -ForegroundColor White
Write-Host ''
Write-Host '  Пропажа связи ВНУТРИ ВМ — ожидаемый результат теста, а не авария.' -ForegroundColor Yellow
Write-Host '  Хост не затронут. Быстрый откат — на ХОСТЕ:' -ForegroundColor Yellow
Write-Host '    .\tools\sandbox\hyperv_stand.ps1 -Action Reset' -ForegroundColor White
Write-Host ''

Set-Location $source
