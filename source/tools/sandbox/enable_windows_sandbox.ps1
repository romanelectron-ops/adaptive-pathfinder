#Requires -Version 5.1
<#
.SYNOPSIS
    Включает компонент Windows Sandbox (одноразовая ВМ для рантайм-испытаний APF).

.DESCRIPTION
    ТРЕБУЕТ ПРАВ АДМИНИСТРАТОРА и ПЕРЕЗАГРУЗКИ. Скрипт ничего не делает молча: сначала
    показывает текущее состояние компонентов и точную команду, затем спрашивает подтверждение.

    Что включается:
      * Containers-DisposableClientVM — собственно Windows Sandbox.
      * VirtualMachinePlatform       — платформа виртуализации (обычно уже включена, если есть WSL2).

    Почему это нужно: APF меняет глобальное состояние машины (политика фаервола, WFP-фильтры,
    системный прокси, DNS). Проверять его на рабочей машине — значит регулярно терять связь.
    В песочнице сетевой стек, реестр и фаервол свои, и всё исчезает при закрытии окна.

.EXAMPLE
    # Запустить в консоли, поднятой «от имени администратора»:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\enable_windows_sandbox.ps1
#>
[CmdletBinding()]
param(
    # Не спрашивать подтверждение (для неинтерактивного запуска).
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

Write-Host ""
Write-Host "=== Windows Sandbox: проверка предпосылок ===" -ForegroundColor Cyan
Write-Host ""

# 1. Редакция Windows
$caption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host ("  Редакция ОС:            {0}" -f $caption)
if ($caption -notmatch 'Pro|Enterprise|Education') {
    Write-Host "  ! Windows Sandbox доступен только в Pro/Enterprise/Education." -ForegroundColor Red
    Write-Host "    На Home используйте Hyper-V ВМ или Docker (см. tools\sandbox\README.md)." -ForegroundColor Yellow
    exit 1
}

# 2. Аппаратная виртуализация
$hv = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
Write-Host ("  Виртуализация активна:  {0}" -f $hv)
if (-not $hv) {
    Write-Host "  ! Виртуализация выключена в BIOS/UEFI — включите Intel VT-x / AMD-V." -ForegroundColor Red
    exit 1
}

# 3. Уже установлено?
$sandboxExe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
if (Test-Path $sandboxExe) {
    Write-Host ""
    Write-Host "  Windows Sandbox УЖЕ УСТАНОВЛЕН — включать нечего." -ForegroundColor Green
    Write-Host "  Запуск стенда:  explorer.exe tools\sandbox\apf_sandbox.wsb" -ForegroundColor White
    Write-Host ""
    exit 0
}
Write-Host "  Windows Sandbox:        НЕ установлен"

# 4. Права
if (-not (Test-Admin)) {
    Write-Host ""
    Write-Host "  ТРЕБУЮТСЯ ПРАВА АДМИНИСТРАТОРА." -ForegroundColor Red
    Write-Host "  Откройте PowerShell «от имени администратора» и выполните:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ("    powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -ForegroundColor White
    Write-Host ""
    Write-Host "  Либо однострочником (тоже от администратора):" -ForegroundColor Yellow
    Write-Host "    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All" -ForegroundColor White
    Write-Host ""
    exit 1
}

# 5. Подтверждение
Write-Host ""
Write-Host "  БУДЕТ ВЫПОЛНЕНО:" -ForegroundColor Yellow
Write-Host "    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart"
Write-Host "    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart"
Write-Host ""
Write-Host "  ПОСЛЕ ЭТОГО ПОТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА." -ForegroundColor Yellow
Write-Host ""
if (-not $Force) {
    $ans = Read-Host "  Продолжить? (yes/no)"
    if ($ans -ne 'yes') { Write-Host "  Отменено пользователем." -ForegroundColor Yellow; exit 0 }
}

# 6. Применение — с ЯВНЫМ перехватом ошибок.
#
# Почему не «просто вызвать cmdlet»: при $ErrorActionPreference='Stop' сбой
# Enable-WindowsOptionalFeature — терминирующее исключение. Если скрипт запущен как
# `powershell -Command "& скрипт *> лог"`, текст исключения в лог не попадает: наружу
# видно только «код возврата 1», а лог обрывается на последней Write-Host.
# 29.07.2026 так и вышло — настоящую причину (CBS HRESULT=0x80188306, «Failed finalizing
# changes» при включении Containers-DisposableClientVM) пришлось доставать из
# C:\Windows\Logs\DISM\dism.log. Инструмент, который не умеет объяснить свой отказ,
# бесполезен, поэтому дальше каждый сбой печатается на месте.

$features = @('VirtualMachinePlatform', 'Containers-DisposableClientVM')

function Get-FeatureState {
    param([string]$Name)
    try { (Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop).State }
    catch { 'неизвестно' }
}

function Show-DismErrors {
    # Последние строки уровня Error из dism.log — там лежит настоящая причина.
    $dism = Join-Path $env:SystemRoot 'Logs\DISM\dism.log'
    if (-not (Test-Path $dism)) { return }
    $err = @(Get-Content $dism -ErrorAction SilentlyContinue |
             Where-Object { $_ -match ',\s*Error\s' } | Select-Object -Last 8)
    if ($err.Count -eq 0) { return }
    Write-Host "    Хвост dism.log (уровень Error):" -ForegroundColor Yellow
    $err | ForEach-Object { Write-Host ("      {0}" -f $_) }
}

function Enable-Feature {
    param([string]$Name)
    Write-Host ("  Включаю {0} (сейчас: {1}) ..." -f $Name, (Get-FeatureState $Name)) -ForegroundColor Yellow
    try {
        $r = Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart -ErrorAction Stop
        Write-Host ("    [OK/cmdlet] нужна перезагрузка: {0}" -f $r.RestartNeeded) -ForegroundColor Green
        return $true
    } catch {
        Write-Host ("    [СБОЙ/cmdlet] {0}" -f $_.Exception.Message) -ForegroundColor Red
        if ($_.Exception.HResult) {
            Write-Host ("    HRESULT: 0x{0:X8}" -f $_.Exception.HResult) -ForegroundColor Red
        }
        # Запасной путь: dism.exe. Он возвращает числовой код (в отличие от исключения)
        # и не зависит от состояния PowerShell-модуля Dism.
        Write-Host "    Повторяю через dism.exe ..." -ForegroundColor Yellow
        & dism.exe /Online /Enable-Feature /FeatureName:$Name /All /NoRestart /Quiet | Out-Null
        $code = $LASTEXITCODE
        # 3010 = ERROR_SUCCESS_REBOOT_REQUIRED — это успех, а не сбой.
        if ($code -eq 0 -or $code -eq 3010) {
            Write-Host ("    [OK/dism.exe] код {0}" -f $code) -ForegroundColor Green
            return $true
        }
        Write-Host ("    [СБОЙ/dism.exe] код возврата {0}" -f $code) -ForegroundColor Red
        Show-DismErrors
        return $false
    }
}

Write-Host ""
$failed = @()
foreach ($f in $features) {
    # Платформа виртуализации — предпосылка для песочницы; без неё второй шаг бессмыслен.
    if (-not (Enable-Feature $f)) { $failed += $f; break }
}

Write-Host ""
Write-Host "  СОСТОЯНИЕ КОМПОНЕНТОВ:" -ForegroundColor Yellow
foreach ($f in $features) { Write-Host ("    {0,-32} {1}" -f $f, (Get-FeatureState $f)) }

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "  ГОТОВО. Перезагрузите компьютер, затем запустите стенд:" -ForegroundColor Green
    Write-Host "    explorer.exe tools\sandbox\apf_sandbox.wsb" -ForegroundColor White
    Write-Host ""
    exit 0
}

Write-Host ("  НЕ УДАЛОСЬ включить: {0}" -f ($failed -join ', ')) -ForegroundColor Red
Write-Host "  Обычная последовательность лечения (каждый шаг — от администратора):" -ForegroundColor Yellow
Write-Host "    1) перезагрузка (незавершённая транзакция CBS блокирует обслуживание)"
Write-Host "    2) DISM /Online /Cleanup-Image /RestoreHealth"
Write-Host "    3) sfc /scannow"
Write-Host "    4) повторить этот скрипт"
Write-Host "  Полная причина: C:\Windows\Logs\DISM\dism.log и C:\Windows\Logs\CBS\CBS.log" -ForegroundColor Yellow
Write-Host ""
exit 2
