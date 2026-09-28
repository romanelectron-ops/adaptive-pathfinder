#Requires -Version 5.1
<#
.SYNOPSIS
    Восстанавливает СТАНДАРТНУЮ таблицу политик префиксов IPv6 (RFC 6724 / умолчания Windows).

.DESCRIPTION
    ТРЕБУЕТ ПРАВ АДМИНИСТРАТОРА. Перезагрузка НЕ нужна — изменения действуют сразу.

    Зачем: таблица политик префиксов управляет выбором адреса назначения и источника
    (getaddrinfo, RFC 6724). Если она схлопнута до одной записи, выбор между IPv4 и IPv6
    делается не по правилам, а по остаточному поведению стека — вплоть до сетевых сбоев
    и до искажения результатов любых испытаний, где сравнивается путь v4 и v6.

    Что делает:
      1. Сохраняет ТЕКУЩУЮ таблицу в файл (действие обратимо).
      2. Выставляет 8 стандартных записей Windows.
      3. Показывает результат.

    Откат: записи из сохранённого файла вернуть теми же командами `set prefixpolicy`,
    либо `netsh interface ipv6 reset` (сбрасывает ВСЮ конфигурацию IPv6, нужна перезагрузка).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\restore_ipv6_prefixpolicy.ps1
#>
[CmdletBinding()]
param(
    # Куда положить резервную копию и лог. По умолчанию — рядом со скриптом.
    [string]$BackupDir = $PSScriptRoot,
    # Только показать план, ничего не менять.
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Стандартная таблица Windows (совпадает с RFC 6724 §2.1 с поправками Microsoft).
# Порядок строк значения не имеет — политика определяется парой precedence/label.
$defaults = @(
    @{ Prefix = '::1/128';       Precedence = 50; Label = 0  } # loopback — выше всего
    @{ Prefix = '::/0';          Precedence = 40; Label = 1  } # обычный IPv6
    @{ Prefix = '::ffff:0:0/96'; Precedence = 35; Label = 4  } # IPv4-mapped — ключевая строка для v4
    @{ Prefix = '2002::/16';     Precedence = 30; Label = 2  } # 6to4
    @{ Prefix = '2001::/32';     Precedence = 5;  Label = 5  } # Teredo
    @{ Prefix = 'fc00::/7';      Precedence = 3;  Label = 13 } # ULA
    @{ Prefix = 'fec0::/10';     Precedence = 1;  Label = 11 } # site-local (устарел)
    @{ Prefix = '3ffe::/16';     Precedence = 1;  Label = 12 } # 6bone (устарел)
)

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

Write-Host ""
Write-Host "=== Таблица политик префиксов IPv6: восстановление умолчаний ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "  ТЕКУЩЕЕ СОСТОЯНИЕ:" -ForegroundColor Yellow
$before = netsh interface ipv6 show prefixpolicies
$before | ForEach-Object { Write-Host "    $_" }

$beforeCount = @($before | Select-String -Pattern '^\s*\d+\s+\d+\s+\S+').Count
Write-Host ""
Write-Host ("  Записей сейчас: {0}, ожидается {1}" -f $beforeCount, $defaults.Count)

if ($beforeCount -eq $defaults.Count) {
    Write-Host ""
    Write-Host "  Таблица уже полная — восстанавливать нечего." -ForegroundColor Green
    Write-Host ""
    exit 0
}

if (-not (Test-Admin)) {
    Write-Host ""
    Write-Host "  ТРЕБУЮТСЯ ПРАВА АДМИНИСТРАТОРА (netsh set prefixpolicy)." -ForegroundColor Red
    Write-Host ("    powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath)
    Write-Host ""
    exit 1
}

# 1. Резервная копия — до любых изменений.
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $BackupDir ("ipv6_prefixpolicy_backup_{0}.txt" -f $stamp)
$before | Out-File -FilePath $backup -Encoding utf8
Write-Host ""
Write-Host ("  Резервная копия: {0}" -f $backup) -ForegroundColor Green

# 2. Применение.
Write-Host ""
Write-Host "  БУДЕТ ВЫПОЛНЕНО (для каждой записи):" -ForegroundColor Yellow
Write-Host "    netsh interface ipv6 add prefixpolicy <prefix> <precedence> <label> store=persistent"
Write-Host "    при неудаче (запись уже есть) — то же самое через 'set'"
foreach ($p in $defaults) {
    Write-Host ("      {0,-16} precedence={1,-3} label={2}" -f $p.Prefix, $p.Precedence, $p.Label)
}
if ($DryRun) {
    Write-Host ""
    Write-Host "  DryRun — ничего не изменено." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
# add создаёт запись, но падает, если она уже есть; set обновляет, но падает, если её нет
# («Элемент не найден»). Пара add→set покрывает оба случая и делает скрипт идемпотентным.
$failed = 0
foreach ($p in $defaults) {
    $out = netsh interface ipv6 add prefixpolicy $p.Prefix $p.Precedence $p.Label store=persistent 2>&1
    $verb = 'add'
    if ($LASTEXITCODE -ne 0) {
        $out = netsh interface ipv6 set prefixpolicy $p.Prefix $p.Precedence $p.Label store=persistent 2>&1
        $verb = 'set'
    }
    if ($LASTEXITCODE -ne 0) {
        $failed++
        Write-Host ("    [СБОЙ] {0}: {1}" -f $p.Prefix, ($out -join ' ')) -ForegroundColor Red
    } else {
        Write-Host ("    [OK/{0}] {1,-16} precedence={2,-3} label={3}" -f $verb, $p.Prefix, $p.Precedence, $p.Label)
    }
}

# 3. Проверка.
Write-Host ""
Write-Host "  СТАЛО:" -ForegroundColor Yellow
$after = netsh interface ipv6 show prefixpolicies
$after | ForEach-Object { Write-Host "    $_" }
$afterCount = @($after | Select-String -Pattern '^\s*\d+\s+\d+\s+\S+').Count

Write-Host ""
if ($failed -eq 0 -and $afterCount -eq $defaults.Count) {
    Write-Host ("  ГОТОВО: {0} → {1} записей. Перезагрузка не нужна." -f $beforeCount, $afterCount) -ForegroundColor Green
    exit 0
}
Write-Host ("  ЗАВЕРШЕНО С ЗАМЕЧАНИЯМИ: сбоев {0}, записей {1} из {2}." -f $failed, $afterCount, $defaults.Count) -ForegroundColor Red
Write-Host ("  Откат — из {0}" -f $backup) -ForegroundColor Yellow
exit 2
