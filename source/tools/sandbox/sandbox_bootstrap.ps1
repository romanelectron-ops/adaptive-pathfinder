#Requires -Version 5.1
<#
.SYNOPSIS
    Подготовка изолированной среды APF ВНУТРИ Windows Sandbox.

.DESCRIPTION
    Запускается автоматически из apf_sandbox.wsb (LogonCommand) под учёткой WDAGUtilityAccount,
    которая в песочнице является администратором.

    Делает:
      1. Копирует исходники из read-only C:\apf-src в записываемый C:\work.
      2. Настраивает Go/MinGW из проброшенных папок.
      3. Снимает барьер hostguard (APF_ALLOW_HOST_MUTATION) — ТОЛЬКО здесь это законно:
         «хост» для песочницы одноразовый, и его порча ничего не стоит.
      4. Делает снимок сетевого состояния песочницы (точка отсчёта).
      5. Собирает проект и выводит меню дальнейших действий.

    ВАЖНО: этот скрипт НИКОГДА не должен запускаться на рабочей машине. Защита — проверка
    маркера песочницы в начале.
#>

$ErrorActionPreference = 'Continue'

# ─── Защита от запуска вне песочницы ──────────────────────────────────────────
# Признак Windows Sandbox: учётная запись WDAGUtilityAccount + отсутствие C:\apf-src на хосте.
$inSandbox = ($env:USERNAME -eq 'WDAGUtilityAccount')
if (-not $inSandbox) {
    Write-Host ""
    Write-Host "  ОТКАЗ: скрипт предназначен ТОЛЬКО для Windows Sandbox." -ForegroundColor Red
    Write-Host "  Он снимает барьер защиты хоста (APF_ALLOW_HOST_MUTATION) и на рабочей" -ForegroundColor Red
    Write-Host "  машине привёл бы ровно к тому, от чего мы защищаемся: потере связи." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Текущий пользователь: $env:USERNAME (ожидался WDAGUtilityAccount)" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Enter для выхода"
    exit 1
}

$src  = 'C:\apf-src\APF\APF-v1.0.5\apf-dist\source'
$work = 'C:\work\source'

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  APF · ИЗОЛИРОВАННЫЙ СТЕНД (Windows Sandbox)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

# ─── 1. Копия исходников в записываемое место ─────────────────────────────────
Write-Host "[1/5] Копирую исходники C:\apf-src -> C:\work ..." -ForegroundColor Yellow
if (-not (Test-Path $src)) {
    Write-Host "  ОШИБКА: не найден $src — проверьте HostFolder в apf_sandbox.wsb" -ForegroundColor Red
    Read-Host "Enter для выхода"; exit 1
}
New-Item -ItemType Directory -Force -Path 'C:\work' | Out-Null
robocopy $src $work /E /NFL /NDL /NJH /NJS /NP | Out-Null
Write-Host "  готово: $work" -ForegroundColor Green

# ─── 2. Toolchain ─────────────────────────────────────────────────────────────
Write-Host "[2/5] Настраиваю Go и MinGW ..." -ForegroundColor Yellow
$env:GOROOT = 'C:\Go'
$env:PATH   = "C:\Go\bin;C:\mingw64\bin;$env:PATH"
$env:GOPATH = 'C:\work\gopath'
$env:GOFLAGS = '-mod=vendor'          # зависимости вендорены — интернет для сборки не нужен
$env:CGO_ENABLED = '1'                # нужен для -race
New-Item -ItemType Directory -Force -Path $env:GOPATH | Out-Null

$goVer = (& go version) 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ОШИБКА: Go не запускается. Проверьте проброс C:\Program Files\Go" -ForegroundColor Red
    Read-Host "Enter для выхода"; exit 1
}
Write-Host "  $goVer" -ForegroundColor Green
$gccVer = (& gcc --version 2>&1 | Select-Object -First 1)
Write-Host "  $gccVer" -ForegroundColor Green

# ─── 3. Снятие барьера hostguard ──────────────────────────────────────────────
# ЗАКОННО ТОЛЬКО ЗДЕСЬ: состояние этой ВМ одноразовое.
Write-Host "[3/5] Снимаю барьер hostguard (мы в одноразовой ВМ) ..." -ForegroundColor Yellow
$env:APF_ALLOW_HOST_MUTATION = 'i-know-this-is-an-isolated-vm'
Write-Host "  APF_ALLOW_HOST_MUTATION установлен — мутации ОС здесь разрешены и безопасны" -ForegroundColor Green

# ─── 4. Точка отсчёта ─────────────────────────────────────────────────────────
Write-Host "[4/5] Снимок исходного состояния сети песочницы ..." -ForegroundColor Yellow
$snap = Join-Path $work 'tools\apf_host_snapshot.ps1'
if (Test-Path $snap) {
    & $snap -Save 'sandbox_baseline' | Out-Null
    Write-Host "  снимок 'sandbox_baseline' сохранён" -ForegroundColor Green
} else {
    Write-Host "  ПРЕДУПРЕЖДЕНИЕ: не найден apf_host_snapshot.ps1" -ForegroundColor Yellow
}

# ─── 5. Сборка ────────────────────────────────────────────────────────────────
Write-Host "[5/5] Сборка проекта ..." -ForegroundColor Yellow
Push-Location $work
& go build ./... 2>&1 | ForEach-Object { Write-Host "  $_" }
$buildOK = ($LASTEXITCODE -eq 0)
Pop-Location
if ($buildOK) { Write-Host "  СБОРКА OK" -ForegroundColor Green }
else          { Write-Host "  СБОРКА УПАЛА" -ForegroundColor Red }

# ─── Проверка связи как точка отсчёта ─────────────────────────────────────────
Write-Host ""
Write-Host "Проверяю связь в песочнице (точка отсчёта для позитивных тестов):" -ForegroundColor Yellow
try {
    $r = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 10
    if ($r.StatusCode -eq 200) { Write-Host "  СЕТЬ ЕСТЬ (HTTP 200)" -ForegroundColor Green }
} catch {
    Write-Host "  СЕТИ НЕТ: $_" -ForegroundColor Red
}

# ─── Меню ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  ЧТО МОЖНО ДЕЛАТЬ ЗДЕСЬ (и НЕЛЬЗЯ на рабочей машине)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  cd C:\work\source" -ForegroundColor White
Write-Host ""
Write-Host "  # полный прогон тестов С РАЗРЕШЁННЫМИ мутациями ОС" -ForegroundColor Gray
Write-Host "  go test ./internal/... " -ForegroundColor White
Write-Host ""
Write-Host "  # рантайм-приёмка Kill Switch (сценарии A-G чек-листа)" -ForegroundColor Gray
Write-Host "  .\tools\part_b_killswitch_tg1.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  # инвариант TG-1: 100 циклов Enable/Disable -> 0 остатков правил" -ForegroundColor Gray
Write-Host "  .\tools\apf_ks_safe_run.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  # проверка WFP-бэкенда (нужен admin — здесь он есть)" -ForegroundColor Gray
Write-Host "  go run .\cmd\apf-wfpcheck" -ForegroundColor White
Write-Host ""
Write-Host "  # что изменилось в системе с момента старта" -ForegroundColor Gray
Write-Host "  .\tools\apf_host_snapshot.ps1 -Save now; .\tools\apf_host_snapshot.ps1 -Diff sandbox_baseline,now" -ForegroundColor White
Write-Host ""
Write-Host "  Если связь внутри песочницы пропадёт — это ОЖИДАЕМЫЙ результат теста," -ForegroundColor Yellow
Write-Host "  а не авария. Хост не затронут. Восстановление:" -ForegroundColor Yellow
Write-Host "  .\tools\apf_emergency_restore.bat   (или просто закройте окно песочницы)" -ForegroundColor White
Write-Host ""

Set-Location $work

