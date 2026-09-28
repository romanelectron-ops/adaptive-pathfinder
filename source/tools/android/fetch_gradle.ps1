#Requires -Version 5.1
<#
.SYNOPSIS
    Ставит дистрибутив Gradle на диск D: и готовит wrapper проекта (этап Э-2).

.DESCRIPTION
    Прав администратора НЕ требует. БЕЗ ключа -Apply ничего не скачивает.

    Зачем отдельный шаг: на машине нет ни Gradle, ни Android Studio, ни
    gradle-wrapper.jar. Wrapper без своего .jar не работает, а сам .jar порождается
    только уже установленным Gradle — замкнутый круг разрывается разовой загрузкой
    дистрибутива.

    После установки скрипт выполняет `gradle wrapper`, чтобы в проекте появились
    gradlew.bat и gradle-wrapper.jar: дальше сборка не зависит от глобальной установки
    и воспроизводится на другой машине одной командой.

    Всё складывается в APF-Stand внутри папки проекта — по правилу проекта файлы
    (включая кэши сборки) не должны жить вне папки проекта.

.EXAMPLE
    .\fetch_gradle.ps1              # план
    .\fetch_gradle.ps1 -Apply       # скачать, распаковать, создать wrapper
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$Version = '8.7',
    [string]$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand')),
    [string]$JavaHome,
    # Не создавать wrapper в проекте (только установить дистрибутив).
    [switch]$NoWrapper
)

$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$sourceRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
$projectDir = (Join-Path (Split-Path $sourceRoot -Parent) 'android\android-project')

$zipName = "gradle-$Version-bin.zip"
$url = "https://services.gradle.org/distributions/$zipName"
$downloads = Join-Path $Root 'downloads'
$zipPath = Join-Path $downloads $zipName
$installDir = Join-Path $Root 'gradle'
$gradleHome = Join-Path $installDir "gradle-$Version"
$gradleBat = Join-Path $gradleHome 'bin\gradle.bat'

function Say     { param([string]$s) Write-Host $s }
function SayOK   { param([string]$s) Write-Host $s -ForegroundColor Green }
function SayWarn { param([string]$s) Write-Host $s -ForegroundColor Yellow }
function SayErr  { param([string]$s) Write-Host $s -ForegroundColor Red }

Write-Host ''
Write-Host ('=== APF · Gradle {0} ===' -f $Version) -ForegroundColor Cyan
Write-Host ''
Say ('  Источник:   {0}' -f $url)
Say ('  Размер:     примерно 130 МБ')
Say ('  Установка:  {0}' -f $gradleHome)
Say ('  Wrapper:    {0}' -f $(if ($NoWrapper) { 'не создавать' } else { (Join-Path $projectDir 'gradlew.bat') }))
Write-Host ''

if (Test-Path $gradleBat) {
    SayOK ('  Gradle уже установлен: {0}' -f $gradleBat)
    if ($NoWrapper) { Write-Host ''; exit 0 }
}

if (-not $Apply) {
    SayWarn '  Это предварительный просмотр. Ничего не скачано.'
    SayWarn '  Для выполнения добавьте -Apply.'
    Write-Host ''
    exit 0
}

# ─── JDK ──────────────────────────────────────────────────────────────────────

if (-not $JavaHome) {
    foreach ($root in @("$env:LOCALAPPDATA\Programs\Eclipse Adoptium", 'C:\Program Files\Eclipse Adoptium', 'C:\Program Files\Java')) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '[-.]17([.\-]|$)' } | Select-Object -First 1
        if ($hit) { $JavaHome = $hit.FullName; break }
    }
}
if (-not $JavaHome -or -not (Test-Path $JavaHome)) {
    SayErr '  JDK 17 не найден. Укажите -JavaHome.'
    exit 1
}
Say ('  JDK: {0}' -f $JavaHome)
$env:JAVA_HOME = $JavaHome

# ─── Загрузка ─────────────────────────────────────────────────────────────────

if (-not (Test-Path $gradleBat)) {
    New-Item -ItemType Directory -Force -Path $downloads | Out-Null
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null

    if (-not (Test-Path $zipPath)) {
        Say '  Скачиваю ...'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    } else {
        Say ('  Архив уже скачан: {0}' -f $zipPath)
    }
    Say ('  Архив: {0:N1} МБ' -f ((Get-Item $zipPath).Length / 1MB))

    Say '  Распаковываю ...'
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force

    if (-not (Test-Path $gradleBat)) { SayErr ('  После распаковки не найден {0}' -f $gradleBat); exit 2 }
    SayOK ('  Установлен: {0}' -f $gradleHome)
}

& $gradleBat --version 2>&1 | Select-Object -First 6 | ForEach-Object { Say ('    {0}' -f $_) }

# ─── Wrapper проекта ──────────────────────────────────────────────────────────

if ($NoWrapper) { Write-Host ''; exit 0 }

if (-not (Test-Path $projectDir)) { SayErr ('  Проект не найден: {0}' -f $projectDir); exit 1 }

Write-Host ''
Say '  Создаю wrapper в проекте ...'
$env:GRADLE_USER_HOME = Join-Path $Root 'gradle-home'
New-Item -ItemType Directory -Force -Path $env:GRADLE_USER_HOME | Out-Null

Push-Location $projectDir
try {
    & $gradleBat wrapper --gradle-version $Version --no-daemon
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host ''
$wrapperJar = Join-Path $projectDir 'gradle\wrapper\gradle-wrapper.jar'
if ($code -ne 0 -or -not (Test-Path $wrapperJar)) {
    SayErr '  Wrapper создать не удалось. Сборку можно вести напрямую:'
    Say ('    tools\android\build_apk.ps1 -GradleExe "{0}"' -f $gradleBat)
    Write-Host ''
    exit 2
}

SayOK ('  Wrapper готов: {0}' -f (Join-Path $projectDir 'gradlew.bat'))
Write-Host ''
exit 0
