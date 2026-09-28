#Requires -Version 5.1
<#
.SYNOPSIS
    Кладёт sing-box для Android в проект под именем libsingbox.so (этап Э-2).

.DESCRIPTION
    Прав администратора НЕ требует. БЕЗ ключа -Apply ничего не скачивает: показывает,
    какой файл, откуда и какого размера будет получен.

    Почему имя libsingbox.so, а не sing-box. Начиная с Android 10 выполнение файлов из
    каталога данных приложения запрещено (W^X). Единственный каталог, откуда запуск
    разрешён, — nativeLibraryDir, а упаковщик Android кладёт туда только файлы вида
    lib*.so. Это не библиотека, а обычный исполняемый файл под подходящим именем.
    Соответствующая ветка есть в ядре: internal/singbox.binaryName("android").

    Дополнительно нужен packaging { jniLibs { useLegacyPackaging = true } } в
    app/build.gradle — иначе файл останется сжатым внутри APK и запускать будет нечего.

.EXAMPLE
    .\fetch_singbox.ps1                  # показать план
    .\fetch_singbox.ps1 -Apply           # скачать и положить в проект
    .\fetch_singbox.ps1 -Apply -FromArchive D:\downloads\sing-box-1.9.4-android-arm64.tar.gz
#>
[CmdletBinding()]
param(
    [switch]$Apply,

    # Пусто — версия берётся из internal/singbox/process.go (единый источник).
    # Задавать вручную стоит только для проверки конкретного релиза: версия связана со
    # схемой, которую выдаёт config_builder.go, и расхождение ломает подключение целиком
    # (дефект D-A27).
    [string]$Version,
    [ValidateSet('arm64-v8a', 'armeabi-v7a')]
    [string]$Abi = 'arm64-v8a',

    # Готовый архив, если он уже скачан вручную — тогда сеть не нужна.
    [string]$FromArchive,

    [string]$TempDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand\downloads'))
)

$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$sourceRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
$projectDir = (Join-Path (Split-Path $sourceRoot -Parent) 'android\android-project')

# Версия — из кода, а не продублирована здесь (дефект D-A27). Раньше «1.9.4» стояло в двух
# местах, и обновление одного из них не трогало другое; расхождение со сборщиком
# конфигурации ломает подключение целиком, а заметно это только на живом устройстве.
if (-not $Version) {
    $processGo = Join-Path $sourceRoot 'internal\singbox\process.go'
    if (-not (Test-Path $processGo)) {
        Write-Host ('  Не найден {0} — версию задайте вручную: -Version 1.13.16' -f $processGo) -ForegroundColor Red
        exit 1
    }
    $m = [regex]::Match((Get-Content $processGo -Raw -Encoding UTF8), 'SingBoxVersion\s*=\s*"([^"]+)"')
    if (-not $m.Success) {
        Write-Host '  В process.go не найдена константа SingBoxVersion — задайте -Version вручную.' -ForegroundColor Red
        exit 1
    }
    $Version = $m.Groups[1].Value
}

$abiToGo = @{ 'arm64-v8a' = 'arm64'; 'armeabi-v7a' = 'armv7' }
$goArch = $abiToGo[$Abi]
$archive = "sing-box-$Version-android-$goArch.tar.gz"
$url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/$archive"
$destDir = Join-Path $projectDir ("app\src\main\jniLibs\{0}" -f $Abi)
$dest = Join-Path $destDir 'libsingbox.so'

function Say     { param([string]$s) Write-Host $s }
function SayOK   { param([string]$s) Write-Host $s -ForegroundColor Green }
function SayWarn { param([string]$s) Write-Host $s -ForegroundColor Yellow }
function SayErr  { param([string]$s) Write-Host $s -ForegroundColor Red }

Write-Host ''
Write-Host '=== APF · sing-box для Android ===' -ForegroundColor Cyan
Write-Host ''
Say ('  Версия:     {0}' -f $Version)
Say ('  ABI:        {0}' -f $Abi)
Say ('  Источник:   {0}' -f $(if ($FromArchive) { $FromArchive } else { $url }))
Say ('  Назначение: {0}' -f $dest)
Say  '  Размер:     примерно 12–15 МБ в архиве'
Write-Host ''

if (Test-Path $dest) {
    SayWarn ('  Файл уже существует ({0:N1} МБ). Будет перезаписан.' -f ((Get-Item $dest).Length / 1MB))
    Write-Host ''
}

if (-not $Apply) {
    SayWarn '  Это предварительный просмотр. Ничего не скачано.'
    SayWarn '  Для выполнения добавьте -Apply.'
    Write-Host ''
    exit 0
}

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
New-Item -ItemType Directory -Force -Path $destDir | Out-Null

$archivePath = $FromArchive
if (-not $archivePath) {
    $archivePath = Join-Path $TempDir $archive
    Say ('  Скачиваю {0} ...' -f $url)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing
}
if (-not (Test-Path $archivePath)) { SayErr ('  Архив не найден: {0}' -f $archivePath); exit 2 }
Say ('  Архив: {0} ({1:N1} МБ)' -f $archivePath, ((Get-Item $archivePath).Length / 1MB))

# tar есть в Windows 10 1803+ — распаковываем им, без сторонних зависимостей.
$extractDir = Join-Path $TempDir 'singbox_extract'
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

Say '  Распаковываю ...'
& tar.exe -xzf $archivePath -C $extractDir
if ($LASTEXITCODE -ne 0) { SayErr '  tar не смог распаковать архив'; exit 2 }

$bin = Get-ChildItem $extractDir -Recurse -File | Where-Object { $_.Name -eq 'sing-box' } | Select-Object -First 1
if (-not $bin) { SayErr '  В архиве не найден файл sing-box'; exit 2 }

Copy-Item $bin.FullName $dest -Force
Write-Host ''
SayOK ('  ГОТОВО: {0} ({1:N1} МБ)' -f $dest, ((Get-Item $dest).Length / 1MB))
Write-Host ''
Say  '  Дальше: tools\android\build_apk.ps1'
Write-Host ''
exit 0
