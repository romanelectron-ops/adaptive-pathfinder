#Requires -Version 5.1
<#
.SYNOPSIS
    Сборка APK приложения APF (этап Э-2).

.DESCRIPTION
    Прав администратора НЕ требует. Перед сборкой проверяет ВСЕ предпосылки и внятно
    сообщает, чего не хватает: молчаливый отказ Gradle разбирать труднее, чем список.

    Предпосылки:
      * JDK 17 (допустимо 17…21). JDK 25 для AGP 8.2 слишком новый.
      * Gradle: либо gradle/wrapper/gradle-wrapper.jar, либо установленный gradle в PATH.
      * app/libs/apf.aar — собирается через build_aar.ps1 (этап Э-1).
      * app/src/main/jniLibs/arm64-v8a/libsingbox.so — кладётся через fetch_singbox.ps1.

    Кэш Gradle направляется на диск D: (правило проекта: писать только на D:).

    После сборки APK разбирается на месте: пакет, версия, ABI, набор .so и «мёртвое
    пространство» (см. -Clean). Артефакт, который едет на стенд, обязан состоять
    ровно из того, что собрано, иначе его размер ничего не значит.

.EXAMPLE
    .\build_apk.ps1                 # проверить предпосылки и собрать debug
    .\build_apk.ps1 -Clean          # эталонная сборка с нуля
    .\build_apk.ps1 -Variant release
#>
[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string]$Variant = 'debug',

    [string]$JavaHome,
    [string]$GradleUserHome = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand\gradle-home')),

    # Путь к gradle.bat, если wrapper не подготовлен.
    [string]$GradleExe,

    # Собрать с нуля. Обязателен, когда пересобран apf.aar или libsingbox.so:
    # инкрементальный упаковщик Gradle не умеет заменять .so на месте (см. D-T3).
    [switch]$Clean,

    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$sourceRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
$projectDir = (Join-Path (Split-Path $sourceRoot -Parent) 'android\android-project')

function Say     { param([string]$s) Write-Host $s }
function SayOK   { param([string]$s) Write-Host $s -ForegroundColor Green }
function SayWarn { param([string]$s) Write-Host $s -ForegroundColor Yellow }
function SayErr  { param([string]$s) Write-Host $s -ForegroundColor Red }

Write-Host ''
Write-Host ('=== APF · сборка APK ({0}) ===' -f $Variant) -ForegroundColor Cyan
Write-Host ''

if (-not (Test-Path $projectDir)) { SayErr ('  Проект не найден: {0}' -f $projectDir); exit 1 }
Say ('  Проект: {0}' -f $projectDir)

$missing = @()

# ─── JDK ──────────────────────────────────────────────────────────────────────

function Find-Jdk {
    if ($JavaHome -and (Test-Path $JavaHome)) { return $JavaHome }
    $candidates = @()
    foreach ($root in @('C:\Program Files\Java', 'C:\Program Files\Eclipse Adoptium',
                        'C:\Program Files\Microsoft', "$env:LOCALAPPDATA\Programs\Eclipse Adoptium")) {
        if (Test-Path $root) { $candidates += Get-ChildItem $root -Directory -ErrorAction SilentlyContinue }
    }
    # Предпочитаем 17, затем 18…21. 25 и выше AGP 8.2 не поддерживает.
    foreach ($want in @('17', '21', '20', '19', '18')) {
        $hit = $candidates | Where-Object { $_.Name -match "[-.]$want([.\-]|$)" } | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

$jdk = Find-Jdk
if ($jdk) {
    Say ('  JDK:            {0}' -f $jdk)
    if ($jdk -notmatch '17') { SayWarn '                  (рекомендуется JDK 17: AGP 8.2 проверен именно на нём)' }
} else {
    $missing += 'JDK 17 (скачать: https://adoptium.net/temurin/releases/?version=17)'
    SayErr '  JDK 17: НЕ НАЙДЕН'
}

# ─── Gradle ───────────────────────────────────────────────────────────────────

$wrapperJar = Join-Path $projectDir 'gradle\wrapper\gradle-wrapper.jar'
$gradlew = Join-Path $projectDir 'gradlew.bat'
$useWrapper = (Test-Path $wrapperJar) -and (Test-Path $gradlew)

if ($useWrapper) {
    Say '  Gradle:         wrapper'
} else {
    if (-not $GradleExe) {
        $g = Get-Command gradle.bat -ErrorAction SilentlyContinue
        if ($g) { $GradleExe = $g.Source }
    }
    if (-not $GradleExe) {
        # Дистрибутив, установленный fetch_gradle.ps1. Ищем самую свежую версию.
        $localGradleRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand\gradle'))
        $local = Get-ChildItem $localGradleRoot -Directory -ErrorAction SilentlyContinue |
                 Where-Object { Test-Path (Join-Path $_.FullName 'bin\gradle.bat') } |
                 Sort-Object Name -Descending | Select-Object -First 1
        if ($local) { $GradleExe = Join-Path $local.FullName 'bin\gradle.bat' }
    }
    if ($GradleExe -and (Test-Path $GradleExe)) {
        Say ('  Gradle:         {0}' -f $GradleExe)
    } else {
        $missing += 'Gradle 8.7 (либо gradle-wrapper.jar, либо дистрибутив: https://services.gradle.org/distributions/gradle-8.7-bin.zip)'
        SayErr '  Gradle:         НЕ НАЙДЕН (нет ни wrapper-jar, ни gradle в PATH)'
    }
}

# ─── Android SDK ──────────────────────────────────────────────────────────────

$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { 'C:\Android\Sdk' }
if (Test-Path $sdk) {
    Say ('  Android SDK:    {0}' -f $sdk)
    $plat34 = Join-Path $sdk 'platforms\android-34'
    if (-not (Test-Path $plat34)) { $missing += 'Android SDK Platform 34' ; SayErr '  Platform 34:    НЕТ' }
} else {
    $missing += 'Android SDK'
    SayErr '  Android SDK:    НЕ НАЙДЕН'
}

# ─── Артефакты проекта ────────────────────────────────────────────────────────

$aar = Join-Path $projectDir 'app\libs\apf.aar'
if (Test-Path $aar) {
    Say ('  apf.aar:        есть ({0:N1} МБ)' -f ((Get-Item $aar).Length / 1MB))
} else {
    $missing += 'app/libs/apf.aar — соберите: tools\android\build_aar.ps1 -Apply'
    SayErr '  apf.aar:        НЕТ'
}

$so = Join-Path $projectDir 'app\src\main\jniLibs\arm64-v8a\libsingbox.so'
if (Test-Path $so) {
    Say ('  libsingbox.so:  есть ({0:N1} МБ)' -f ((Get-Item $so).Length / 1MB))
} else {
    $missing += 'app/src/main/jniLibs/arm64-v8a/libsingbox.so — положите: tools\android\fetch_singbox.ps1 -Apply'
    SayErr '  libsingbox.so:  НЕТ'
}

Write-Host ''
if ($missing.Count -gt 0) {
    SayErr '  НЕ ХВАТАЕТ:'
    $missing | ForEach-Object { Say ('    - {0}' -f $_) }
    Write-Host ''
    exit 1
}
SayOK '  Все предпосылки на месте.'

if ($CheckOnly) { Write-Host ''; exit 0 }

# ─── Сборка ───────────────────────────────────────────────────────────────────

New-Item -ItemType Directory -Force -Path $GradleUserHome | Out-Null
$env:JAVA_HOME = $jdk
$env:ANDROID_HOME = $sdk
$env:GRADLE_USER_HOME = $GradleUserHome

$task = if ($Variant -eq 'release') { 'assembleRelease' } else { 'assembleDebug' }
# Тип объявлен явно: результат if-выражения идёт через конвейер, а тот разворачивает
# одноэлементный массив в строку. Без [string[]] сплаттинг @tasks передавал бы Gradle
# строку посимвольно, и он ругался на несуществующую задачу «s».
[string[]]$tasks = if ($Clean) { @('clean', $task) } else { @($task) }

Write-Host ''
Say ('  Запускаю {0} (кэш Gradle: {1}) ...' -f ($tasks -join ' '), $GradleUserHome)
Push-Location $projectDir
try {
    if ($useWrapper) { & $gradlew @tasks --no-daemon }
    else { & $GradleExe @tasks --no-daemon }
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host ''
if ($code -ne 0) { SayErr ('  Сборка упала, код {0}.' -f $code); Write-Host ''; exit 2 }

$apk = Get-ChildItem (Join-Path $projectDir 'app\build\outputs\apk') -Filter '*.apk' -Recurse -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $apk) { SayErr '  Сборка завершилась, но APK не найден.'; exit 2 }

# ─── Разбор готового APK (дефект D-T3) ────────────────────────────────────────
#
# Размер APK сам по себе ничего не подтверждает. Инкрементальный упаковщик Gradle
# (zipflinger) не умеет заменять запись на месте: когда пересобранный libgojni.so
# не влезает на старое место, новая копия дописывается в конец, а дыра затыкается
# цепочкой ЛОКАЛЬНЫХ заголовков без записей в центральном каталоге. Такой мусор
# невидим любому читателю zip — файл вырос на 5,35 МБ при неизменном содержимом.
# Поэтому считаем «мёртвое пространство» сами и не выпускаем артефакт с ним:
# на приёмке размер обязан объясняться содержимым.

function Get-ApkLayout {
    param([string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $offsetField = [System.IO.Compression.ZipArchiveEntry].GetField(
            '_offsetOfLocalHeader', 'NonPublic,Instance')
        $endOfData = 0
        $payload   = 0
        $libs      = @()
        foreach ($e in $zip.Entries) {
            # 30 байт — фиксированная часть локального заголовка; поле extra в нём
            # обычно пустое, поэтому оценка снизу, и она нас устраивает: искомый
            # мусор измеряется мегабайтами, а не байтами.
            $end = [int64]$offsetField.GetValue($e) + 30 + $e.FullName.Length + $e.CompressedLength
            if ($end -gt $endOfData) { $endOfData = $end }
            $payload += $e.CompressedLength
            if ($e.FullName -like 'lib/*') {
                $libs += [pscustomobject]@{ Name = $e.FullName; Mb = $e.Length / 1MB }
            }
        }
        [pscustomobject]@{
            Files    = $zip.Entries.Count
            Payload  = $payload
            DeadSpace = $endOfData - $payload - (30 * $zip.Entries.Count)
            Libs     = $libs
        }
    } finally { $zip.Dispose() }
}

$layout = Get-ApkLayout -Path $apk.FullName

Write-Host ''
SayOK ('  ГОТОВО: {0} ({1:N2} МБ)' -f $apk.FullName, ($apk.Length / 1MB))
Say   ('  Записей: {0}; полезных данных {1:N2} МБ' -f $layout.Files, ($layout.Payload / 1MB))
foreach ($lib in $layout.Libs) { Say ('    {0}  {1:N2} МБ (в распакованном виде)' -f $lib.Name, $lib.Mb) }

# aapt2 — если найден. Отсутствие не повод валить сборку: это справка, а не проверка.
$aapt2 = Get-ChildItem (Join-Path $sdk 'build-tools') -Filter 'aapt2.exe' -Recurse -ErrorAction SilentlyContinue |
         Sort-Object FullName -Descending | Select-Object -First 1
if ($aapt2) {
    $badging = & $aapt2.FullName dump badging $apk.FullName 2>$null
    # sdkVersion vs minSdkVersion: build-tools 34 печатает первое, 36 — второе.
    # Принимаем оба, иначе минимальная версия API молча пропадает из отчёта.
    $badging | Select-String -Pattern "^(package:|(min)?sdkVersion:|targetSdkVersion:|native-code:)" |
        ForEach-Object { Say ('    {0}' -f $_.ToString().Trim()) }
}

if ($layout.DeadSpace -gt 1MB) {
    Write-Host ''
    SayErr ('  В APK {0:N2} МБ мёртвого пространства.' -f ($layout.DeadSpace / 1MB))
    Say    '  Это следы прошлой сборки: Gradle заменил нативную библиотеку, дописав новую'
    Say    '  копию в конец, а старое место забив заглушками без записей в каталоге.'
    Say    '  Артефакт с таким довеском на стенд не выпускаем — соберите заново:'
    Write-Host ''
    Say   ('    tools\android\build_apk.ps1 -Variant {0} -Clean' -f $Variant)
    Write-Host ''
    exit 3
}

Write-Host ''
Say  '  Установка на телефон:'
Say ('    tools\android\apf_phone.ps1 -Action Install -ApkPath "{0}"' -f $apk.FullName)
Write-Host ''
exit 0
