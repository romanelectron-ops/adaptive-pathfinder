#Requires -Version 5.1
<#
.SYNOPSIS
    Сборка apf.aar — моста между Go-ядром APF и Android-приложением (этап Э-1).

.DESCRIPTION
    Прав администратора НЕ требует. БЕЗ ключа -Apply ничего не делает: показывает план,
    что будет скачано и что изменится в проекте. Это намеренно — шаг меняет go.mod и
    каталог vendor, а такие изменения не должны происходить молча.

    Что требуется и почему:

    1. gomobile и gobind. В системе их нет. Ставятся командой go install в каталог на
       диске D: (переменная GOBIN), чтобы не разносить файлы по профилю пользователя.
       ТРЕБУЕТСЯ СЕТЬ: модуль golang.org/x/mobile скачивается из прокси Go.

    2. golang.org/x/mobile/bind как зависимость модуля. Сейчас НЕ вендорен: в
       vendor/modules.txt его нет. gomobile bind без него не соберётся, потому что
       проект собирается с GOFLAGS=-mod=vendor. Значит нужны go get + go mod vendor,
       и это ИЗМЕНИТ go.mod, go.sum и содержимое vendor/.

    3. NDK. На машине есть (C:\Android\Sdk\ndk\...), но переменная ANDROID_NDK_HOME
       не выставлена — gomobile его не найдёт.

    4. Патч experimental/libbox/pidfd_android.go В КЭШЕ МОДУЛЕЙ (не в vendor/).
       gomobile bind собирается с -mod=mod (см. пункт «ВАЖНО» ниже) и берёт исходники
       sing-box из GOMODCACHE, а не из vendor/ — поэтому правка, уже применённая к
       vendor/.../pidfd_android.go (TZ_ANDROID_E4_v1.1.md §3.2, снимает
       "invalid reference to os.checkPidfdOnce" на GOOS=android), туда не долетает.
       Без повторения патча здесь линковка apf.aar падает с той же ошибкой — она и
       падала при первой попытке сборки после Э-4 Ш-1/Ш-2/Ш-3, пока это не обнаружилось.
       Патч идемпотентен: безопасно применять на каждой сборке.

    После сборки ОБЯЗАТЕЛЬНО сверить имена методов в сгенерированном
    androidbridge/Androidbridge.java с тем, что вызывает app/.../ApfCore.kt:
    gomobile переводит имена в нижний верблюжий регистр (Init → init), и если
    соглашение окажется иным, правка нужна только в ApfCore.kt.

.EXAMPLE
    .\build_aar.ps1              # показать план, ничего не менять
    .\build_aar.ps1 -Apply       # выполнить
#>
[CmdletBinding()]
param(
    [switch]$Apply,

    # Куда ставить gomobile/gobind (правило проекта: все файлы проекта, включая
    # кэши сборки, — внутри папки проекта; на D:\APF-Stand переносить нельзя,
    # это отдельный диск/папка вне проекта).
    [string]$GoBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand\gobin')),

    # Кэш модулей Go (та же логика — внутри папки проекта). БЕЗ явного задания
    # gomobile/go используют системный умолчательный путь (обычно на C:) — так уже
    # случилось один раз при разработке Э-4: сборка ушла ~2,5 ГБ в
    # C:\Users\<user>\go\pkg\mod, потому что переменная не была выставлена явно.
    [string]$GoModCache = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..\APF-Stand\gomodcache')),

    [string]$NdkHome,

    # Минимальный уровень API. 26 — совпадает с minSdk приложения.
    [int]$AndroidApi = 26,

    [string]$Target = 'android/arm64'
)

$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$sourceRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path                    # ...\apf-dist\source
$aarOut = (Join-Path (Split-Path $sourceRoot -Parent) 'android\android-project\app\libs\apf.aar')

function Say     { param([string]$s) Write-Host $s }
function SayOK   { param([string]$s) Write-Host $s -ForegroundColor Green }
function SayWarn { param([string]$s) Write-Host $s -ForegroundColor Yellow }
function SayErr  { param([string]$s) Write-Host $s -ForegroundColor Red }

Write-Host ''
Write-Host '=== APF · сборка моста apf.aar (этап Э-1) ===' -ForegroundColor Cyan
Write-Host ''

# ─── Предпосылки ──────────────────────────────────────────────────────────────

$go = Get-Command go.exe -ErrorAction SilentlyContinue
if (-not $go) { SayErr '  go.exe не найден в PATH.'; exit 1 }
Say ('  Go:            {0}' -f (& go version))

if (-not $NdkHome) {
    if ($env:ANDROID_NDK_HOME) {
        $NdkHome = $env:ANDROID_NDK_HOME
    } else {
        $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { 'C:\Android\Sdk' }
        $ndkRoot = Join-Path $sdk 'ndk'
        if (Test-Path $ndkRoot) {
            $newest = Get-ChildItem $ndkRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($newest) { $NdkHome = $newest.FullName }
        }
    }
}
if (-not $NdkHome -or -not (Test-Path $NdkHome)) {
    SayErr '  NDK не найден. Укажите -NdkHome или выставьте ANDROID_NDK_HOME.'
    exit 1
}
Say ('  NDK:           {0}' -f $NdkHome)
Say ('  Модуль:        {0}' -f $sourceRoot)
Say ('  Результат:     {0}' -f $aarOut)
Say ('  GOBIN:         {0}' -f $GoBin)
Say ('  GOMODCACHE:    {0}' -f $GoModCache)

$required = $false
$goMod = Join-Path $sourceRoot 'go.mod'
if (Test-Path $goMod) {
    $required = [bool](Select-String -Path $goMod -Pattern 'golang.org/x/mobile' -Quiet)
}
Say ('  x/mobile в go.mod: {0}' -f $(if ($required) { 'да' } else { 'НЕТ — потребуется go get' }))

# ─── План ─────────────────────────────────────────────────────────────────────

Write-Host ''
Say 'БУДЕТ ВЫПОЛНЕНО:'
Say ('  1. go install golang.org/x/mobile/cmd/gomobile@latest   (скачивание из сети)')
Say ('  2. go install golang.org/x/mobile/cmd/gobind@latest      (скачивание из сети)')
Say ('  3. gomobile init                                          (подготовка NDK-окружения)')
if (-not $required) {
    Say ('  4. go get golang.org/x/mobile/bind    ← ИЗМЕНИТ go.mod и go.sum')
}
Say ('  5. патч pidfd_android.go в GOMODCACHE (см. пункт 4 выше в описании)')
Say ('  6. сборка идёт с -mod=mod; каталог vendor/ НЕ трогается')
Say ('  7. gomobile bind -target={0} -androidapi {1} -o <apf.aar> ./mobile/androidbridge' -f $Target, $AndroidApi)
Write-Host ''

if (-not $Apply) {
    SayWarn '  Это предварительный просмотр. Ничего не изменено.'
    SayWarn '  Для выполнения добавьте -Apply.'
    Write-Host ''
    exit 0
}

# ─── Выполнение ───────────────────────────────────────────────────────────────

New-Item -ItemType Directory -Force -Path $GoBin | Out-Null
New-Item -ItemType Directory -Force -Path $GoModCache | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $aarOut -Parent) | Out-Null

$env:GOBIN = $GoBin
$env:GOMODCACHE = $GoModCache
$env:ANDROID_NDK_HOME = $NdkHome
$env:ANDROID_HOME = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { 'C:\Android\Sdk' }
$env:PATH = "$GoBin;$env:PATH"

# go install должен идти БЕЗ -mod=vendor: он ставит сторонний инструмент,
# а не собирает наш модуль.
$savedGoFlags = $env:GOFLAGS
$env:GOFLAGS = ''

# Версия x/mobile берётся ИЗ go.mod, а не @latest.
#
# Причина (2026-08-24, сломанная сборка): upstream поднял требование до Go >= 1.26, и
# `go install ...@latest` начал падать на Go 1.25 — сборка Android умирала на первом шаге,
# хотя в go.mod у нас закреплена рабочая версия. Ставить инструмент той же версии, что и
# библиотека, с которой он биндит, правильнее и само по себе: расхождение gomobile и
# x/mobile — известный источник трудноуловимых ошибок генерации.
$mobileVersion = (& go list -m -f '{{.Version}}' golang.org/x/mobile 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($mobileVersion)) {
    SayErr '  не удалось определить версию golang.org/x/mobile из go.mod'
    exit 2
}
Say ("  версия x/mobile из go.mod: {0}" -f $mobileVersion)

Say '  [1/6] Ставлю gomobile ...'
& go install ("golang.org/x/mobile/cmd/gomobile@{0}" -f $mobileVersion)
if ($LASTEXITCODE -ne 0) { SayErr '  не удалось установить gomobile'; exit 2 }

Say '  [2/6] Ставлю gobind ...'
& go install ("golang.org/x/mobile/cmd/gobind@{0}" -f $mobileVersion)
if ($LASTEXITCODE -ne 0) { SayErr '  не удалось установить gobind'; exit 2 }

Say '  [3/6] gomobile init ...'
# НЕ фатально, и оборачивается try/catch, а не просто проверкой $LASTEXITCODE — при
# $ErrorActionPreference='Stop' (стоит в начале файла) PowerShell превращает ЛЮБОЙ ненулевой
# выход нативной команды в терминирующий NativeCommandError ДО того, как скрипт доходит до
# следующей строки — проверка "if ($LASTEXITCODE -ne 0)" была мертва: сама попытка её
# выполнить никогда не наступала, скрипт падал прямо на вызове gomobile.exe (живой сбой
# 2026-08-24). try/catch перехватывает это здесь же, локально, не ослабляя Stop для всего
# остального скрипта.
#
# Сам сбой внутри — `gomobile init` делает `go install gobind@latest`, а с 2026-08-24 upstream
# требует Go >= 1.26 — на Go 1.25 этот внутренний вызов падает, хотя gobind нужной версии мы
# уже поставили шагом выше явно, и NDK-окружение подготовлено. Единственная задача init —
# разложить NDK-обвязку; если она не разложена или сломана, следующий шаг (`gomobile bind`)
# упадёт сам и с внятной ошибкой, поэтому останавливать сборку здесь значит блокировать её
# из-за постороннего сбоя.
try {
    & (Join-Path $GoBin 'gomobile.exe') init
} catch {
    Say '  gomobile init отказал (обычно — внутренний go install @latest на старом Go).'
    Say '  Продолжаю: gobind нужной версии уже установлен, реальную проблему покажет bind.'
}

Push-Location $sourceRoot
try {
    if (-not $required) {
        Say '  [4/6] go get golang.org/x/mobile/bind ...'
        & go get golang.org/x/mobile/bind
        if ($LASTEXITCODE -ne 0) { SayErr '  go get не отработал'; exit 2 }
    } else {
        Say '  [4/6] пропущено: x/mobile уже в go.mod'
    }

    # Патч pidfd_android.go в GOMODCACHE — см. пункт 4 в описании скрипта.
    # Версия берётся из go.mod текстовым поиском (тот же приём, что уже используется
    # выше для x/mobile), а не через `go list -m -f {{.Dir}}` — тот в этом окружении
    # изредка возвращает пустой вывод (расхождение -mod между вызовами), и Join-Path
    # падает на null раньше, чем становится ясно, что пошло не так.
    Say '  [5/6] патч pidfd_android.go (кэш модулей) ...'
    $sbLine = Select-String -Path $goMod -Pattern 'github\.com/sagernet/sing-box\s+(v\S+)' | Select-Object -First 1
    if (-not $sbLine) {
        SayErr '  github.com/sagernet/sing-box не найден в go.mod — не могу применить патч'
        exit 2
    }
    $sbVersion = $sbLine.Matches[0].Groups[1].Value
    & go mod download ('github.com/sagernet/sing-box@' + $sbVersion)
    if ($LASTEXITCODE -ne 0) { SayErr '  go mod download sing-box не отработал'; exit 2 }
    $pidfdFile = Join-Path $GoModCache ('github.com\sagernet\sing-box@{0}\experimental\libbox\pidfd_android.go' -f $sbVersion)
    if (-not (Test-Path $pidfdFile)) {
        SayErr ('  не найден {0} — не могу применить патч' -f $pidfdFile)
        exit 2
    }
    Set-ItemProperty -Path $pidfdFile -Name IsReadOnly -Value $false
    # PowerShell 5.1: Set-Content -Encoding utf8 пишет БЕЗ BOM только начиная с 6+;
    # здесь пишем вручную через .NET, иначе Go откажется компилировать файл с BOM
    # ("illegal character U+FEFF").
    $pidfdContent = @'
package libbox

// ПРАВКА APF (патч кэша модулей, применяется автоматически этим скриптом при каждой
// сборке — см. source/docs/TZ_ANDROID_E4_v1.1.md §3.2 и
// vendor/github.com/sagernet/sing-box/experimental/libbox/pidfd_android.go, тот же патч).
// Оригинал делал //go:linkname checkPidfdOnce os.checkPidfdOnce, обходя golang/go#70508;
// в android-сборке пакета os этого символа нет (есть только в os/pidfd_linux.go, строго
// GOOS=linux) — компоновщик Go 1.26.2 отказывает на "invalid reference to
// os.checkPidfdOnce". android и так не использует pidfd (os/pidfd_other.go), так что
// исходный манёвр — мёртвый код на этом тулчейне.
'@
    [System.IO.File]::WriteAllText($pidfdFile, $pidfdContent, (New-Object System.Text.UTF8Encoding $false))
    SayOK ('        {0}' -f $pidfdFile)

    # ВАЖНО: bind идёт с -mod=mod, а не -mod=vendor.
    #
    # `go mod vendor` вендорит только те пакеты, которые кто-то ИМПОРТИРУЕТ. Ни один
    # наш файл не импортирует golang.org/x/mobile, поэтому в vendor/ он попадает как
    # пустая запись, и gomobile отказывает: «not in the module dependency graph».
    # Заставить вендор его подхватить можно только tool-директивой, но тогда в проект
    # уезжает весь golang.org/x/tools — тысячи файлов ради инструмента сборки.
    # Поэтому мост собирается из кэша модулей, а vendor/ остаётся нетронутым:
    # основная сборка проекта продолжает идти с -mod=vendor, как и раньше.
    Say ('  [6/6] gomobile bind → {0}' -f $aarOut)
    $env:GOFLAGS = '-mod=mod'
    # -tags with_clash_api ОБЯЗАТЕЛЕН (находка Ш-6, приёмка на устройстве). libbox.NewCommandServer
    # (InProcessRunner, режим VPN) всегда взводит options.PlatformLogWriter, а box.New() при
    # этом БЕЗУСЛОВНО требует experimental clash-server (sing-box box.go: needClashAPI =
    # experimentalOptions.ClashAPI != nil || options.PlatformLogWriter != nil) — независимо от
    # того, что реально в конфигурации. Без тега линкуется только заглушка
    # (include/clashapi_stub.go), и КАЖДОЕ подключение в VPN-режиме отказывает на
    # StartOrReloadService с "clash api is not included in this build", живой узел или нет.
    #
    # -tags with_utls ОБЯЗАТЕЛЕН (находка 2026-08-10, разведка перед Э-Выход-1 — до реального
    # подключения на устройстве не дошло). VLESS+Reality — ОСНОВНОЙ протокол APF (config_builder.go
    # buildTLS ставит UTLS+Reality для любого узла с node.TLS.Reality != nil) — и клиентский, и
    # серверный путь Reality живут в common/tls/reality_client.go и reality_server.go, у ОБОИХ
    # `//go:build with_utls`. Без тега компонуется common/tls/utls_stub.go, и sing-box отказывает
    # на КАЖДОЙ попытке использовать Reality (клиент ИЛИ сервер) фразой "uTLS, which is required by
    # reality is not included in this build" — независимо от узла. Тот же класс дефекта, что и
    # with_clash_api: не «пул мёртв», а сборка не умеет протокол, которым APF пользуется по
    # умолчанию. Обнаружено при разборе vendor/.../common/tls перед реализацией ServerRunner
    # (docs/TZ_APF_VHOD_VYHOD_v1.0.md, Э-Выход-1) — там же лежит NewRealityServer с тем же тегом.
    #
    # -tags with_gvisor ОБЯЗАТЕЛЕН (находка 2026-08-10, живой прогон Э-Выход-1 на устройстве —
    # четвёртый по счёту слой того же класса дефекта). TunOptions.Stack всегда "mixed"
    # (config_builder.go) — sing-tun требует gVisor userspace-стек для этого режима (и для
    # "gvisor"). Без тега — заглушка, и КАЖДОЕ поднятие TUN отказывает на старте inbound'а:
    # "gVisor is not included in this build, rebuild with -tags with_gvisor" — опять до
    # какой-либо попытки дозвониться до узла.
    #
    # -tags with_wireguard ОБЯЗАТЕЛЕН (P1 ТЗ доработок relay/хвостов — пятый по счёту слой
    # того же класса дефекта, найден по аналогии при аудите 2026-09-01, живьём на устройстве
    # НЕ проверен). vendor/.../sing-box/include/wireguard.go: `//go:build with_wireguard`;
    # wireguard_stub.go: `//go:build !with_wireguard` — без тега компонуется заглушка,
    # возвращающая "WireGuard is not included in this build, rebuild with -tags
    # with_wireguard". internal/singbox/config_builder.go собирает WireGuard-узлы через
    # ОТДЕЛЬНЫЙ endpoint-путь (nodeToEndpoint, см. кластер B, TZ_TAILS_HARDENING_2026-08-31.md)
    # именно в этом же пакете — без тега сборка Android .aar и десктопной сборки была бы
    # рассинхронизирована по составу поддерживаемых протоколов теми же средствами, какими
    # уже рассинхронизировались Reality/ClashAPI/gVisor до находок выше.
    #
    # -trimpath ОБЯЗАТЕЛЕН (2026-09-29, подготовка открытых релизов): без него Go вшивает в
    # libgojni.so абсолютные пути сборочной машины — каталог проекта и кэш модулей с именем
    # учётной записи Windows (найдено сканом APK 1.1.9: тысячи вхождений). Бинарник, который
    # уходит наружу, не должен раскрывать, на чьей машине и в каких папках он собран.
    & (Join-Path $GoBin 'gomobile.exe') bind `
        -target $Target `
        -androidapi $AndroidApi `
        -tags with_clash_api,with_utls,with_gvisor,with_wireguard `
        -trimpath `
        -o $aarOut `
        ./mobile/androidbridge
    $bindCode = $LASTEXITCODE
} finally {
    Pop-Location
    $env:GOFLAGS = $savedGoFlags
}

Write-Host ''
if ($bindCode -ne 0 -or -not (Test-Path $aarOut)) {
    SayErr '  Сборка моста не удалась.'
    Write-Host ''
    exit 2
}

SayOK ('  ГОТОВО: {0} ({1:N1} МБ)' -f $aarOut, ((Get-Item $aarOut).Length / 1MB))
Write-Host ''
SayWarn '  ОБЯЗАТЕЛЬНЫЙ СЛЕДУЮЩИЙ ШАГ: сверить имена методов.'
Say     '  Откройте apf.aar как zip → classes.jar → androidbridge/Androidbridge.class'
Say     '  (или сгенерированный .java) и убедитесь, что имена совпадают с вызовами в'
Say     '  app/src/main/java/com/apf/app/ApfCore.kt. gomobile переводит Init → init.'
Write-Host ''
exit 0
