# Сборка APF из исходников

Все команды — для Windows (PowerShell), если не сказано иное. Пути даны относительно корня
репозитория.

## Что нужно

| Компонент | Версия | Для чего |
|---|---|---|
| Go | 1.25+ | движок, служба, настольное приложение, мост Android, посредник |
| Node.js + npm | 18+ | фронтенд настольного приложения (Vite) |
| NSIS | 3.x | установщик Windows |
| Android SDK | platform 34 | приложение Android |
| Android NDK | r27+ | мост Go → Android (gomobile) |
| JDK | 17–21 | Gradle / Android Gradle Plugin |
| Gradle | 8.7+ | сборка APK |

## 1. Зависимости Go

Каталог `vendor/` в репозиторий не входит (он большой и полностью восстанавливается):

```powershell
cd source
go mod vendor
.\tools\patch_vendor.ps1   # локальный патч sing-box для GOOS=android, см. комментарий в скрипте
```

## 2. Тесты

```powershell
cd source
go test -timeout 30m ./internal/... ./mobile/...
```

Тесты **никогда** не запускают настоящий sing-box и не меняют состояние системы (фаервол,
прокси, DNS, маршруты): такие операции закрыты барьером `internal/hostguard`, а сетевой
выход — `internal/netguard`. Живые испытания делайте на отдельной машине или виртуальной
машине, не на рабочем компьютере.

Настольное приложение — отдельный Go-модуль, его тесты запускаются из его каталога:

```powershell
cd source\gui
go test ./...
```

## 3. Windows: приложение, служба, установщик

Всегда собирайте с `-trimpath` — иначе в бинарник попадут абсолютные пути вашей машины
(каталоги проекта и имя учётной записи).

```powershell
cd source

# служба (движок + Kill Switch + веб-интерфейс)
go build -trimpath -ldflags "-s -w" -o bin\apf-svc.exe ./cmd/apf-svc

# фронтенд настольного приложения
cd gui\frontend
npm ci
npm run build
cd ..

# настольное приложение (Wails v2). Вариант без Wails CLI:
go build -trimpath -tags "desktop,production" -ldflags "-w -s -H windowsgui" -o build\bin\APF.exe .
cd ..
```

Можно собирать и через Wails CLI (`wails build -trimpath`), если он у вас установлен.

Установщик ожидает в корне репозитория каталог `windows\bin` (в git не входит) с файлами из
официального релиза sing-box для Windows amd64 (`sing-box-<версия>-windows-amd64.zip`):
`sing-box.exe` и `libcronet.dll`. `wintun.dll` берётся из `vendor/` (см. шаг 1). Версия sing-box — константа `SingBoxVersion` в
`source/internal/singbox/process.go`.

```powershell
cd source
& "C:\Program Files (x86)\NSIS\makensis.exe" /INPUTCHARSET UTF8 installer\apf.nsi       # полный
& "C:\Program Files (x86)\NSIS\makensis.exe" /INPUTCHARSET UTF8 installer\apf-core.nsi  # облегчённый
```

Результат — `source\dist\APF-Setup-<версия>.exe`.

## 4. Android

```powershell
cd source

# sing-box для Android (исполняемый файл под именем libsingbox.so)
.\tools\android\fetch_singbox.ps1 -Apply

# мост Go → Android: android\android-project\app\libs\apf.aar
.\tools\android\build_aar.ps1 -Apply

# APK (debug). -Clean обязателен после пересборки apf.aar или libsingbox.so
.\tools\android\build_apk.ps1 -Clean
```

`build_aar.ps1` сам ставит `gomobile`/`gobind` нужной версии (из `go.mod`), применяет патч
к кэшу модулей и собирает мост с обязательными тегами
`with_clash_api,with_utls,with_gvisor,with_wireguard` и `-trimpath`.
Без этих тегов приложение соберётся, но не сможет подключаться (Reality, TUN, Clash API).

Путь к Android SDK задайте переменной `ANDROID_HOME` или в
`android/android-project/local.properties` (`sdk.dir=...`; файл в репозиторий не входит).

## 5. Посредник `apf-relay` (Linux-сервер)

```bash
cd source
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o apf-relay ./cmd/apf-relay
./apf-relay -addr :9443 -cert-dir /var/lib/apf-relay
```

При первом запуске `apf-relay` создаёт самоподписанный TLS-сертификат и печатает его
отпечаток — его вводят в настройках роли «Выход» вместе с адресом посредника.
Флаги: `-addr`, `-cert-dir`, `-max-exits`, `-max-conns-per-ip`, `-shutdown-grace`.

## Версия

Номер версии хранится в четырёх местах и должен совпадать (часть из них сверяет тест
`internal/version`): `source/internal/version/version.go`, `source/installer/apf.nsi`,
`source/installer/apf-core.nsi` (`APP_VERSION`) и `android/android-project/app/build.gradle`
(`versionName`/`versionCode`).
