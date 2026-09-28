# APF — Adaptive PathFinder

**APF** — открытый клиент обхода сетевых блокировок для **Windows** и **Android**. Он сам
находит рабочие прокси/VPN-узлы из публичных источников, проверяет их *реальным трафиком*
(а не только «порт открыт»), подключается к лучшему и переключается, когда узел умирает.
Отдельная роль **«Выход»** превращает ваш собственный компьютер или телефон в личную точку
выхода в интернет: другое устройство подключается к нему по ссылке, а сайты видят адрес
вашего устройства.

В основе — движок на Go и [sing-box](https://github.com/SagerNet/sing-box) (ядро протоколов).

> **Статус: экспериментальный.** Проект развивается и проверяется на ограниченном наборе
> устройств (Windows 11, Android 13 arm64). Честные ограничения и известные проблемы
> описаны в [docs/](docs/) — перед реальным использованием прочитайте их.

*English summary is [below](#english).*

---

## Возможности

**Подключение**
- Протоколы узлов: VLESS (в т.ч. Reality), VMess, Trojan, Shadowsocks — через sing-box.
  Роль «Выход» сейчас выдаёт узел VLESS+Reality.
- Два режима: **прокси** (локальные SOCKS5/HTTP, по желанию — системный прокси Windows) и
  **VPN** (TUN-интерфейс: весь трафик устройства идёт через туннель).
- Автоматический подбор узла: сбор узлов из источников, обход пула по TCP, **проба
  реальным трафиком** (HTTP-запрос через сам узел), ранжирование, избранное.
- Автопереключение при сбое, циклический поиск, режим цепочки и многохоповые цепочки.
- Аварийные резервы (Tor — если установлен).

**Защита**
- **Kill Switch**: на Windows — правила фаервола через отдельную службу; на Android — через
  системный «Всегда включённый VPN» и «Блокировать соединения без VPN».
- Защита от утечек DNS и IPv6, подсказки по WebRTC.
- Раздельное туннелирование: домены напрямую, приложения вне VPN.
- Блокировка рекламы и трекеров на уровне DNS.

**Своя точка выхода («Вход» → «Выход»)**
- Роль **«Выход»** на ПК или телефоне поднимает сервер VLESS+Reality и выдаёт ссылку.
- Устройство **«Вход»** вставляет ссылку — и выходит в интернет через «Выход». Сайты видят
  адрес «Выхода», промежуточные сети видят только зашифрованный поток.
- Если «Выход» недоступен снаружи (NAT/CGNAT), помогает **посредник (relay)** —
  программа `apf-relay` на любой машине с публичным адресом.

## Платформы

| Платформа | Что есть |
|---|---|
| Windows 10/11 (x64) | Приложение с окном и значком в трее, фоновая служба, веб-интерфейс, установщик |
| Android 8.0+ (arm64) | Приложение: режимы прокси и VPN, роль «Выход», Kill Switch через систему |
| Linux (x64) | `apf-relay` — посредник для роли «Выход» |

## Установка

Готовые сборки — в разделе [**Releases**](https://github.com/romanelectron-ops/adaptive-pathfinder/releases):
- `APF-Setup-<версия>.exe` — полный установщик для Windows;
- `APF-Setup-<версия>-core.exe` — облегчённый установщик для Windows;
- `APF-<версия>.apk` — Android (установка из файла; разрешите установку из этого источника).

Сборки не подписаны сертификатом издателя — Windows SmartScreen и Google Play Защита могут
предупредить при установке. Контрольные суммы SHA-256 приложены к каждому релизу.

## Сборка из исходников

Кратко:

```bash
cd source
go mod vendor
go test ./internal/... ./mobile/...
```

Полная инструкция (ПК, установщик, Android, посредник) — в [docs/BUILD.md](docs/BUILD.md).
Устройство проекта — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Структура репозитория

```
source/                 Go-модуль: движок, службы, настольное приложение, установщик
  cmd/                  точки входа: apf (CLI), apf-svc (служба), apf-tray, apf-relay
  internal/             движок и подсистемы (engine, singbox, checker, killswitch, relay, ...)
  mobile/androidbridge/ мост Go → Android (gomobile)
  gui/                  настольное приложение (Wails v2 + HTML/JS)
  installer/            сценарии установщика NSIS
  tools/                сборочные и служебные скрипты
android/android-project Android-приложение (Kotlin)
docs/                   документация
```

## Безопасность и приватность

- Проект **не содержит собственных серверов** и не собирает телеметрию.
- Автообновление только **уведомляет** о новой версии; само приложение не заменяет файлы —
  релизы пока не подписаны, обновляйтесь вручную со страницы Releases.
- Об уязвимостях — см. [SECURITY.md](SECURITY.md).

## Ответственность

APF — инструмент для доступа к информации и защиты приватности. Соблюдайте законы своей
страны. Если вы запускаете роль «Выход», весь трафик подключённых к вам устройств выходит
в интернет с **вашего** адреса — давайте ссылку только тем, кому доверяете.

## Лицензия

[GNU General Public License v3.0 or later](LICENSE). APF встраивает sing-box (GPL-3.0),
поэтому весь проект распространяется на тех же условиях. Сторонние компоненты и их
лицензии — в [NOTICE.md](NOTICE.md). APF — независимый проект и не связан с авторами
sing-box.

---

## English

**APF (Adaptive PathFinder)** is an open-source censorship-circumvention client for
**Windows** and **Android**. It collects proxy/VPN nodes from public sources, verifies them
with *real traffic*, connects to the best one and fails over automatically. The **Exit role**
turns your own PC or phone into a private internet exit that your other devices can connect
to via a link; a small **relay** (`apf-relay`) helps when the exit is behind NAT/CGNAT.

- Protocols (via sing-box): VLESS (incl. Reality), VMess, Trojan, Shadowsocks. The Exit role
  currently issues VLESS+Reality links.
- Proxy mode and full-device VPN (TUN) mode, Kill Switch, DNS/IPv6 leak protection,
  split tunnelling, DNS ad-blocking.
- Status: **experimental**. Downloads: see *Releases*. Build instructions: `docs/BUILD.md`.
- License: **GPL-3.0-or-later** (it embeds sing-box, GPL-3.0). Not affiliated with sing-box.
