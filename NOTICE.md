# Сторонние компоненты / Third-party components

APF распространяется под GPL-3.0-or-later (см. [LICENSE](LICENSE)). В проект входят или
используются им следующие компоненты; полные списки Go-зависимостей — в `source/go.mod`,
JavaScript — в `source/gui/frontend/package.json`.

| Компонент | Лицензия | Как используется |
|---|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | GPL-3.0-or-later (+ запрет использовать имя sing-box для обозначения связи с проектом) | ядро протоколов: библиотека libbox в приложении Android и настольном модуле; исполняемый файл в установщике Windows |
| [sing-tun](https://github.com/SagerNet/sing-tun), [sing](https://github.com/SagerNet/sing) и другие модули SagerNet | GPL-3.0 / см. репозитории | TUN, сетевые примитивы |
| [Wintun](https://www.wintun.net/) | Prebuilt Binaries License (распространение неизменённого `wintun.dll` в составе приложения разрешено) | TUN-драйвер Windows |
| libcronet (из релизов sing-box) | BSD-3-Clause (Chromium) | сетевой стек для отдельных транспортов sing-box |
| [Wails](https://github.com/wailsapp/wails) | MIT | настольное приложение |
| [gomobile](https://pkg.go.dev/golang.org/x/mobile) | BSD-3-Clause | мост Go → Android |
| [goupnp](https://github.com/tailscale/goupnp) | BSD-2-Clause | автоматический проброс порта (UPnP) |
| [Vite](https://vitejs.dev/) | MIT | сборка фронтенда |

APF — независимый проект и не связан с авторами sing-box или других перечисленных
компонентов. Названия продуктов принадлежат их владельцам.
