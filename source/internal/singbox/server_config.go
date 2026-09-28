package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// ─── Серверный (роль «Выход»/«Транзит») JSON-документ ────────────────────────────
//
// Отдельные типы от клиентских Config/Inbound (config_builder.go), не обвязка вокруг
// них — решение зафиксировано в docs/PLAN_APF_VHOD_VYHOD_v1.0.md («следующий шаг»):
// клиентский Inbound моделирует socks/http/tun и не имеет полей users/tls, которые
// нужны серверному VLESS+Reality inbound. Смешивать их в одном []Inbound было бы
// неверно типизировано — раздельные структуры честнее, чем один тип с наполовину
// пустыми полями в обе стороны.
//
// LogConfig/Outbound/RouteConfig/DomainResolver/DNSConfig/DNSServer — общие понятия
// sing-box, уже определены в config_builder.go, переиспользуются без изменений.

// ServerInboundUser — один клиент, которому разрешено подключаться (ТЗ §2: у звена может
// быть несколько выданных ссылок с разными UUID, но одним и тем же Reality-ключом сервера).
type ServerInboundUser struct {
	Name string `json:"name,omitempty"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

// ServerRealityHandshake — куда «Выход» ходит за настоящим TLS-хендшейком для маскировки
// (ТЗ §2: Reality маскирует хендшейк сервера под настоящий сайт).
type ServerRealityHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// ServerInboundReality — серверная сторона Reality: приватный ключ (не публикуется),
// список допустимых short_id, цель для маскировочного хендшейка.
type ServerInboundReality struct {
	Enabled    bool                   `json:"enabled"`
	Handshake  ServerRealityHandshake `json:"handshake"`
	PrivateKey string                 `json:"private_key"`
	ShortID    []string               `json:"short_id"`
}

// ServerInboundTLS — контейнер TLS для серверного inbound (по аналогии с клиентским
// OutboundTLS в config_builder.go, но на стороне сервера).
type ServerInboundTLS struct {
	Enabled    bool                  `json:"enabled"`
	ServerName string                `json:"server_name,omitempty"`
	Reality    *ServerInboundReality `json:"reality,omitempty"`
}

// ServerInbound — VLESS+Reality inbound (ТЗ §2: основной протокол «Выхода»).
type ServerInbound struct {
	Type       string              `json:"type"`
	Tag        string              `json:"tag"`
	Listen     string              `json:"listen"`
	ListenPort int                 `json:"listen_port"`
	Users      []ServerInboundUser `json:"users"`
	TLS        *ServerInboundTLS   `json:"tls,omitempty"`
}

// ServerDoc — корневой JSON-документ серверного режима: принять VLESS+Reality, отдать в
// открытый интернет (роль «Выход») напрямую. Роль «Транзит» (Выход+Вход одного процесса,
// ТЗ §1, Э-Цепочки-1) добавит свой исходящий outbound вместо/вместе с "direct" — не
// предмет этого файла (Этап Э-Выход-1 — только «Выход»).
type ServerDoc struct {
	Log          LogConfig           `json:"log"`
	DNS          DNSConfig           `json:"dns"`
	Inbounds     []ServerInbound     `json:"inbounds"`
	Outbounds    []Outbound          `json:"outbounds"`
	Route        RouteConfig         `json:"route"`
	Experimental *ExperimentalConfig `json:"experimental,omitempty"`
}

// ServerClashAPIPort — порт встроенного Clash-API роли «Выход» (§5): фиксированное
// смещение от listenPort основного VLESS-инбаунда, а не отдельный настраиваемый порт —
// роли «Выход» и клиента (ClashAPI в config_builder.go, ListenPort+2 от SOCKS-порта)
// живут на РАЗНЫХ базовых портах (443/8443/... у сервера против 10808 у клиента), поэтому
// коллизия между ними исключена без явной настройки (docs/PLAN_2026-08-28_
// stubs_and_realfunc.md §5, п.1). Экспортирован — engine.go спрашивает тот же порт,
// которым сервер объявил себя в BuildServerConfig, без дублирования формулы. Оборачивается,
// чтобы остаться в валидном диапазоне портов даже для listenPort у верхней границы.
func ServerClashAPIPort(listenPort int) int {
	p := listenPort + 1
	if p > 65535 {
		p = listenPort - 1
	}
	return p
}

// BuildServerConfig собирает минимальный рабочий серверный документ: один VLESS+Reality
// inbound на listenPort, один direct outbound (роль «Выход» — последнее звено, отдаёт
// трафик в интернет как есть). DNS/Route — тот же паттерн, что уже проверен в
// TestInProcessRunner_StartWithRealConfig_DoesNotPanic (local-резолвер, без него sing-box
// 1.12+ отказывает целиком с "missing route.default_domain_resolver", см. дефект D-A27).
//
//	Вход:      identity (см. GenerateServerIdentity), listenPort (1..65535), realityDest —
//	           куда ходить за маскировочным хендшейком (см. GoodRealitySNI).
//	Тело:      один пользователь (identity.UUID), Reality с приватным ключом и одним short_id
//	           из identity, слушает ТОЛЬКО на loopback (127.0.0.1).
//	Выход:     готовый *ServerDoc, сериализуемый через ToServerJSON.
//	Fail-safe: не валидирует listenPort/realityDest — это забота вызывающей стороны
//	           (Reachability, ТЗ §3) ДО вызова; здесь — чистая сборка структуры.
//
// [CRITICAL, найдено 2026-08-29 при живом тесте на Redmi+ПК] Раньше здесь стояло "::" (все
// интерфейсы) — оставалось от эпохи ДО AdmissionProxy (Фаза C/D/E, docs/TZ_APF_RELAY_v1.0.md
// §10.2), когда listenPort и был публичным портом из ссылки, и sing-box был обязан слушать
// его отовсюду. С admission-control listenPort, который сюда передают ОБА вызывающих
// (internal/engine/server_role.go, mobile/androidbridge/server_role.go), — это ВСЕГДА
// внутренний эфемерный порт за AdmissionProxy (реальный публичный порт слушает она, не
// sing-box), а AdmissionProxy дозванивается сюда именно по "127.0.0.1:<порт>" (см.
// NewAdmissionProxy в обоих файлах). "::" оставлял внутренний Reality-листенер доступным
// СНАРУЖИ напрямую — с тем же портом можно было полностью обойти лимит подключений
// (весь смысл admission-control), просто подключившись мимо AdmissionProxy. "127.0.0.1"
// делает такой обход физически невозможным: сокет не принимает пакеты не с loopback.
func BuildServerConfig(identity ServerIdentity, listenPort int, realityDest string) *ServerDoc {
	return &ServerDoc{
		Log: LogConfig{Level: "info"},
		// Находка живого прогона Э-Выход-2 (2026-08-18): Type:"local" на Android разбирается
		// на резолвер localhost ([::1]:53), которого там нет — "read: connection refused"
		// на КАЖДОМ запросе, включая обязательный дозвон Reality до realityDest (см.
		// комментарий у Route.AutoDetectInterface ниже). platformAdapter.LocalDNSTransport()
		// честно возвращает nil (см. mobile/androidbridge/platform_adapter.go — платформенный
		// DNS-мост не реализован), поэтому "local" здесь не может означать ничего платформо-
		// специфичного. Обычный публичный резолвер по UDP — тот же класс решения, что уже
		// использует клиент для dns-local (config_builder.go), не выдуманный отдельно.
		DNS: DNSConfig{
			Servers: []DNSServer{{Type: "udp", Tag: "local", Server: "8.8.8.8"}},
		},
		Inbounds: []ServerInbound{
			{
				Type:       "vless",
				Tag:        "vless-in",
				Listen:     "127.0.0.1",
				ListenPort: listenPort,
				Users: []ServerInboundUser{
					{Name: "primary", UUID: identity.UUID, Flow: "xtls-rprx-vision"},
				},
				TLS: &ServerInboundTLS{
					Enabled:    true,
					ServerName: realityDest,
					Reality: &ServerInboundReality{
						Enabled:    true,
						Handshake:  ServerRealityHandshake{Server: realityDest, ServerPort: 443},
						PrivateKey: identity.PrivateKey,
						ShortID:    []string{identity.ShortID},
					},
				},
			},
		},
		Outbounds: []Outbound{{Type: "direct", Tag: "direct"}},
		// [найдено 2026-08-29, живой тест Redmi+ПК: одно устройство ОДНОВРЕМЕННО в роли
		// «Выход» (этот конфиг) и «Вход» (config_builder.go, свой отдельный sing-box-инстанс
		// через chain-partner/EntryBridge)] Оба инстанса поднимаются через один и тот же
		// механизм (libbox.CommandServer — InProcessRunner у клиента, AndroidServerRunner
		// здесь), и оба безусловно требуют cache-file (см. комментарий у Builder.baseConfig,
		// D-A35: needCacheFile = ... || PlatformLogWriter != nil). Раньше здесь ПУТЬ ВООБЩЕ
		// НЕ ЗАДАВАЛСЯ — sing-box брал дефолтный cache.db, что на практике совпадало с
		// путём, который клиентский baseConfig задаёт ЯВНО (config.DataDir()/cache.db):
		// при одновременной работе обеих ролей второй инстанс блокировался на файловой
		// блокировке первого и падал с "initialize cache-file: timeout" — воспроизведено
		// живьём (Redmi: «Выход» с 02:39:56, «Вход»-подключение к самому себе через relay в
		// 02:44/02:45 — оба раза FATAL timeout ровно на ~9.7с). Отдельный файл здесь
		// устраняет коллизию — тот же принцип, что уже применён к клиенту, другое имя.
		Experimental: &ExperimentalConfig{
			CacheFile: &CacheFileConfig{
				Enabled: true,
				Path:    filepath.Join(config.DataDir(), "server_cache.db"),
			},
			ClashAPI: &ClashAPIConfig{
				ExternalController: fmt.Sprintf("127.0.0.1:%d", ServerClashAPIPort(listenPort)),
			},
		},
		Route: RouteConfig{
			Final: "direct",
			// Находка живого прогона Э-Выход-2 (Android, 2026-08-18): захардкоженный true
			// ронял КАЖДОЕ подключение к Reality-инбаунду ("TLS handshake: REALITY: failed
			// to dial dest: lookup <sni>: ... no available network interface") — Reality-
			// сервер обязан сходить за настоящим сертификатом маскировочного хендшейка
			// (BuildServerConfig.realityDest) через тот же исходящий "direct" outbound, а
			// его дозвон на Android идёт через dialParallelInterface (vendor/.../common/
			// dialer/default_parallel_interface.go), которому нужен непустой список
			// интерфейсов от PlatformInterface.GetInterfaces() — mobile/androidbridge/
			// platform_adapter.go честно возвращает ПУСТОЙ список (Android не даёт узнать
			// интерфейсы этим путём), поэтому "нет интерфейса" ⇒ дозвон отказывает ещё до
			// какой-либо проверки подлинности клиента. Тот же класс дефекта, что и D-A28
			// ("netlink socket in Android is banned by Google") у клиентского пути — там
			// уже есть готовое решение (autoDetectInterfaceSupported(), config_builder.go):
			// переиспользуем его, а не дублируем платформенную развилку по-своему. На
			// Windows/Linux (Э-Выход-1/3) остаётся true — там нет платформенных ограничений
			// PlatformInterface, обычный net.Dialer видит интерфейсы сам.
			AutoDetectInterface:   autoDetectInterfaceSupported(),
			DefaultDomainResolver: &DomainResolver{Server: "local"},
		},
	}
}

// ToServerJSON сериализует ServerDoc в JSON (симметрично клиентскому ToJSON).
func ToServerJSON(doc *ServerDoc) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

// validateServerDoc — общая граница проверки перед Start, одна на все платформенные
// реализации ServerRunner (windows_server_runner.go, android_server_runner.go).
//
//	Вход:      *ServerDoc — необязательно результат BuildServerConfig, вызывающая сторона
//	           (WriteConfig любого ServerRunner) принимает его от любого кода.
//	Тело:      требует хотя бы один Inbound и listenPort в диапазоне 1..65535.
//	Выход:     nil при валидном doc.
//	Fail-safe: находка консилиума 2026-08-10 (CRITICAL) — раньше эта проверка не
//	           существовала вовсе, и listenPort=0 (или отсутствующий Inbounds) молча уходил
//	           в Start(): у Process это означало ветку awaitReady «признака готовности нет»
//	           (2 секунды сна и тихий «успех», хотя реальный sing-box слушал не тот порт или
//	           случайный эфемерный от ОС); у in-process путей (android_server_runner.go)
//	           тот же порт=0 означал бы то же самое молчаливое расхождение между «мы думаем,
//	           что слушаем 0» и тем, что sing-box выбрал сам. Граница должна быть здесь, а не
//	           полагаться на то, что каждая платформенная реализация продублирует её сама.
func validateServerDoc(doc *ServerDoc) error {
	if doc == nil {
		return errors.New("singbox: WriteConfig(nil ServerDoc)")
	}
	if len(doc.Inbounds) == 0 {
		return errors.New("singbox: WriteConfig(doc без Inbounds) — серверной роли нужен хотя бы один слушающий inbound")
	}
	port := doc.Inbounds[0].ListenPort
	if port < 1 || port > 65535 {
		return fmt.Errorf("singbox: WriteConfig: listenPort=%d вне диапазона 1..65535", port)
	}
	return nil
}
