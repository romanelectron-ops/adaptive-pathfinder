package singbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

// ServerIdentity — ключи одного звена, сгенерированные при первом запуске роли
// «Выход»/«Транзит» (ТЗ §2: «у каждого звена цепочки свой независимый ключ»). Генерируется
// ОДИН раз и хранится вызывающей стороной; ServerConfig (server_config.go) собирается заново
// на каждый Start(), Identity — нет.
type ServerIdentity struct {
	UUID       string
	PrivateKey string // base64.RawURLEncoding — для tls.reality.private_key (inbound)
	PublicKey  string // base64.RawURLEncoding — для ссылки vless://...?pbk=...
	ShortID    string // hex, 8 байт — для short_id (inbound) И ?sid=... (ссылка)
}

// GenerateServerIdentity генерирует новый независимый UUID + X25519-пару + short_id тем же
// способом, что и справочные генераторы Reality-ключей (xray x25519 и подобные): 32
// случайных байта как приватный ключ, скалярное умножение на базовую точку Curve25519 —
// публичный, без ручного клэмпинга (X25519 в golang.org/x/crypto/curve25519 и в
// common/tls/reality_server.go на стороне sing-box клэмпит сам при использовании).
//
//	Вход:      нет — источник случайности crypto/rand.
//	Тело:      UUID v4; X25519-пара; short_id — 8 случайных байт в hex (совпадает с лимитом
//	           sing-box: reality_server.go отвергает short_id длиннее 8 байт).
//	Выход:     ServerIdentity с готовыми для JSON-конфигурации и для ссылки полями.
//	Fail-safe: единственный источник ошибки — crypto/rand не смог выдать случайность
//	           (истощение ОС-источника энтропии); тогда ключи НЕ «додумываются» — ошибка.
//	Инвариант: два вызова НИКОГДА не возвращают одинаковый UUID/ключ (не в статистическом
//	           смысле — crypto/rand, не math/rand).
func GenerateServerIdentity() (ServerIdentity, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return ServerIdentity{}, fmt.Errorf("singbox: генерация UUID: %w", err)
	}

	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return ServerIdentity{}, fmt.Errorf("singbox: генерация приватного ключа: %w", err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return ServerIdentity{}, fmt.Errorf("singbox: вычисление публичного ключа: %w", err)
	}

	shortIDBytes := make([]byte, 8)
	if _, err := rand.Read(shortIDBytes); err != nil {
		return ServerIdentity{}, fmt.Errorf("singbox: генерация short_id: %w", err)
	}

	return ServerIdentity{
		UUID:       u.String(),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		ShortID:    hex.EncodeToString(shortIDBytes),
	}, nil
}

// BuildServerLink собирает готовую vless://-ссылку для передачи «Входу» (ТЗ §5.2, шаг
// «Готово — вот ваша ссылка»). Формат и имена query-параметров ЗЕРКАЛЬНЫ тому, что уже
// разбирает internal/parser.parseVLESS (uuid@host:port?flow=...&security=reality&sni=...
// &pbk=...&sid=...#label) — round-trip проверен тестом в этом же пакете, чтобы формат
// сервера и формат клиентского парсера не разошлись молча.
//
//	Вход:      identity, host (куда «Вход» будет физически подключаться — домен/IP,
//	           doc.Reachability отвечает за то, что оно достижимо снаружи), port, realityDest
//	           (тот же SNI, что и в BuildServerConfig), label — человекочитаемое имя звена.
//	Выход:     готовая строка ссылки.
//	Fail-safe: не проверяет достижимость host — это не его ответственность (см. internal/relay).
func BuildServerLink(identity ServerIdentity, host string, port int, realityDest, label string) string {
	v := serverLinkValues(identity, realityDest)
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(identity.UUID),
		Host:     fmt.Sprintf("%s:%d", host, port),
		RawQuery: v.Encode(),
		Fragment: label,
	}
	return u.String()
}

// BuildServerRelayLink — то же, что BuildServerLink, но для relay-режима
// (docs/TZ_APF_RELAY_v1.0.md §3): host:port в самой ссылке — адрес RelayServer, НЕ адрес
// устройства «Выход» напрямую (обычный vless://-парсер по-прежнему разбирает его без
// специального кода — «относится к серверу по этому адресу»). exitID — публичный маршрутный
// идентификатор (докс §2.1, §3 — намеренно НЕ совпадает с identity.UUID). relayFingerprint —
// отпечаток TLS-сертификата relay-сервера (TZ_RELAY_HARDENING_2026-08-29.md кластер B,
// internal/relay/tunnel_tls.go) — обязателен для relay-режима, партнёр без него не сможет
// подключиться (EntryBridge теперь fail-closed без отпечатка). Три добавленных
// query-параметра (apf_relay/apf_exitid/apf_relayfp) чужому VLESS-клиенту ничем не мешают —
// просто нераспознанные поля; APF-парсер сохраняет их в Node.ExtraParams
// (internal/parser/parser.go).
func BuildServerRelayLink(identity ServerIdentity, relayHost string, relayPort int, exitID, relayFingerprint, realityDest, label string) string {
	v := serverLinkValues(identity, realityDest)
	v.Set("apf_relay", "1")
	v.Set("apf_exitid", exitID)
	v.Set("apf_relayfp", relayFingerprint)
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(identity.UUID),
		Host:     fmt.Sprintf("%s:%d", relayHost, relayPort),
		RawQuery: v.Encode(),
		Fragment: label,
	}
	return u.String()
}

func serverLinkValues(identity ServerIdentity, realityDest string) url.Values {
	v := url.Values{}
	v.Set("flow", "xtls-rprx-vision")
	v.Set("security", "reality")
	v.Set("sni", realityDest)
	v.Set("pbk", identity.PublicKey)
	v.Set("sid", identity.ShortID)
	v.Set("fp", "chrome")
	return v
}
