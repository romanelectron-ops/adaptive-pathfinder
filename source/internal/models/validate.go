package models

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// validate.go — валидатор полей узла (B-29 / D25).
// Используется при ручном добавлении/редактировании узла, чтобы заведомо некорректные
// данные (пустой адрес, порт вне диапазона, VLESS без UUID, Reality без public_key и т.п.)
// не попадали в пул и не падали молча при проверке. Контракт ValidateNode:
//   Вход:  *Node (как из формы редактора или импорта).
//   Тело:  общие проверки (адрес/порт) + протокол-специфичные (UUID/Password/Method/Reality).
//   Выход: nil, если узел валиден; иначе error со списком всех нарушений (через ; ).
// Инвариант: чистая функция без side-effects; nil-узел → ошибка, не паника.

// ValidateNode проверяет узел и возвращает агрегированную ошибку всех нарушений.
func ValidateNode(n *Node) error {
	if n == nil {
		return fmt.Errorf("node is nil")
	}
	var errs []string

	// ── Общие поля ──
	addr := strings.TrimSpace(n.Address)
	if addr == "" {
		errs = append(errs, "address is empty")
	} else if !isValidHostOrIP(addr) {
		errs = append(errs, fmt.Sprintf("invalid address %q", addr))
	}
	if n.Port < 1 || n.Port > 65535 {
		errs = append(errs, fmt.Sprintf("port %d out of range 1..65535", n.Port))
	}

	// ── Протокол-специфичные ──
	switch n.Protocol {
	case ProtoVLESS:
		if strings.TrimSpace(n.UUID) == "" {
			errs = append(errs, "VLESS requires uuid")
		} else if !isValidUUID(n.UUID) {
			errs = append(errs, fmt.Sprintf("invalid uuid %q", n.UUID))
		}
		errs = append(errs, validateRealityIfPresent(n)...)
	case ProtoVMess:
		if strings.TrimSpace(n.UUID) == "" {
			errs = append(errs, "VMess requires uuid")
		} else if !isValidUUID(n.UUID) {
			errs = append(errs, fmt.Sprintf("invalid uuid %q", n.UUID))
		}
	case ProtoTrojan:
		if strings.TrimSpace(n.Password) == "" {
			errs = append(errs, "Trojan requires password")
		}
	case ProtoShadowsocks:
		if strings.TrimSpace(n.Password) == "" {
			errs = append(errs, "Shadowsocks requires password")
		}
		if strings.TrimSpace(n.Method) == "" {
			errs = append(errs, "Shadowsocks requires method (cipher)")
		}
	case ProtoWireGuard, ProtoAmneziaWG:
		if strings.TrimSpace(n.WGPrivateKey) == "" {
			errs = append(errs, "WireGuard requires wg_private_key")
		}
		if strings.TrimSpace(n.WGPublicKey) == "" {
			errs = append(errs, "WireGuard requires wg_public_key (server)")
		}
		// [TZ_TAILS_HARDENING_2026-08-31.md кластер B] без клиентского адреса endpoint-
		// конфигурация sing-box не соберётся вовсе (WireGuardEndpointOptions.Address
		// обязателен, не omitempty) — отказывать здесь, а не глубже в config_builder.go.
		if strings.TrimSpace(n.WGLocalAddress) == "" {
			errs = append(errs, "WireGuard requires wg_local_address (client tunnel address, e.g. 10.0.0.2/32)")
		}
	case ProtoTor:
		// ВНИМАНИЕ: этот case намеренно пуст — общие проверки Address/Port (выше по функции)
		// применяются и к Tor тоже, несмотря на то что название протокола наводит на мысль
		// «раз это Tor, адрес и порт не обязательны». Раньше здесь стоял именно такой
		// комментарий («снимаем общие требования»), но кода, реализующего снятие, не было
		// никогда — сами общие проверки безусловно выполняются до этого switch. Комментарий
		// молчал о реальном поведении и противоречил ему.
		//
		// Оставляем как есть осознанно: internal/engine/nodes_manage.go mergeFetchedNodes
		// (NL-10) полагается ИМЕННО на то, что ValidateNode отвергает Tor-узлы без адреса и
		// порта — sources.fetchTorBridges создаёт узел-заглушку "Tor Bridge" ровно с такими
		// пустыми полями (реальные bridge-строки obfs4/snowflake не разбираются), и раньше эта
		// заглушка попадала в пул и «висела» красной без единого шанса подключиться. Если
		// когда-нибудь этот case перестанет быть пустым и правда снимет требования к
		// адресу/порту для Tor — это вернёт баг NL-10. См. TestValidateNode_TorStubRejected.
	case "":
		errs = append(errs, "protocol is empty")
	default:
		errs = append(errs, fmt.Sprintf("unknown protocol %q", n.Protocol))
	}

	// ── Transport (если задан) ──
	if n.Transport != nil {
		switch n.Transport.Type {
		case "tcp", "ws", "grpc", "http", "":
			// ok
		default:
			errs = append(errs, fmt.Sprintf("unknown transport type %q", n.Transport.Type))
		}
		if (n.Transport.Type == "ws" || n.Transport.Type == "http") && n.Transport.Path != "" &&
			!strings.HasPrefix(n.Transport.Path, "/") {
			errs = append(errs, fmt.Sprintf("transport path must start with '/': %q", n.Transport.Path))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid node: %s", strings.Join(errs, "; "))
	}
	return nil
}

// validateRealityIfPresent проверяет Reality-поля, если TLS.Reality задан.
func validateRealityIfPresent(n *Node) []string {
	if n.TLS == nil || n.TLS.Reality == nil {
		return nil
	}
	var errs []string
	if strings.TrimSpace(n.TLS.Reality.PublicKey) == "" {
		errs = append(errs, "Reality requires public_key (pbk)")
	}
	// short_id (sid) — необязателен, но если задан, должен быть hex чётной длины ≤ 16 байт
	if sid := strings.TrimSpace(n.TLS.Reality.ShortID); sid != "" {
		if !isHex(sid) || len(sid)%2 != 0 || len(sid) > 16 {
			errs = append(errs, fmt.Sprintf("invalid Reality short_id %q (hex, even length, ≤16 chars)", sid))
		}
	}
	return errs
}

// isValidHostOrIP — IP или правдоподобное доменное имя (без схемы/пробелов).
func isValidHostOrIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.ContainsAny(s, " /\\:") {
		return false
	}
	// домен: хотя бы одна точка и валидные метки
	if !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

// isValidUUID — канонический UUID (8-4-4-4-12 hex) ЛИБО произвольная непустая строка,
// которую sing-box/Xray принимают как идентификатор пользователя.
//
// Строгая проверка «только 8-4-4-4-12» отвергала рабочие ссылки (найдено 2026-08-24 при
// разборе жалобы «не получилось ввести вручную узел и добавить»). Xray и sing-box
// детерминированно отображают ЛЮБУЮ строку в UUIDv5, и такие конфиги массово встречаются
// у публичных провайдеров. Отвергать их — значит запрещать пользователю добавить узел,
// который прекрасно работает в других клиентах, и не давать взамен никакого объяснения,
// кроме `invalid uuid`. Показательно, что собственные тесты проекта на этот путь были
// написаны «терпимо к отказу» (логировали предупреждение вместо проверки) — то есть
// зелёными они были и тогда, когда добавление не работало.
//
// Отвергаем по-прежнему очевидный мусор: пустое значение и пробелы внутри (это почти
// всегда склеенный кусок чужого текста, а не идентификатор).
func isValidUUID(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) == 5 {
		want := []int{8, 4, 4, 4, 12}
		canonical := true
		for i, p := range parts {
			if len(p) != want[i] || !isHex(p) {
				canonical = false
				break
			}
		}
		if canonical {
			return true
		}
	}
	// Не канонический — но валидный для sing-box/Xray идентификатор.
	return true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 64)
	if err == nil {
		return true
	}
	// длинные hex-строки не влезают в uint64 — проверяем посимвольно
	for _, c := range strings.ToLower(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
