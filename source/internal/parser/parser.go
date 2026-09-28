// Package parser разбирает ссылки и файлы конфигураций узлов
// Поддерживает: vmess://, vless://, ss://, trojan://, wireguard://
// А также форматы: base64-списки, clash YAML, sing-box JSON
package parser

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ParseLink разбирает одну ссылку любого формата
func ParseLink(raw string) (*models.Node, error) {
	raw = strings.TrimSpace(raw)
	// Схему приводим к нижнему регистру: экранные клавиатуры на Android автоматически
	// поднимают первую букву («Vless://…»), и раньше такая ссылка отвергалась как
	// «unknown protocol» — при том что пользователь вставил её без единой ошибки.
	// Трогаем ТОЛЬКО схему: тело ссылки регистрозависимо (base64, UUID, пароли).
	if i := strings.Index(raw, "://"); i > 0 {
		raw = strings.ToLower(raw[:i]) + raw[i:]
	}
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(raw, "ss://"):
		return parseShadowsocks(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw)
	case strings.HasPrefix(raw, "wireguard://"), strings.HasPrefix(raw, "wg://"), strings.HasPrefix(raw, "amneziawg://"):
		return parseWireGuard(raw)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", raw[:func() int {
			if len(raw) < 20 {
				return len(raw)
			}
			return 20
		}()])
	}
}

// ParseSubscription разбирает подписку (base64 или построчный список ссылок)
func ParseSubscription(data []byte) ([]*models.Node, error) {
	// Пробуем base64-декодирование
	decoded, err := tryBase64(data)
	if err == nil {
		data = decoded
	}

	var nodes []*models.Node
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		node, err := ParseLink(line)
		if err == nil && node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// ParseClashYAML — разбор Clash-формата (поддерживает ss/vmess/trojan/vless)
func ParseClashYAML(data []byte) ([]*models.Node, error) {
	var nodes []*models.Node
	lines := strings.Split(string(data), "\n")
	inProxies := false

	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if trimmed == "proxies:" {
			inProxies = true
			i++
			continue
		}

		if inProxies {
			// Конец секции proxies: непробельная строка не начинающаяся с "-"
			if trimmed != "" && !strings.HasPrefix(line, " ") &&
				!strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "-") {
				inProxies = false
				i++
				continue
			}

			if strings.HasPrefix(trimmed, "- ") {
				// Определяем базовый отступ текущей строки
				baseIndent := len(line) - len(strings.TrimLeft(line, " \t"))
				block := []string{line}

				// Собираем последующие строки с большим отступом
				j := i + 1
				for j < len(lines) {
					next := lines[j]
					nextTrimmed := strings.TrimSpace(next)
					if nextTrimmed == "" {
						j++
						continue
					}
					nextIndent := len(next) - len(strings.TrimLeft(next, " \t"))
					if nextIndent <= baseIndent {
						break
					}
					block = append(block, next)
					j++
				}

				if node := parseClashProxyBlock(block); node != nil {
					nodes = append(nodes, node)
				}
				i = j
				continue
			}
		}
		i++
	}
	return nodes, nil
}

// --- VLESS ---
func parseVLESS(raw string) (*models.Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	node := &models.Node{
		Protocol: models.ProtoVLESS,
		UUID:     u.User.Username(),
		Address:  u.Hostname(),
		Name:     u.Fragment,
		AddedAt:  time.Now(),
		Status:   models.StatusUnknown,
	}
	node.Port, _ = strconv.Atoi(u.Port())

	q := u.Query()
	node.Flow = q.Get("flow")

	// TLS / Reality
	security := q.Get("security")
	if security == "tls" || security == "reality" {
		node.TLS = &models.TLSConfig{
			Enabled:    true,
			ServerName: q.Get("sni"),
			// fp — uTLS-отпечаток; раньше терялся, см. models.TLSConfig.Fingerprint.
			Fingerprint: q.Get("fp"),
		}
		if security == "reality" {
			node.TLS.Reality = &models.RealityConfig{
				PublicKey: q.Get("pbk"),
				ShortID:   q.Get("sid"),
			}
		}
	}

	// Transport
	netType := q.Get("type")
	if netType != "" && netType != "tcp" {
		node.Transport = &models.TransportConfig{
			Type: netType,
			Path: q.Get("path"),
			Host: q.Get("host"),
		}
	}

	// Нераспознанные query-параметры сохраняем как есть (models.Node.ExtraParams) — общий
	// механизм для расширений, которым нужны свои параметры в ссылке (например, relay-режим
	// Вход-Выход, docs/TZ_APF_RELAY_v1.0.md §5), БЕЗ раздувания знаний общего парсера о
	// частных случаях конкретной фичи — известные VLESS-параметры (flow/security/sni/fp/
	// pbk/sid/type/path/host) остаются обработанными как раньше, всё остальное просто
	// переживает разбор нетронутым.
	knownVLESSParams := map[string]bool{
		"flow": true, "security": true, "sni": true, "fp": true,
		"pbk": true, "sid": true, "type": true, "path": true, "host": true,
	}
	for key, vals := range q {
		if knownVLESSParams[key] || len(vals) == 0 {
			continue
		}
		if node.ExtraParams == nil {
			node.ExtraParams = make(map[string]string)
		}
		node.ExtraParams[key] = vals[0]
	}

	node.ID = generateID(node)
	if node.Name == "" {
		node.Name = fmt.Sprintf("VLESS %s:%d", node.Address, node.Port)
	}
	return node, nil
}

// --- VMess ---
type vmessConfig struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	FP   string `json:"fp"` // uTLS-отпечаток, см. models.TLSConfig.Fingerprint
}

func parseVMess(raw string) (*models.Node, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("vmess base64 decode: %w", err)
		}
	}

	var cfg vmessConfig
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}

	node := &models.Node{
		Protocol: models.ProtoVMess,
		UUID:     cfg.ID,
		Address:  cfg.Add,
		Name:     cfg.PS,
		AddedAt:  time.Now(),
		Status:   models.StatusUnknown,
	}

	// port может быть строкой или числом
	switch v := cfg.Port.(type) {
	case float64:
		node.Port = int(v)
	case string:
		node.Port, _ = strconv.Atoi(v)
	}

	switch v := cfg.Aid.(type) {
	case float64:
		node.AltID = int(v)
	case string:
		node.AltID, _ = strconv.Atoi(v)
	}

	if cfg.TLS == "tls" {
		node.TLS = &models.TLSConfig{
			Enabled:     true,
			ServerName:  cfg.SNI,
			Fingerprint: cfg.FP,
		}
	}
	if cfg.Net != "" && cfg.Net != "tcp" {
		node.Transport = &models.TransportConfig{
			Type: cfg.Net,
			Path: cfg.Path,
			Host: cfg.Host,
		}
	}

	node.ID = generateID(node)
	if node.Name == "" {
		node.Name = fmt.Sprintf("VMess %s:%d", node.Address, node.Port)
	}
	return node, nil
}

// --- Shadowsocks ---
//
// Разбирается ВРУЧНУЮ, без url.Parse, потому что на практике встречаются три формы, из
// которых url.Parse корректно берёт только одну:
//
//  1. SIP002:        ss://BASE64URL(method:password)@host:port#name
//  2. SIP002-plain:  ss://method:password@host:port#name
//  3. legacy:        ss://BASE64(method:password@host:port)#name   ← весь адрес внутри base64
//
// Форму 3 url.Parse разбирает в мусор (весь блоб становится хостом → Port=0 → узел
// отвергается валидатором как «port 0 out of range»), а форму 1 ломает, если base64 —
// стандартный, а не URL-safe: символ «/» внутри userinfo превращается в границу пути, и
// хост с портом уезжают в path. Обе поломки выглядели для пользователя одинаково —
// «ссылка не добавляется», хотя ссылка валидна и работает в других клиентах.
// Найдено при разборе жалобы 2026-08-24.
func parseShadowsocks(raw string) (*models.Node, error) {
	body := strings.TrimPrefix(raw, "ss://")

	// Фрагмент (#имя) отрезаем первым — он не участвует ни в base64, ни в адресе.
	name := ""
	if i := strings.Index(body, "#"); i >= 0 {
		name = body[i+1:]
		// PathUnescape, а не QueryUnescape: «+» в имени узла — обычный символ, и названия
		// вида «RU+Fast» встречаются постоянно. QueryUnescape превращал бы их в «RU Fast».
		if unescaped, err := url.PathUnescape(name); err == nil {
			name = unescaped
		}
		body = body[:i]
	}

	// Query (?plugin=...) — отдельно, до любых попыток декодирования.
	query := url.Values{}
	if i := strings.Index(body, "?"); i >= 0 {
		query, _ = url.ParseQuery(body[i+1:])
		body = body[:i]
	}

	// Форма 3: во всём теле нет «@» → это единый base64-блоб с адресом внутри.
	if !strings.Contains(body, "@") {
		decoded, err := tryBase64([]byte(body))
		if err != nil {
			return nil, fmt.Errorf("ss: не удалось разобрать ссылку (ни SIP002, ни base64): %w", err)
		}
		body = string(decoded)
	}

	// Делим по ПОСЛЕДНЕМУ «@»: пароль сам может содержать «@», хост — нет.
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, fmt.Errorf("ss: в ссылке нет разделителя '@' между учёткой и адресом")
	}
	userInfo, hostPort := body[:at], body[at+1:]

	// Хвостовой путь. В примерах самой спецификации SIP002 адрес пишется со слэшем перед
	// query: ss://…@host:8888/?plugin=… . Отрезать только «?query» недостаточно — остаётся
	// «host:8888/», net.SplitHostPort порт не валидирует и отдаёт «8888/», а strconv.Atoi
	// падает. Это была регрессия против прежней реализации на url.Parse (найдено ревью
	// 2026-08-24): каноническая ссылка молча не добавлялась вручную и молча терялась при
	// импорте подписки.
	if i := strings.Index(hostPort, "/"); i >= 0 {
		hostPort = hostPort[:i]
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("ss: не разобран адрес %q: %w", hostPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("ss: порт %q не число", portStr)
	}

	// Учётка либо base64(method:password), либо уже открытые method:password.
	wasBase64 := false
	if decoded, err := tryBase64([]byte(userInfo)); err == nil && strings.Contains(string(decoded), ":") {
		userInfo = string(decoded)
		wasBase64 = true
	}
	method, password, found := strings.Cut(userInfo, ":")
	if !found {
		return nil, fmt.Errorf("ss: учётные данные не в формате method:password")
	}
	// Процент-декодирование — ТОЛЬКО для открытой формы: после base64 пароль уже буквальный,
	// и повторное декодирование исказило бы его.
	//
	// И именно PathUnescape, а не QueryUnescape: последний трактует «+» как пробел (правило
	// query-строк), а в пароле «+» — обычный символ, и притом частый (пароли нередко
	// генерируют base64-алфавитом). Через QueryUnescape пароль «pa+ss» молча превращался в
	// «pa ss», узел не аутентифицировался, а причина ниоткуда не была видна — регрессия,
	// внесённая при переписывании этого разбора 2026-08-24 и пойманная тестом.
	if !wasBase64 {
		if unescaped, err := url.PathUnescape(password); err == nil {
			password = unescaped
		}
	}

	node := &models.Node{
		Protocol: models.ProtoShadowsocks,
		Address:  host,
		Port:     port,
		Method:   method,
		Password: password,
		Name:     name,
		AddedAt:  time.Now(),
		Status:   models.StatusUnknown,
	}

	// Plugin (obfs / v2ray-plugin) — НЕ поддерживается этой сборкой, и узел с ним отвергается
	// сразу, а не притворяется добавленным.
	//
	// Раньше строка плагина клалась в Transport.Type. Это не просто бесполезно — это ломало
	// работу двумя разными способами (найдено ревью 2026-08-24): при ручном добавлении
	// ValidateNode отвергал узел с невнятным «unknown transport type "obfs-local"», а при
	// импорте подписки валидации нет вовсе — узел попадал в пул, buildTransport писал
	// мусорный transport.type, и sing-box отвергал КОНФИГУРАЦИЮ ЦЕЛИКОМ. Один такой узел
	// ронял весь сеанс, а в режиме гонки — сразу всю группу кандидатов, включая исправных.
	if plugin := query.Get("plugin"); plugin != "" {
		return nil, fmt.Errorf("ss: плагин %q (obfs/v2ray-plugin) не поддерживается этой "+
			"сборкой sing-box — узел не добавлен", strings.SplitN(plugin, ";", 2)[0])
	}

	node.ID = generateID(node)
	if node.Name == "" {
		node.Name = fmt.Sprintf("SS %s:%d", node.Address, node.Port)
	}
	return node, nil
}

// --- Trojan ---
func parseTrojan(raw string) (*models.Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	node := &models.Node{
		Protocol: models.ProtoTrojan,
		Password: u.User.Username(),
		Address:  u.Hostname(),
		Name:     u.Fragment,
		AddedAt:  time.Now(),
		Status:   models.StatusUnknown,
	}
	node.Port, _ = strconv.Atoi(u.Port())

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = node.Address
	}
	node.TLS = &models.TLSConfig{
		Enabled:     true,
		ServerName:  sni,
		Fingerprint: q.Get("fp"),
	}

	netType := q.Get("type")
	if netType != "" && netType != "tcp" {
		node.Transport = &models.TransportConfig{
			Type: netType,
			Path: q.Get("path"),
			Host: q.Get("host"),
		}
	}

	node.ID = generateID(node)
	if node.Name == "" {
		node.Name = fmt.Sprintf("Trojan %s:%d", node.Address, node.Port)
	}
	return node, nil
}

// --- WireGuard ---
//
// [TZ_TAILS_HARDENING_2026-08-31.md кластер B] раньше извлекались только host/port/имя —
// приватный ключ, публичный ключ сервера и адрес клиента внутри туннеля никогда не читались из
// ссылки, хотя без них узел в принципе не мог пройти валидацию (validate.go) и тем более
// собраться в endpoint-конфигурацию (config_builder.go, nodeToEndpoint). Формат ссылки —
// wireguard://<приватный_ключ>@<host>:<port>?publickey=<публичный_ключ_сервера>&
// address=<CIDR_клиента>&reserved=<r0>,<r1>,<r2>&mtu=<mtu>&jc=<..>&jmin=<..>&jmax=<..>#<имя> —
// тот же принцип, что уже используется у остальных протоколов этого файла: секрет (здесь —
// приватный ключ) в userinfo, остальное — в query. amneziawg:// вместо wireguard:// выбирает
// протокол ProtoAmneziaWG (jc/jmin/jmax сохраняются в модель узла, но текущая сборка sing-box
// их не умеет использовать — см. AmneziaWG-ветку nodeToOutbound/nodeToEndpoint).
func parseWireGuard(raw string) (*models.Node, error) {
	proto := models.ProtoWireGuard
	if strings.HasPrefix(raw, "amneziawg://") {
		proto = models.ProtoAmneziaWG
	}
	raw = strings.TrimPrefix(raw, "wireguard://")
	raw = strings.TrimPrefix(raw, "amneziawg://")
	raw = strings.TrimPrefix(raw, "wg://")
	u, err := url.Parse("wg://" + raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()

	node := &models.Node{
		Protocol:       proto,
		Address:        u.Hostname(),
		Name:           u.Fragment,
		AddedAt:        time.Now(),
		Status:         models.StatusUnknown,
		WGPublicKey:    q.Get("publickey"),
		WGLocalAddress: q.Get("address"),
	}
	node.Port, _ = strconv.Atoi(u.Port())
	if u.User != nil {
		node.WGPrivateKey, _ = u.User.Password()
		if node.WGPrivateKey == "" {
			// Ссылка без ":" в userinfo — весь userinfo и есть приватный ключ
			// (net/url кладёт его в Username в этом случае, Password пуст).
			node.WGPrivateKey = u.User.Username()
		}
	}
	if reserved := q.Get("reserved"); reserved != "" {
		for _, part := range strings.Split(reserved, ",") {
			b, err := strconv.Atoi(strings.TrimSpace(part))
			if err == nil && b >= 0 && b <= 255 {
				node.WGReserved = append(node.WGReserved, uint8(b))
			}
		}
	}
	if jc := q.Get("jc"); jc != "" {
		node.AWGJc, _ = strconv.Atoi(jc)
	}
	if jmin := q.Get("jmin"); jmin != "" {
		node.AWGJmin, _ = strconv.Atoi(jmin)
	}
	if jmax := q.Get("jmax"); jmax != "" {
		node.AWGJmax, _ = strconv.Atoi(jmax)
	}

	node.ID = generateID(node)
	if node.Name == "" {
		node.Name = fmt.Sprintf("WG %s:%d", node.Address, node.Port)
	}
	return node, nil
}

// --- Clash proxy block parser ---

// parseClashProxyBlock разбирает один блок строк Clash YAML для одного прокси.
// Поддерживаемые типы: ss (shadowsocks), vmess, trojan, vless.
// Поддерживает как многострочный, так и инлайн-формат (- {key: val, ...}).
func parseClashProxyBlock(block []string) *models.Node {
	if len(block) == 0 {
		return nil
	}
	fields := make(map[string]string)

	firstTrimmed := strings.TrimSpace(block[0])

	// Инлайн формат: - {name: x, type: ss, server: host, ...}
	if strings.HasPrefix(firstTrimmed, "- {") {
		inner := strings.TrimPrefix(firstTrimmed, "- ")
		inner = strings.TrimSpace(inner)
		inner = strings.TrimPrefix(inner, "{")
		inner = strings.TrimSuffix(inner, "}")
		clashParseInline(inner, fields)
	} else {
		// Многострочный формат — первая строка: "- name: value" или "- name:"
		first := strings.TrimPrefix(firstTrimmed, "- ")
		clashParseField(first, fields)
		for _, l := range block[1:] {
			clashParseField(strings.TrimSpace(l), fields)
		}
	}

	return clashBuildNode(fields)
}

// clashParseField разбирает строку "key: value" и записывает в map.
// Кавычки и пробелы вокруг значения удаляются.
func clashParseField(s string, fields map[string]string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+1:])
	val = strings.Trim(val, `"'`)
	if key != "" && val != "" {
		fields[key] = val
	}
}

// clashParseInline разбирает "key: val, key2: val2, ..." (инлайн YAML).
func clashParseInline(s string, fields map[string]string) {
	// Разбиваем по ", " — простой подход для типичных Clash-подписок
	parts := strings.Split(s, ", ")
	for _, part := range parts {
		clashParseField(strings.TrimSpace(part), fields)
	}
}

// clashBuildNode строит models.Node из карты полей Clash YAML.
func clashBuildNode(f map[string]string) *models.Node {
	proxyType := strings.ToLower(f["type"])
	server := f["server"]
	portStr := f["port"]
	name := f["name"]

	if server == "" || portStr == "" || proxyType == "" {
		return nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil
	}

	node := &models.Node{
		Address: server,
		Port:    port,
		Name:    name,
		AddedAt: time.Now(),
		Status:  models.StatusUnknown,
	}
	if node.Name == "" {
		node.Name = fmt.Sprintf("%s %s:%d", strings.ToUpper(proxyType), server, port)
	}

	switch proxyType {
	case "ss", "shadowsocks":
		node.Protocol = models.ProtoShadowsocks
		node.Method = f["cipher"]
		node.Password = f["password"]

	case "vmess":
		node.Protocol = models.ProtoVMess
		node.UUID = f["uuid"]
		node.AltID, _ = strconv.Atoi(f["alterId"])
		if f["tls"] == "true" {
			sni := f["servername"]
			if sni == "" {
				sni = f["sni"]
			}
			if sni == "" {
				sni = server
			}
			node.TLS = &models.TLSConfig{Enabled: true, ServerName: sni}
		}
		if net := f["network"]; net != "" && net != "tcp" {
			node.Transport = &models.TransportConfig{
				Type: net,
				Path: f["ws-path"],
				Host: f["ws-headers-Host"],
			}
		}

	case "trojan":
		node.Protocol = models.ProtoTrojan
		node.Password = f["password"]
		sni := f["sni"]
		if sni == "" {
			sni = server
		}
		node.TLS = &models.TLSConfig{Enabled: true, ServerName: sni}
		if net := f["network"]; net != "" && net != "tcp" {
			node.Transport = &models.TransportConfig{
				Type: net,
				Path: f["ws-path"],
			}
		}

	case "vless":
		node.Protocol = models.ProtoVLESS
		node.UUID = f["uuid"]
		node.Flow = f["flow"]
		tls := f["tls"]
		if tls == "true" || tls == "reality" {
			sni := f["servername"]
			if sni == "" {
				sni = f["sni"]
			}
			if sni == "" {
				sni = server
			}
			node.TLS = &models.TLSConfig{Enabled: true, ServerName: sni}
		}
		if net := f["network"]; net != "" && net != "tcp" {
			node.Transport = &models.TransportConfig{
				Type: net,
				Path: f["ws-path"],
			}
		}

	default:
		return nil
	}

	node.ID = generateID(node)
	return node
}

// --- Вспомогательные функции ---

func tryBase64(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	// Убираем возможные переносы строк внутри base64
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("not valid base64")
}

// generateID — стабильный идентификатор узла.
//
// Учётные данные ОБЯЗАНЫ участвовать в хеше (найдено 2026-08-24 живым разбором жалобы
// «не получилось ввести вручную узел и добавить»). Раньше ID считался только по
// protocol:address:port, а `AddNodeFromLink` отвергает узел, ID которого уже есть в пуле.
// У пользователя в пуле тысячи узлов из публичных агрегаторов; агрегаторы регулярно
// публикуют ОДИН И ТОТ ЖЕ host:port с РАЗНЫМИ (часто протухшими) учётками. Поэтому рабочая
// ссылка, добавляемая вручную, отвергалась как «already exists» — а в пуле оставался
// мёртвый узел с тем же адресом и чужими учётными данными. Ровно тот же дефект тихо терял
// валидные узлы и при массовом импорте подписок (updateSources дедуплицирует тем же ID).
//
// Смена схемы ID безопасна для уже сохранённого кеша: `Engine.loadNodes` пересчитывает ID
// каждому загруженному узлу этой же функцией, поэтому старые и новые ID сходятся за один
// запуск. Новый ID строго конкретнее старого (та же база + учётки), так что двух РАЗНЫХ
// узлов он в один ID не сольёт.
func generateID(node *models.Node) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%d", node.Protocol, node.Address, node.Port)))
	h.Write([]byte(fmt.Sprintf("|%s|%s|%s|%s|%d",
		node.UUID, node.Password, node.Method, node.Flow, node.AltID)))
	// Параметры TLS/Reality и транспорта тоже различают узлы. Для VLESS+Reality именно
	// pbk/sid/sni — единственный различитель: UUID у старой и новой конфигурации один и тот
	// же, и без этих полей смена ключа на сервере давала ТОТ ЖЕ ID. Пользователь вставлял
	// рабочую ссылку с новым ключом, попадал в ветку дубликата — и в пуле оставался узел со
	// СТАРЫМ, нерабочим ключом (найдено ревью 2026-08-24).
	if t := node.TLS; t != nil {
		h.Write([]byte(fmt.Sprintf("|tls:%v|%s|%s", t.Enabled, t.ServerName, t.Fingerprint)))
		if r := t.Reality; r != nil {
			h.Write([]byte(fmt.Sprintf("|reality:%s|%s", r.PublicKey, r.ShortID)))
		}
	}
	if tr := node.Transport; tr != nil {
		h.Write([]byte(fmt.Sprintf("|tr:%s|%s|%s", tr.Type, tr.Path, tr.Host)))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// GenerateNodeID — публичная обёртка над generateID для ручного создания узлов (B-29).
// Использует тот же алгоритм (sha256 по protocol:address:port), что и парсеры ссылок,
// поэтому ID детерминирован и совпадает для одинаковых узлов независимо от способа ввода.
func GenerateNodeID(node *models.Node) string {
	return generateID(node)
}

// ── F-12 (T-12): диспетчер импорта каталога ───────────────────────────────────

// looksLikeClashYAML эвристически определяет Clash-конфиг по наличию ключа
// верхнего уровня "proxies:" (на которое опирается ParseClashYAML).
func looksLikeClashYAML(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "proxies:" {
			return true
		}
	}
	return false
}

// ParseCatalogContent — единая точка разбора контента провайдера каталога.
// Контракт (B-12.1): вход — сырое тело источника (links/base64 подписка ИЛИ
// Clash YAML). Тело: сначала пробует ParseSubscription (основной формат); если
// узлов нет и контент похож на Clash YAML — делегирует ParseClashYAML. Выход:
// ([]*models.Node, error). Инвариант: для link/base64-подписок поведение
// идентично прежнему ParseSubscription (не регрессирует существующих провайдеров);
// для Clash-.yml (например nomore-walls) теперь возвращает узлы вместо нуля.
// Подключает ранее изолированный ParseClashYAML (закрывает «остров» из карты связей).
func ParseCatalogContent(data []byte) ([]*models.Node, error) {
	nodes, subErr := ParseSubscription(data)
	if len(nodes) > 0 {
		return nodes, nil
	}
	// B-12.2: sing-box config.json (распознаём по "outbounds")
	if looksLikeSingBoxJSON(data) {
		if jNodes, jErr := ParseSingBoxJSON(data); jErr == nil && len(jNodes) > 0 {
			return jNodes, nil
		}
	}
	if looksLikeClashYAML(data) {
		if yNodes, yErr := ParseClashYAML(data); yErr == nil && len(yNodes) > 0 {
			return yNodes, nil
		}
	}
	return nodes, subErr
}

// ── B-12.2 (T-12): импорт sing-box JSON ───────────────────────────────────────

// sbOutbound — минимальное представление outbound из sing-box config.json для импорта.
type sbOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	UUID       string `json:"uuid"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	AltID      int    `json:"alter_id"`
}

type sbConfig struct {
	Outbounds []sbOutbound `json:"outbounds"`
}

// looksLikeSingBoxJSON эвристически определяет sing-box config по наличию "outbounds".
func looksLikeSingBoxJSON(data []byte) bool {
	t := strings.TrimSpace(string(data))
	if !strings.HasPrefix(t, "{") {
		return false
	}
	return strings.Contains(t, "\"outbounds\"")
}

// ParseSingBoxJSON разбирает sing-box config.json и извлекает узлы из outbounds.
// Контракт (B-12.2): вход — JSON sing-box; тело — парс outbounds, конвертация
// поддерживаемых прокси-типов (vless/vmess/trojan/shadowsocks) в models.Node;
// служебные outbound'ы (direct/block/dns/selector/urltest) пропускаются. Выход —
// []*models.Node. Инвариант: невалидный JSON → ошибка без узлов; нет прокси → пустой
// срез без ошибки. Это обратная операция к singbox.nodeToOutbound (симметрия).
func ParseSingBoxJSON(data []byte) ([]*models.Node, error) {
	var cfg sbConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("sing-box json: %w", err)
	}
	var nodes []*models.Node
	for _, ob := range cfg.Outbounds {
		var proto models.Protocol
		switch ob.Type {
		case "vless":
			proto = models.ProtoVLESS
		case "vmess":
			proto = models.ProtoVMess
		case "trojan":
			proto = models.ProtoTrojan
		case "shadowsocks":
			proto = models.ProtoShadowsocks
		default:
			continue // direct/block/dns/selector/urltest/tor/wireguard — пропускаем
		}
		if ob.Server == "" || ob.ServerPort == 0 {
			continue // неполный outbound — игнорируем, не падаем
		}
		n := &models.Node{
			Protocol: proto,
			Address:  ob.Server,
			Port:     ob.ServerPort,
			UUID:     ob.UUID,
			Password: ob.Password,
			Method:   ob.Method,
			AltID:    ob.AltID,
			Name:     ob.Tag,
		}
		n.ID = generateID(n)
		if n.Name == "" {
			n.Name = fmt.Sprintf("%s %s:%d", proto, n.Address, n.Port)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}
