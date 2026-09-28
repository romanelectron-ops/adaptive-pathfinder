// Package sources управляет источниками узлов: GitHub подписки, Tor мосты, ручной ввод
package sources

import (
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/parser"
)

// Manager — менеджер источников
type Manager struct {
	cfg        *models.AppConfig
	httpClient *http.Client
	lastUpdate map[string]time.Time
	mu         sync.RWMutex

	// OnLog — необязательный приёмник строк для пользовательского лога (движок ставит e.log).
	OnLog func(string)

	// ── C-7 (ТЗ v1.4, B3 #7): подписки через туннель ────────────────────────────────────
	//
	// Канал поставки узлов деградирует в РФ ровно тогда, когда он нужнее всего, и до этой
	// правки тянулся МИМО туннеля даже при активном подключении: пул мёртв, обновить неоткуда.
	//
	// tunnelProxy — поставщик адреса локального SOCKS движка: ("127.0.0.1:10808", true), когда
	// подключение активно И режим proxy. В VPN(TUN)-режиме обязан отвечать false: там весь
	// трафик и так в туннеле, а второй заворот только удлинил бы путь.
	tunnelProxy func() (string, bool)
	// socksDial — точка подмены ДЛЯ ТЕСТОВ (в бою — dialSOCKS5). Поднимать настоящий SOCKS в
	// испытании нечем, а поведение «через туннель / напрямую» проверить обязательно.
	socksDial func(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error)
}

// New создаёт новый Manager
func New(cfg *models.AppConfig) *Manager {
	return &Manager{
		cfg: cfg,
		// netguard: под `go test` выход за пределы петли отвергается (Т-5).
		httpClient: netguard.Client(30 * time.Second),
		lastUpdate: make(map[string]time.Time),
		socksDial:  dialSOCKS5,
	}
}

// SetTunnelProxy задаёт поставщика адреса локального SOCKS движка (C-7). nil или ответ
// ("", false) означает «тянуть напрямую».
func (m *Manager) SetTunnelProxy(p func() (string, bool)) { m.tunnelProxy = p }

func (m *Manager) log(msg string) {
	if m.OnLog != nil {
		m.OnLog(msg)
	}
}

// sourceHTTPTimeout — общий таймаут запроса источника (тот же, что у прямого клиента).
const sourceHTTPTimeout = 30 * time.Second

// do выполняет запрос источника: при активном подключении в proxy-режиме — через локальный
// SOCKS движка, иначе напрямую.
//
// Fail-safe (обязателен по ТЗ, риск «источники перестали обновляться»): если через туннель не
// вышло, запрос ПОВТОРЯЕТСЯ напрямую, и это видно в логе. Тело запроса у источников всегда
// nil (GET), поэтому повтор того же *http.Request корректен.
func (m *Manager) do(req *http.Request) (*http.Response, error) {
	proxyAddr, viaTunnel := "", false
	if m.tunnelProxy != nil {
		proxyAddr, viaTunnel = m.tunnelProxy()
	}
	if viaTunnel && proxyAddr != "" {
		dial := m.socksDial
		if dial == nil {
			dial = dialSOCKS5
		}
		cl := &http.Client{
			Timeout: sourceHTTPTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					return dial(ctx, proxyAddr, addr, sourceHTTPTimeout)
				},
			},
		}
		resp, err := cl.Do(req)
		if err == nil {
			return resp, nil
		}
		m.log(fmt.Sprintf("Источники: через туннель не вышло (%v) — повторяю напрямую", err))
	}
	return m.httpClient.Do(req)
}

// FetchAll загружает узлы из всех включённых источников
func (m *Manager) FetchAll(ctx context.Context, force bool) ([]*models.Node, error) {
	var allNodes []*models.Node
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, src := range m.cfg.Sources {
		if !src.Enabled {
			continue
		}
		if !force && !m.needsUpdate(src) {
			continue
		}

		wg.Add(1)
		go func(s models.SourceConfig) {
			defer wg.Done()
			nodes, err := m.fetchSource(ctx, s)
			if err != nil {
				return
			}
			mu.Lock()
			allNodes = append(allNodes, nodes...)
			m.mu.Lock()
			m.lastUpdate[s.ID] = time.Now()
			m.mu.Unlock()
			mu.Unlock()
		}(src)
	}

	wg.Wait()
	return allNodes, nil
}

// FetchRawBodies — L5-ENG (харвестер, ТЗ v1.4 §5): сырые тела УЖЕ настроенных источников по
// SourceConfig.ID, БЕЗ разбора. Харвестер сам в сеть не ходит (инвариант I-1), поэтому сырые тела
// ему приносит движок через этот метод; разбор (parser.Parse*) и запись в пул — уже на стороне
// движка (mergeFetchedNodes, ValidateNode).
//
// Безопасность: та же связка, что и у боевого FetchAll — hardened do() (таймаут sourceHTTPTimeout,
// опционально через туннель) + жёсткий потолок тела 10 МБ (io.LimitReader — анти-DoS по памяти).
// Источники берём ТОЛЬКО из пользовательской конфигурации (произвольных URL не изобретаем — то же
// поле атаки, что и у FetchAll, не шире; SSRF-поверхность не растёт). Ошибка/пустое тело отдельного
// источника не валит весь проход (fail-safe, как в FetchAll) — источник просто пропускается. tor
// (встроенные мосты брокера) и manual собственного тела-страницы не имеют и пропускаются.
func (m *Manager) FetchRawBodies(ctx context.Context) (map[string][]byte, error) {
	out := make(map[string][]byte)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, src := range m.cfg.Sources {
		if !src.Enabled {
			continue
		}
		switch src.Type {
		case "subscription", "telegram", "raw":
			// есть скачиваемое тело-страница
		default:
			continue // tor / manual / неизвестный тип — тела нет
		}
		wg.Add(1)
		go func(s models.SourceConfig) {
			defer wg.Done()
			body, err := m.fetchBody(ctx, s)
			if err != nil || len(body) == 0 {
				return
			}
			mu.Lock()
			out[s.ID] = body
			mu.Unlock()
		}(src)
	}
	wg.Wait()
	return out, nil
}

// fetchBody скачивает сырое тело одного URL-источника с теми же гарантиями, что и боевые фетчеры
// (do() + лимит 10 МБ). User-Agent выставляется как у соответствующего типа, чтобы тело совпадало с
// тем, что видит боевой путь FetchAll (часть серверов отдаёт разный контент по UA).
func (m *Manager) fetchBody(ctx context.Context, src models.SourceConfig) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return nil, err
	}
	if src.Type == "subscription" {
		req.Header.Set("User-Agent", "APF/1.0 (Adaptive PathFinder)")
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	resp, err := m.do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source %s returned %d", src.Name, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
}

// ParseSingle разбирает одну ссылку
func (m *Manager) ParseSingle(link string) (*models.Node, error) {
	return parser.ParseLink(link)
}

// FetchSource загружает один источник
func (m *Manager) fetchSource(ctx context.Context, src models.SourceConfig) ([]*models.Node, error) {
	switch src.Type {
	case "subscription":
		return m.fetchSubscription(ctx, src)
	case "telegram":
		return m.fetchTelegramChannel(ctx, src)
	case "raw":
		// C-7 п.1 (ТЗ v1.4): ТРЕТЬЕ семейство хостов — произвольная текстовая/HTML-страница
		// (raw-хостинг, зеркало, pastebin-подобный сервис), с которой снимаются ссылки узлов.
		// Отличается от "subscription" тем, что не требует ни base64, ни построчного формата:
		// страница может быть какой угодно. Конкретные URL — решение владельца (память
		// vpn-node-sources-for-testing), механизм готов и покрыт тестом на сохранённом образце.
		return m.fetchRawText(ctx, src)
	case "tor":
		return m.fetchTorBridges(ctx)
	case "manual":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown source type: %s", src.Type)
	}
}

// fetchSubscription загружает подписку по URL
func (m *Manager) fetchSubscription(ctx context.Context, src models.SourceConfig) ([]*models.Node, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "APF/1.0 (Adaptive PathFinder)")

	resp, err := m.do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source %s returned %d", src.Name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // max 10MB
	if err != nil {
		return nil, err
	}

	nodes, err := parser.ParseSubscription(body)
	if err != nil {
		return nil, err
	}

	// Помечаем источник
	for _, n := range nodes {
		n.Source = src.ID
	}

	return nodes, nil
}

// proxyLinkPattern — ссылки протоколов, которые понимает parser.ParseLink, где угодно
// внутри произвольного текста (не построчно, как ParseSubscription). Нужен для
// fetchTelegramChannel: HTML публичной страницы t.me/s/<канал> перемешивает ссылки с
// разметкой на одной "строке", построчный разбор ParseSubscription тут не подходит.
var proxyLinkPattern = regexp.MustCompile(`(?:vless|vmess|ss|trojan|wireguard|wg)://[^\s"'<>&]*(?:&amp;[^\s"'<>&]*)*`)

// fetchTelegramChannel — источник узлов из публичной веб-версии Telegram-канала
// (https://t.me/s/<имя>, отдаётся без авторизации, это официальная функция Telegram для
// встраивания). Живой запрос пользователя 2026-08-28: пополнить пул рабочими узлами из
// конкретных каналов, но НЕ статическим снимком на сегодня (та же «заглушка», от которой
// просили уйти) — реальный, обновляющийся при каждом сканировании источник, тот же
// принцип, что и у остальных Source.Type ("subscription"/"tor"), просто с другим форматом
// на входе (HTML с постами, где ссылки перемешаны с разметкой, а не чистый список).
//
//	Тело:      скачивает HTML, вытаскивает через proxyLinkPattern все похожие на ссылку
//	           протокола подстроки (regexp не заботится о валидности — невалидные позже
//	           отсеет parser.ParseLink), html.UnescapeString на каждую (Telegram отдаёт
//	           "&amp;" вместо "&" в параметрах query — иначе распознаётся только первый
//	           параметр ссылки), затем обычный ParseLink, тот же путь, что ручной ввод
//	           одной ссылки пользователем.
//	Fail-safe: не считает невалидные/нераспознанные фрагменты ошибкой всего источника —
//	           страница канала содержит куда больше текста, чем просто ссылки на узлы;
//	           единственная фатальная ошибка — сам HTTP-запрос не удался.
func (m *Manager) fetchTelegramChannel(ctx context.Context, src models.SourceConfig) ([]*models.Node, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := m.do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source %s returned %d", src.Name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	return parseRawTextSource(body, src.ID), nil
}

// fetchRawText — источник «произвольная текстовая страница» (C-7 п.1, третье семейство хостов).
//
//	Вход:      SourceConfig с http(s)-URL.
//	Тело:      скачивает тело (лимит 10 МБ), снимает с него все похожие на ссылку узла
//	           подстроки тем же разбором, что и Telegram-страница.
//	Fail-safe: мусор на странице — не ошибка источника; ошибка только у самого HTTP-запроса.
func (m *Manager) fetchRawText(ctx context.Context, src models.SourceConfig) ([]*models.Node, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := m.do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source %s returned %d", src.Name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	return parseRawTextSource(body, src.ID), nil
}

// parseRawTextSource — общий разбор произвольного текста/HTML в узлы (Telegram-страница и
// raw-источник отличаются только тем, откуда взято тело).
//
//	Принимает:  любое тело; ссылки могут быть перемешаны с разметкой и текстом.
//	Игнорирует: всё, что не разобралось как ссылка узла, и повторы.
//	Выход:      узлы, помеченные ID источника.
func parseRawTextSource(body []byte, srcID string) []*models.Node {
	seen := make(map[string]bool)
	var nodes []*models.Node
	for _, raw := range proxyLinkPattern.FindAllString(string(body), -1) {
		link := html.UnescapeString(raw)
		if seen[link] {
			continue
		}
		seen[link] = true
		node, perr := parser.ParseLink(link)
		if perr != nil || node == nil {
			continue
		}
		node.Source = srcID
		nodes = append(nodes, node)
	}
	return nodes
}

// torBridgeURLs is an injection hook for testing.
var torBridgeURLs = []string{
	"https://bridges.torproject.org/bridges?transport=obfs4",
	"https://bridges.torproject.org/bridges?transport=snowflake",
}

// bridgeTransports — pluggable transports, с имени которых начинается строка моста.
// Строка без транспорта («vanilla bridge») начинается сразу с адреса.
var bridgeTransports = map[string]bool{
	"obfs2": true, "obfs3": true, "obfs4": true, "scramblesuit": true,
	"snowflake": true, "meek": true, "meek_lite": true, "webtunnel": true,
	"conjure": true, "fte": true,
}

// parseBridgeLine разбирает одну строку ответа брокера мостов Tor.
//
// Вход:      строка произвольного текста.
// Тело:      отбрасывает пустые строки и комментарии; определяет транспорт (или его
//
//	отсутствие); вытаскивает host:port, поддерживая IPv6 в скобках.
//
// Выход:     транспорт, адрес, порт, true — только если строка действительно описывает мост.
// Игнорирует: всё остальное (HTML капчи, пояснения брокера, мусор) — это НЕ ошибка строки,
//
//	решение «мостов не получено» принимает вызывающая сторона по итогу всего тела.
func parseBridgeLine(line string) (transport, host string, port int, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", 0, false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", 0, false
	}
	transport = "vanilla"
	addr := fields[0]
	if bridgeTransports[strings.ToLower(fields[0])] {
		if len(fields) < 2 {
			return "", "", 0, false
		}
		transport = strings.ToLower(fields[0])
		addr = fields[1]
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", 0, false
	}
	pn, err := strconv.Atoi(p)
	if err != nil || pn <= 0 || pn > 65535 {
		return "", "", 0, false
	}
	h = strings.Trim(h, "[]")
	if h == "" {
		return "", "", 0, false
	}
	return transport, h, pn, true
}

// fetchTorBridges запрашивает мосты Tor у брокера и разбирает ответ.
//
// Вход:      список URL брокера (torBridgeURLs; в тестах подменяется).
// Тело:      GET по каждому URL → проверка кода ответа → чтение тела с лимитом → построчный
//
//	разбор bridge-строк в узлы с НАСТОЯЩИМИ адресом и портом.
//
// Выход:     разобранные мосты; ошибка, если не получено НИ ОДНОГО моста (все URL отказали,
//
//	ответы пусты или в них нет ни одной bridge-строки).
//
// Fail-safe: частичный успех — успех (один брокер упал, другой отдал мосты → nil-ошибка);
//
//	полный провал — честная ошибка с причиной по каждому URL.
//
// К2-E П8 (свод C трек 1 №8; подтверждено A4 и F1 независимо). Раньше функция ВСЕГДА
// возвращала err=nil и НЕ смотрела в тело вовсе: на каждый удавшийся запрос — включая ответ
// 500 — создавался один узел-заглушка "Tor Bridge" c пустыми Address/Port и ID из
// time.Now().Unix(). Такой узел отвергает ValidateNode (models/validate.go:86, NL-10), то есть
// включённый по умолчанию источник не мог дать ни одного пригодного узла НИ ПРИ КАКОМ ответе
// сервера — и молчал об этом. ID теперь выводится из транспорта и адреса: повторная загрузка
// того же брокера не плодит дубликаты в пуле.
func (m *Manager) fetchTorBridges(ctx context.Context) ([]*models.Node, error) {
	var bridges []*models.Node
	var failures []string
	seen := make(map[string]bool)

	for _, u := range torBridgeURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			failures = append(failures, "некорректный URL брокера")
			continue
		}
		resp, err := m.do(req)
		if err != nil {
			failures = append(failures, "запрос к брокеру мостов не выполнен")
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			failures = append(failures, fmt.Sprintf("брокер мостов вернул %d", resp.StatusCode))
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		resp.Body.Close()
		if err != nil {
			failures = append(failures, "тело ответа брокера не прочитано")
			continue
		}

		found := 0
		for _, line := range strings.Split(string(body), "\n") {
			transport, host, port, ok := parseBridgeLine(line)
			if !ok {
				continue
			}
			id := fmt.Sprintf("tor-%s-%s-%d", transport, host, port)
			if seen[id] {
				continue
			}
			seen[id] = true
			found++
			bridges = append(bridges, &models.Node{
				ID:       id,
				Name:     fmt.Sprintf("Tor Bridge (%s) %s:%d", transport, host, port),
				Protocol: models.ProtoTor,
				Address:  host,
				Port:     port,
				Source:   "tor-bridges",
				AddedAt:  time.Now(),
				Status:   models.StatusUnknown,
			})
		}
		if found == 0 {
			failures = append(failures, "в ответе брокера нет ни одной строки моста")
		}
	}

	if len(bridges) == 0 {
		if len(failures) == 0 {
			// Список брокеров пуст: ни одного запроса не делалось, сообщать не о чем.
			// Это конфигурационное вырождение, а не отказ загрузки (см. TestFetchTorBridges_EmptyURLs).
			return nil, nil
		}
		return nil, fmt.Errorf("tor bridges: мостов не получено (%s)", strings.Join(failures, "; "))
	}
	return bridges, nil
}

func (m *Manager) needsUpdate(src models.SourceConfig) bool {
	if !src.AutoUpdate {
		return false
	}
	m.mu.RLock()
	last, ok := m.lastUpdate[src.ID]
	m.mu.RUnlock()

	// ТЗ v1.3 F4 Stage 0: время последней загрузки персистентно (SourceConfig.LastUpdatedAt) —
	// менеджер может быть только что создан после перезапуска/нового скана, а источник уже
	// свежий.
	if !ok && src.LastUpdatedAt > 0 {
		last, ok = time.Unix(src.LastUpdatedAt, 0), true
	}
	if !ok {
		return true
	}
	interval := time.Duration(src.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = time.Hour // 0/отрицательный интервал — не «каждый раз», а разумный минимум
	}
	return time.Since(last) >= interval
}

// LastUpdated — копия карты «ID источника → время последней успешной загрузки» этого
// менеджера (только источники, загруженные ИМ; движок переносит их в SourceConfig.LastUpdatedAt).
func (m *Manager) LastUpdated() map[string]time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]time.Time, len(m.lastUpdate))
	for k, v := range m.lastUpdate {
		out[k] = v
	}
	return out
}

// ─── C-7: SOCKS5 CONNECT для загрузки источников через туннель ───────────────────────────

// dialSOCKS5 — TCP-соединение к targetAddr ЧЕРЕЗ локальный SOCKS5 движка (RFC 1928, метод
// «без аутентификации»), без внешних зависимостей.
//
// Почему копия, а не вызов checker: тот же хендшейк есть в internal/checker, но неэкспортируемый
// (checker.dialViaSOCKS5), а пакет checker этим лотом не владеется — экспортировать его значило
// бы править чужой файл. Расхождение зафиксировано в result.md как кандидат на общий
// internal/socks5 при следующем структурном разрезе (лот L7-STRUCT).
//
//	Вход:      адрес прокси (всегда петля: 127.0.0.1:<ListenPort>) и адрес цели.
//	Выход:     соединение или ошибка с внятной причиной на каждом шаге хендшейка.
//	Fail-safe: сам дозвон до прокси идёт через netguard — под `go test` выход за пределы петли
//	           отвергается барьером, как и у прямого клиента.
func dialSOCKS5(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := netguard.DialContext(dialCtx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy %s: %w", proxyAddr, err)
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// 1) Приветствие: VER=5, NMETHODS=1, METHOD=0x00 (no-auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: write greeting: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read method reply: %w", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: no-auth rejected (ver=%d method=%d)", rep[0], rep[1])
	}

	// 2) CONNECT: VER, CMD=1, RSV=0, ATYP, ADDR, PORT.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: split target %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad port %q", portStr)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: write connect: %w", err)
	}

	// 3) Ответ: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT — адрес привязки дочитываем и
	// отбрасываем, иначе его байты уехали бы в тело HTTP-ответа.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read connect reply: %w", err)
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect rejected (rep=%d)", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read bnd len: %w", err)
		}
		skip = int(l[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unknown atyp %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read bnd addr: %w", err)
	}
	// Дедлайн хендшейка снимаем: дальше временем распоряжается http.Client.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
