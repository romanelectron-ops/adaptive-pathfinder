package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/web"
)

// webClient — HTTP-клиент к Web UI API уже запущенного (в другом процессе) движка
// (internal/web/server.go). Нужен, когда singleinstance.AcquireEngine() не досталась
// GUI (Э-Win-TUN-2, docs/TZ_WINDOWS_TUN_VPN_v1.0.md) — движком владеет apf-svc/apf-tray/
// apf, GUI работает как «наблюдатель», а не поднимает второй sing-box поверх первого.
//
// Порт передаёт вызывающая сторона (app.go: startup()) — она уже пытается прочитать
// config.ReadPortFile() (публикуется владельцем в internal/web/server.go, Start()) и
// откатывается на cfg.WebUIPort, если файла нет. Раньше здесь был захардкожен
// cfg.WebUIPort без какого-либо обнаружения — живой инцидент 2026-08-25 (сторонний
// процесс занял порт по умолчанию раньше APF, владелец сел на другой порт, а этот
// клиент продолжал стучаться в исходный и получал либо чужой ответ, либо тишину).
type webClient struct {
	baseURL string
	http    *http.Client

	// tokenMu/token — S-2 (ТЗ v1.4): постоянный Bearer-токен аутентификации локального API
	// (контракт — result.json.token_contract лота L1-WEB). Читается ЛЕНИВО (при первом
	// запросе, не в newWebClient) и кэшируется; при 401 doAuthorized перечитывает файл и
	// повторяет запрос один раз — служба-владелец могла перезапуститься с новым токеном
	// (он НЕ персистентен между перезапусками процесса, см. контракт).
	tokenMu sync.Mutex
	token   string
}

func newWebClient(port int) *webClient {
	return &webClient{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		// Общего таймаута у клиента НЕТ намеренно: раньше стоял единый netguard.Client(5s), и
		// запуск роли «Выход» (остановка прежней роли + UPnP + 2×netsh + ожидание sing-box до
		// 30 с) стабильно упирался в него — окно показывало «context deadline exceeded», хотя
		// служба запуск успешно заканчивала (живой инцидент ПК 2026-09-29). Срок ожидания теперь
		// свой у каждого запроса — см. requestTimeout/newRequest.
		http: netguard.Client(0),
	}
}

// Сроки ожидания ответа службы. Опрос состояния (GET, раз в секунды) должен падать быстро —
// иначе зависшая служба вешает интерфейс; действия (POST) законно бывают долгими: часть из
// них ходит в сеть или ждёт запуска/остановки процесса, и обрыв на середине выглядит для
// человека как отказ, хотя служба продолжает и доделывает дело.
const (
	timeoutPoll    = 5 * time.Second   // GET-опросы состояния
	timeoutAction  = 30 * time.Second  // обычные POST-действия
	timeoutNetwork = 60 * time.Second  // проверки, ходящие в интернет
	timeoutRoleRun = 90 * time.Second  // запуск роли «Выход», подключение партнёра, резервные туннели
	timeoutCatalog = 200 * time.Second // обновление каталога (в режиме владельца — до 3 минут, app.go)
)

// longRequestTimeouts — пути, которым нужно больше, чем обычному действию. Ключ — путь без
// query-строки. Сроки взяты не «на глаз», а из того, сколько те же операции получают в режиме
// владельца (app.go: RunCanaryTest 25 с, RefreshCatalog 3 мин), плюс запас.
var longRequestTimeouts = map[string]time.Duration{
	"/api/server-role/start":      timeoutRoleRun,
	"/api/chain-partner/connect":  timeoutRoleRun,
	"/api/fallback/activate":      timeoutRoleRun,
	"/api/fallback/auto-select":   timeoutRoleRun,
	"/api/catalog/refresh":        timeoutCatalog,
	"/api/dpi/canary-test":        timeoutNetwork,
	"/api/dpi/shadowtls-auto-sni": timeoutNetwork,
	"/api/leakguard/dns-test":     timeoutNetwork,
	"/api/paid-providers/test":    timeoutNetwork,
	"/api/emergency/wipe":         timeoutNetwork,
	"/api/logs/export":            timeoutNetwork,
}

// requestTimeout — срок ожидания ответа для запроса method+path (path без query-строки).
func requestTimeout(method, path string) time.Duration {
	if d, ok := longRequestTimeouts[path]; ok {
		return d
	}
	if method == http.MethodGet {
		return timeoutPoll
	}
	return timeoutAction
}

// newRequest строит запрос с контекстом-таймаутом по requestTimeout. Вызывающая сторона
// ОБЯЗАНА вызвать cancel после того, как прочитала тело ответа (defer cancel()) — раньше
// срок отсчитывал http.Client.Timeout (он тоже охватывал чтение тела); контекст ведёт себя так же.
func (c *webClient) newRequest(method, path string, body io.Reader) (*http.Request, context.CancelFunc, error) {
	route := path
	if i := strings.IndexByte(route, '?'); i >= 0 {
		route = route[:i]
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout(method, route))
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return req, cancel, nil
}

// webUITokenFilePath — тот же путь, что internal/web/server.go:authTokenFilePath()
// (config.DataDir()/webui_token, НЕ SharedDataDir — см. token_contract лота L1-WEB).
// internal/web не экспортирует свою функцию пути — контракт зафиксирован текстом ТЗ S-2 и
// result.json лота L1-WEB, поэтому путь собран здесь тем же способом, а не импортирован.
func webUITokenFilePath() string {
	return filepath.Join(config.DataDir(), "webui_token")
}

// readWebUIToken — читает файл токена. Ошибка (файла ещё нет — сервер-владелец не успел его
// написать, либо процесс без web.Server вовсе) не паникует и не ломает вызывающий код: он
// получит обычный 401 от сервера, что для наблюдателя и так штатный "не подключились" исход.
func readWebUIToken() (string, error) {
	data, err := os.ReadFile(webUITokenFilePath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// cachedToken — токен из памяти, при первом обращении читается из файла.
func (c *webClient) cachedToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token == "" {
		if tok, err := readWebUIToken(); err == nil {
			c.token = tok
		}
	}
	return c.token
}

// refreshToken — принудительно перечитывает файл токена (сервер-владелец перезапустился —
// см. doc-комментарий у поля token). Не удалось перечитать — оставляет прежнее значение
// (может быть пустой строкой), не паникует.
func (c *webClient) refreshToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if tok, err := readWebUIToken(); err == nil {
		c.token = tok
	}
	return c.token
}

// doAuthorized — S-2: добавляет Authorization: Bearer <token> и повторяет запрос РОВНО один
// раз с перечитанным файлом токена при ответе 401. req должен уметь себя пересобрать
// (req.GetBody) для запросов с телом — http.NewRequest сам заполняет GetBody для
// *bytes.Reader/*bytes.Buffer/*strings.Reader, которыми пользуются getJSON/postJSON ниже.
func (c *webClient) doAuthorized(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.cachedToken())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	resp.Body.Close()

	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		body, berr := req.GetBody()
		if berr != nil {
			return resp, nil // тело не восстановить — возвращаем исходный 401, не паникуем
		}
		retry.Body = body
	}
	retry.Header.Set("Authorization", "Bearer "+c.refreshToken())
	return c.http.Do(retry)
}

func (c *webClient) getJSON(path string, out interface{}) error {
	req, cancel, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer cancel()
	resp, err := c.doAuthorized(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *webClient) postJSON(path string, body interface{}, out interface{}) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, cancel, err := c.newRequest(http.MethodPost, path, r)
	if err != nil {
		return err
	}
	defer cancel()
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doAuthorized(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", string(msg))
	}
	if out == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Handoff — S-2 п.4: POST /api/ui/handoff (обычный /api/*, требует токен — проходит через
// doAuthorized) минтит одноразовый ключ k (TTL 10с) и возвращает готовый URL ".../ui?k=<k>"
// для системного браузера. Постоянный токен в URL никогда не появляется — вызывающая сторона
// (gui/app.go:OpenWebUI, cmd/apf-tray/main.go) открывает ИМЕННО этот URL, а не "/".
func (c *webClient) Handoff() (string, error) {
	var resp struct {
		K     string `json:"k"`
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/ui/handoff", nil, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("%s", resp.Error)
	}
	if resp.K == "" {
		return "", fmt.Errorf("handoff: сервер не вернул одноразовый ключ")
	}
	return c.baseURL + "/ui?k=" + resp.K, nil
}

// GetState — эквивалент engine.GetState(). Отказ HTTP-запроса отдаёт пустое
// ("отключено") состояние, а не панику/nil — тот же честный fail-safe, что и у
// остальных read-методов observer-режима: наблюдатель без связи с владельцем не может
// утверждать что-либо о его состоянии, кроме «неизвестно, считаем отключённым».
func (c *webClient) GetState() *models.ConnectionState {
	var st models.ConnectionState
	if err := c.getJSON("/api/state", &st); err != nil {
		return &models.ConnectionState{}
	}
	return &st
}

func (c *webClient) GetNodes() []*models.Node {
	var body struct {
		Nodes []*models.Node `json:"nodes"`
	}
	if err := c.getJSON("/api/nodes", &body); err != nil {
		return nil
	}
	return body.Nodes
}

func (c *webClient) GetStats() map[string]int {
	var stats map[string]int
	if err := c.getJSON("/api/stats", &stats); err != nil {
		return map[string]int{}
	}
	return stats
}

func (c *webClient) GetSingBoxInfo() map[string]interface{} {
	var info map[string]interface{}
	if err := c.getJSON("/api/singbox", &info); err != nil {
		return map[string]interface{}{}
	}
	return info
}

// Connect/Disconnect/ForceRescan — как и их локальные эквиваленты в app.go, не ждут
// завершения: /api/connect и т.п. сами возвращаются немедленно (движок владельца
// продолжает сканирование/подключение в своей горутине после ответа).
func (c *webClient) Connect() error     { return c.postJSON("/api/connect", nil, nil) }
func (c *webClient) Disconnect() error  { return c.postJSON("/api/disconnect", nil, nil) }
func (c *webClient) ForceRescan() error { return c.postJSON("/api/rescan", nil, nil) }

// PatchConfig — HTTP-эквивалент engine.PatchConfig для наблюдателя (Э-Win-TUN-4).
// Бьёт в тот же /api/save-config, которым уже пользуется старый переключатель во
// встроенном Web UI (internal/web/server.go: apiSaveConfig → eng.PatchConfig) — не
// новый эндпоинт, переиспользование существующего контракта.
func (c *webClient) PatchConfig(patch map[string]interface{}) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/save-config", patch, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) AddNode(link string) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/add-node", map[string]string{"link": link}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// ConnectChainPartner — HTTP-эквивалент App.ConnectChainPartner (§4) для режима наблюдателя.
func (c *webClient) ConnectChainPartner(link string) (*models.Node, error) {
	var resp struct {
		Node  *models.Node `json:"node"`
		Error string       `json:"error"`
	}
	if err := c.postJSON("/api/chain-partner/connect", map[string]string{"link": link}, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Node, nil
}

// AddNodeManual — HTTP-эквивалент App.AddNodeManual для режима наблюдателя. Бьёт в тот же
// /api/add-node-manual, которым давно пользуется встроенный Web UI (internal/web/server.go).
func (c *webClient) AddNodeManual(node *models.Node) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/add-node-manual", node, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// ─── P2.3: роль «Выход»/«Транзит» — HTTP-эквиваленты App.ServerRole* для наблюдателя ────

func (c *webClient) ServerRoleGenerateIdentity() (map[string]interface{}, error) {
	var resp struct {
		Identity map[string]interface{} `json:"identity"`
		Error    string                 `json:"error"`
	}
	if err := c.postJSON("/api/server-role/generate-identity", nil, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Identity, nil
}

func (c *webClient) ServerRoleLoadIdentity() (map[string]interface{}, error) {
	var resp struct {
		Found    bool                   `json:"found"`
		Identity map[string]interface{} `json:"identity"`
		Error    string                 `json:"error"`
	}
	if err := c.getJSON("/api/server-role/identity", &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	if !resp.Found {
		return nil, nil
	}
	return resp.Identity, nil
}

func (c *webClient) ServerRoleBuildLink(identity map[string]interface{}, host string, listenPort int, realityDest, label, relayAddr, relayFingerprint string) (string, error) {
	var resp struct {
		Link  string `json:"link"`
		Error string `json:"error"`
	}
	body := map[string]interface{}{
		"identity": identity, "host": host, "listen_port": listenPort,
		"reality_dest": realityDest, "label": label, "relay_addr": relayAddr,
		"relay_fingerprint": relayFingerprint,
	}
	if err := c.postJSON("/api/server-role/build-link", body, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("%s", resp.Error)
	}
	return resp.Link, nil
}

func (c *webClient) ServerRoleStart(identity map[string]interface{}, listenPort int, realityDest string) error {
	var resp struct {
		Error string `json:"error"`
	}
	body := map[string]interface{}{
		"identity": identity, "listen_port": listenPort, "reality_dest": realityDest,
	}
	if err := c.postJSON("/api/server-role/start", body, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) ServerRoleStop() error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/server-role/stop", nil, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) ServerRoleStatus() map[string]interface{} {
	var status map[string]interface{}
	_ = c.getJSON("/api/server-role/status", &status)
	return status
}

// ─── P2.1: каталог платных провайдеров — HTTP-эквиваленты App.* для наблюдателя ────────

func (c *webClient) AddPaidProvider(entry models.PaidProviderEntry) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/paid-providers/add", entry, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) RemovePaidProvider(id string) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/paid-providers/remove", map[string]string{"id": id}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) TestPaidProvider(entry models.PaidProviderEntry) (int, error) {
	var resp struct {
		NodeCount int    `json:"node_count"`
		Error     string `json:"error"`
	}
	if err := c.postJSON("/api/paid-providers/test", entry, &resp); err != nil {
		return 0, err
	}
	if resp.Error != "" {
		return 0, fmt.Errorf("%s", resp.Error)
	}
	return resp.NodeCount, nil
}

// ─── Приватность/аварийная очистка (аудит паритета Wails GUI vs Web UI,
// 2026-08-12) — HTTP-эквиваленты соответствующих методов Engine, бьют в те же
// эндпоинты, которыми давно пользуется встроенный Web UI. ──────────────────

func (c *webClient) GetLeakGuardStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/leakguard/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

// RunDNSLeakTest — тот же таймаут 15с, что и у владельца (App.RunDNSLeakTest),
// выдержан через netguard.Client(5*time.Second) в newWebClient... нет: HTTP-
// клиент здесь настроен на 5с (см. newWebClient) — короче, чем сам тест может
// длиться (до 8с при удаче, а таймаут на владельце — 15с). Отдельный клиент с
// увеличенным таймаутом ради одного эндпоинта был бы избыточен: наблюдатель —
// уже редкий, вторичный путь (singleinstance почти всегда достаётся первому
// открытому окну), и текущий 5-секундный HTTP-таймаут — тот же для ВСЕХ
// вызовов наблюдателя, каким он уже был до этой правки, не новое ограничение.
func (c *webClient) RunDNSLeakTest() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.postJSON("/api/leakguard/dns-test", nil, &result); err != nil {
		return nil, err
	}
	if errMsg, ok := result["error"].(string); ok && errMsg != "" {
		return nil, fmt.Errorf("%s", errMsg)
	}
	return result, nil
}

func (c *webClient) SetWebRTCBlock(enabled bool) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/leakguard/webrtc", map[string]bool{"enabled": enabled}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) SetMasterPassword(password string) error {
	return c.postJSON("/api/crypto/set-password", map[string]string{"password": password}, nil)
}

func (c *webClient) EmergencyWipe(wipeAll bool, confirm string) (map[string]interface{}, error) {
	var result map[string]interface{}
	body := map[string]interface{}{"wipe_all": wipeAll, "confirm": confirm}
	if err := c.postJSON("/api/emergency/wipe", body, &result); err != nil {
		return nil, err
	}
	if errMsg, ok := result["error"].(string); ok && errMsg != "" {
		return nil, fmt.Errorf("%s", errMsg)
	}
	return result, nil
}

// ─── Сессия: force-switch, sticky policy ───────────────────────────────────

func (c *webClient) ForceSwitch() error {
	return c.postJSON("/api/session/force-switch", nil, nil)
}

func (c *webClient) SetStickyPolicy(policy string) error {
	return c.postJSON("/api/session/policy", map[string]string{"policy": policy}, nil)
}

func (c *webClient) GetSessionStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/session/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

// ─── Анти-DPI/скрытность (область #2) ──────────────────────────────────────

func (c *webClient) GetDPIStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/dpi/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

func (c *webClient) RunCanaryTest() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.postJSON("/api/dpi/canary-test", nil, &result); err != nil {
		return nil, err
	}
	if errMsg, ok := result["error"].(string); ok && errMsg != "" {
		return nil, fmt.Errorf("%s", errMsg)
	}
	return result, nil
}

func (c *webClient) SetTrafficPadding(enabled, aggressive bool) error {
	return c.postJSON("/api/dpi/padding", map[string]bool{"enabled": enabled, "aggressive": aggressive}, nil)
}

func (c *webClient) SetShadowTLSConfig(enabled bool, password, sni, server, serverAddr string) error {
	body := map[string]interface{}{
		"enabled": enabled, "password": password, "sni": sni, "server": server,
		"server_addr": serverAddr,
	}
	return c.postJSON("/api/dpi/shadowtls", body, nil)
}

func (c *webClient) AutoSelectShadowTLSSNI() (string, error) {
	var resp struct {
		SNI   string `json:"sni"`
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/dpi/shadowtls-auto-sni", nil, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("%s", resp.Error)
	}
	return resp.SNI, nil
}

func (c *webClient) SetCDNConfig(workerDomain, backendHost string, backendPort int) error {
	body := map[string]interface{}{"worker_domain": workerDomain, "backend_host": backendHost, "backend_port": backendPort}
	return c.postJSON("/api/dpi/cdn", body, nil)
}

// ─── Fallback-туннели + watchdog (область #3) ──────────────────────────────

func (c *webClient) GetFallbackStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/fallback/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

func (c *webClient) ActivateFallback(tunnel string) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/fallback/activate", map[string]string{"tunnel": tunnel}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) AutoSelectFallback() string {
	var resp struct {
		Tunnel string `json:"tunnel"`
	}
	if err := c.postJSON("/api/fallback/auto-select", nil, &resp); err != nil {
		return ""
	}
	return resp.Tunnel
}

func (c *webClient) GetWatchdogStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/watchdog/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

// ─── Каталог серверов (область #4) ─────────────────────────────────────────

func (c *webClient) GetCatalogStatus() []map[string]interface{} {
	var status []map[string]interface{}
	if err := c.getJSON("/api/catalog/status", &status); err != nil {
		return nil
	}
	return status
}

// RefreshCatalog — /api/catalog/refresh запускает обновление в фоновой
// горутине владельца и отвечает немедленно (см. server.go: apiCatalogRefresh),
// счётчик добавленных узлов туда не попадает — как и локальный владелец-путь
// в App (который ждёт RefreshCatalog синхронно), наблюдатель здесь просто не
// может узнать точное число: сервер его не публикует. Возвращаем 0, ошибку
// не считаем — тот же "честный неизвестный результат", что и у GetState().
func (c *webClient) RefreshCatalog() (int, error) {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/catalog/refresh", nil, &resp); err != nil {
		return 0, err
	}
	if resp.Error != "" {
		return 0, fmt.Errorf("%s", resp.Error)
	}
	return 0, nil
}

func (c *webClient) SetCatalogProviderEnabled(id string, enabled bool) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/catalog/provider", map[string]interface{}{"id": id, "enabled": enabled}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// ─── Блокировка рекламы (область #5) ───────────────────────────────────────

func (c *webClient) GetAdBlockStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/adblock/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

func (c *webClient) SetAdBlockProfile(profile string) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/adblock/profile", map[string]string{"profile": profile}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) AdBlockToggleAllowlist(domain string, add bool) error {
	err := c.postJSON("/api/adblock/allowlist", map[string]interface{}{"domain": domain, "add": add}, nil)
	if err == nil {
		return nil
	}
	// P1-6 (аудит 2026-09-01): при отказе сервер отдаёт 400 с JSON-телом, а postJSON
	// возвращает это тело дословно. Показывать пользователю сырой JSON нельзя — достаём
	// человекочитаемое поле. Если тело не JSON (напр. http.Error с текстом), оставляем как есть.
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(err.Error()), &body) == nil && body.Error != "" {
		return fmt.Errorf("%s", body.Error)
	}
	return err
}

// ─── Анти-блокировка/residential IP (область #6) ───────────────────────────

func (c *webClient) GetAntiBlockStatus() map[string]interface{} {
	var status map[string]interface{}
	if err := c.getJSON("/api/antiblock/status", &status); err != nil {
		return map[string]interface{}{}
	}
	return status
}

func (c *webClient) CheckCurrentIP() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.postJSON("/api/antiblock/check-ip", map[string]string{"ip": "current"}, &result); err != nil {
		return nil, err
	}
	if errMsg, ok := result["error"].(string); ok && errMsg != "" {
		return nil, fmt.Errorf("%s", errMsg)
	}
	return result, nil
}

func (c *webClient) SetAntiBlockConfig(enabled, residentialOnly, autoSwitch bool, apiKey string) error {
	body := map[string]interface{}{
		"enabled": enabled, "residential_only": residentialOnly,
		"auto_switch": autoSwitch, "api_key": apiKey,
	}
	return c.postJSON("/api/antiblock/config", body, nil)
}

func (c *webClient) CheckDomainRouting(query string) []web.DomainRouteResult {
	var result []web.DomainRouteResult
	if err := c.getJSON("/api/domain-check?q="+url.QueryEscape(query), &result); err != nil {
		return nil
	}
	return result
}

func (c *webClient) GetBypassRules() []map[string]interface{} {
	var rules []map[string]interface{}
	if err := c.getJSON("/api/antiblock/bypass-list", &rules); err != nil {
		return nil
	}
	return rules
}

func (c *webClient) SetBypassRule(id string, enabled bool) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := c.postJSON("/api/antiblock/bypass-list", map[string]interface{}{"id": id, "enabled": enabled}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) AddBypassDomain(domain, name string, residential bool, directRoute bool) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	body := map[string]interface{}{
		"domain": domain, "name": name, "residential": residential, "direct_route": directRoute,
	}
	if err := c.postJSON("/api/antiblock/bypass-domain", body, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// ConnectByID/PinNode/UnpinNode/GetPinnedNodeID — §4.4 ТЗ v2.0
// (docs/TZ_APF_QA_AND_BACKLOG_v2.0.md), паритет с Android «Мои серверы».
func (c *webClient) ConnectByID(nodeID string) error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/connect-node", map[string]interface{}{"node_id": nodeID}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) PinNode(nodeID string) error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/pin", map[string]interface{}{"node_id": nodeID, "pinned": true}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// ConnectOnce / SetFavorite / GetFavoriteIDs — ТЗ v1.3 F2 (см. internal/web/server.go:
// apiConnectOnce, apiFavorite, apiFavorites).
func (c *webClient) ConnectOnce(nodeID string) error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/connect-once", map[string]interface{}{"node_id": nodeID}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) SetFavorite(nodeID string, favorite bool) error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/favorite", map[string]interface{}{"node_id": nodeID, "favorite": favorite}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// StartSweep / CancelSweep / GetScanProgress — обход пула (ТЗ v1.3 F4 Stage 1).
func (c *webClient) StartSweep() error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON("/api/scan/start", map[string]interface{}{}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) CancelSweep() {
	_ = c.postJSON("/api/scan/cancel", map[string]interface{}{}, nil)
}

func (c *webClient) GetScanProgress() engine.ScanProgress {
	var p engine.ScanProgress
	if err := c.getJSON("/api/scan/progress", &p); err != nil {
		return engine.ScanProgress{Phase: "idle"}
	}
	return p
}

// NodeAction — POST-действие над узлом (ТЗ v1.3 F3: /api/node/remove|ban|update|reset).
func (c *webClient) NodeAction(path string, body map[string]interface{}) error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := c.postJSON(path, body, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) RestoreRemovedNodes() int {
	var resp struct {
		Restored int `json:"restored"`
	}
	if err := c.postJSON("/api/nodes/restore-removed", map[string]interface{}{}, &resp); err != nil {
		return 0
	}
	return resp.Restored
}

func (c *webClient) GetRemovedNodeIDs() []string {
	var resp struct {
		RemovedIDs []string `json:"removed_ids"`
	}
	if err := c.getJSON("/api/nodes?view=removed", &resp); err != nil {
		return nil
	}
	return resp.RemovedIDs
}

// ExportLogBytes — полный лог-файл службы (GET /api/logs/export, ТЗ v1.3 F5.1). S-2: этот
// эндпоинт тоже под токеном (ТЗ явно перечисляет /api/logs/export как проверенный пример) —
// раньше был единственным местом в файле, минующим getJSON/postJSON (голый c.http.Get без
// заголовка), поэтому переведён на doAuthorized отдельно.
func (c *webClient) ExportLogBytes() ([]byte, error) {
	req, cancel, err := c.newRequest(http.MethodGet, "/api/logs/export", nil)
	if err != nil {
		return nil, err
	}
	defer cancel()
	resp, err := c.doAuthorized(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("экспорт лога: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (c *webClient) GetFavoriteIDs() []string {
	var resp struct {
		FavoriteIDs []string `json:"favorite_ids"`
	}
	if err := c.getJSON("/api/favorites", &resp); err != nil {
		return nil
	}
	return resp.FavoriteIDs
}

func (c *webClient) UnpinNode() {
	_ = c.postJSON("/api/pin", map[string]interface{}{"node_id": "", "pinned": false}, nil)
}

// GetPinnedNodeID — единственный из этой группы read-only (см. apiPinnedNode,
// internal/web/server.go: apiPin сам мутирует состояние, для чтения нужен отдельный GET).
func (c *webClient) GetPinnedNodeID() string {
	var resp struct {
		PinnedNodeID string `json:"pinned_node_id"`
	}
	if err := c.getJSON("/api/pinned-node", &resp); err != nil {
		return ""
	}
	return resp.PinnedNodeID
}

func (c *webClient) UpdateBypassDomain(id, domain, name string, residential bool, directRoute bool) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	body := map[string]interface{}{
		"id": id, "domain": domain, "name": name, "residential": residential, "direct_route": directRoute,
	}
	if err := c.postJSON("/api/antiblock/bypass-domain", body, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *webClient) RemoveBypassDomain(id string) error {
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	body := map[string]interface{}{"remove": true, "id": id}
	if err := c.postJSON("/api/antiblock/bypass-domain", body, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}
