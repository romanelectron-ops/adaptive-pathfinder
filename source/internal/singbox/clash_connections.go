package singbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// clashConnectionsQueryTimeout — короткий таймаут: это опрос ЛОКАЛЬНОГО (127.0.0.1) API,
// не сетевой запрос, долгое ожидание означало бы, что sing-box завис, а не что ответ в пути.
const clashConnectionsQueryTimeout = 2 * time.Second

// ConnectionsSnapshot — минимальный срез /connections, нужный роли «Выход» (§5): сколько
// клиентов сейчас подключено и IP последнего подключившегося (диагностика «точно ли Вход
// достучался», docs/PLAN_2026-08-28_stubs_and_realfunc.md §5, п.3).
type ConnectionsSnapshot struct {
	Count      int    `json:"count"`
	LastRemote string `json:"last_remote,omitempty"`
}

// clashConnectionsFullResp — /connections отдаёт больше полей, чем clashConnectionsResp в
// traffic_monitor.go (тому нужны только тоталы трафика); здесь дополнительно берём
// метаданные соединения ради исходного адреса клиента.
type clashConnectionsFullResp struct {
	Connections []struct {
		Metadata struct {
			SourceIP string `json:"sourceIP"`
		} `json:"metadata"`
	} `json:"connections"`
}

// QueryConnectionsCount — разовый (не поллинг, в отличие от TrafficMonitor) запрос к
// Clash-API sing-box за текущим списком активных соединений. Используется ролью «Выход»
// (GetServerRoleStatus) на каждый опрос статуса из UI — не создаёт постоянно висящую
// горутину ради счётчика, который и так спрашивают раз в несколько секунд.
//
//	Fail-safe: sing-box не запущен / clash-api не поднялся / порт занят — возвращает
//	err без паники; вызывающая сторона (server_role.go) трактует это как «неизвестно»,
//	не как «0 подключений» (см. её комментарий).
func QueryConnectionsCount(port int) (ConnectionsSnapshot, error) {
	client := &http.Client{Timeout: clashConnectionsQueryTimeout}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/connections", port))
	if err != nil {
		return ConnectionsSnapshot{}, fmt.Errorf("clash-api /connections: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ConnectionsSnapshot{}, fmt.Errorf("clash-api /connections: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ConnectionsSnapshot{}, fmt.Errorf("clash-api /connections: чтение ответа: %w", err)
	}

	var parsed clashConnectionsFullResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ConnectionsSnapshot{}, fmt.Errorf("clash-api /connections: разбор JSON: %w", err)
	}

	snap := ConnectionsSnapshot{Count: len(parsed.Connections)}
	if snap.Count > 0 {
		snap.LastRemote = parsed.Connections[snap.Count-1].Metadata.SourceIP
	}
	return snap, nil
}
