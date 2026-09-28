// Package singbox — управление процессом sing-box.
// traffic_monitor.go — мониторинг трафика через Clash-compatible API sing-box.
package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

const defaultPollInterval = 2 * time.Second

// TrafficMonitor опрашивает Clash-compatible API sing-box (/traffic, /connections)
// и предоставляет метрики потреблённого трафика.
type TrafficMonitor struct {
	port    int
	baseURL string

	mu      sync.RWMutex
	stats   TrafficStats
	running bool
	stopCh  chan struct{}
	// stopClosed — отдельный от running флаг: «stopCh ТЕКУЩЕГО цикла Start() уже закрыт».
	// running гасится асинхронно — только когда горутина опроса заметит закрытие канала
	// или отмену ctx и дойдёт до своего defer в конце Start(). Пока это не произошло, два
	// подряд идущих вызова Stop() оба видят running == true и без этого флага оба попытались
	// бы сделать close() на одном и том же уже закрытом канале — паника close of closed
	// channel (воспроизводится детерминированно: Start, короткая пауза, Stop, Stop).
	// stopClosed сбрасывается в false при каждом новом Start().
	stopClosed bool

	// OnLog — необязательный callback для вывода диагностики.
	OnLog func(string)

	// OnStats — необязательный callback, вызывается после каждого успешного опроса со
	// свежим срезом статистики (см. engine.go: используется для синхронизации
	// session.StickySessionManager.SyncFromTraffic — единственный практический источник
	// "активны ли сейчас соединения" для реального трафика, идущего через libbox/TUN в
	// обход Go net.Conn).
	OnStats func(TrafficStats)
}

// TrafficStats — агрегированные показатели трафика.
// Поля названы в соответствии с использованием в engine.go.
type TrafficStats struct {
	UpBytes   int64     `json:"up_bytes"`
	DownBytes int64     `json:"down_bytes"`
	UpSpeed   int64     `json:"up_speed"`   // байт/с (мгновенная скорость)
	DownSpeed int64     `json:"down_speed"` // байт/с
	Conns     int       `json:"connections"`
	UpdatedAt time.Time `json:"updated_at"`
}

// clashTrafficResp — ответ /traffic от sing-box/Clash API.
type clashTrafficResp struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// clashConnectionsResp — ответ /connections от sing-box/Clash API.
type clashConnectionsResp struct {
	DownloadTotal int64 `json:"downloadTotal"`
	UploadTotal   int64 `json:"uploadTotal"`
	Connections   []struct {
		ID string `json:"id"`
	} `json:"connections"`
}

// NewTrafficMonitor создаёт TrafficMonitor для Clash API на указанном порту.
// port — значение experimental.clash_api.external_controller (например, 9092).
func NewTrafficMonitor(port int) *TrafficMonitor {
	return &TrafficMonitor{
		port:    port,
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		stopCh:  make(chan struct{}),
	}
}

// Reset сбрасывает накопленную статистику.
// Вызывается при каждом новом подключении.
func (tm *TrafficMonitor) Reset() {
	tm.mu.Lock()
	tm.stats = TrafficStats{}
	tm.mu.Unlock()
}

// Start запускает фоновый опрос API.
// Принимает context — горутина завершается при ctx.Done().
// Безопасно вызывать несколько раз — повторный вызов игнорируется.
func (tm *TrafficMonitor) Start(ctx context.Context) {
	tm.mu.Lock()
	if tm.running {
		tm.mu.Unlock()
		return
	}
	tm.running = true
	tm.stopClosed = false
	stopCh := make(chan struct{})
	tm.stopCh = stopCh
	tm.mu.Unlock()

	go func() {
		ticker := time.NewTicker(defaultPollInterval)
		defer ticker.Stop()
		defer func() {
			tm.mu.Lock()
			tm.running = false
			tm.mu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			// Читаем локальную переменную stopCh, захваченную выше в момент запуска этой
			// горутины, а НЕ поле tm.stopCh: поле переписывается под tm.mu из Start()/Stop()
			// (в т.ч. следующим циклом Start()), и прямое чтение изменяемого поля структуры
			// без лока из другой горутины — гонка данных, отдельная от паники close of closed
			// channel (ловится go test -race).
			case <-stopCh:
				return
			case <-ticker.C:
				tm.poll()
			}
		}
	}()
}

// Stop останавливает фоновый опрос. Идемпотентен: повторные вызовы безопасны независимо
// от того, успела ли отработать отложенная очистка горутины опроса (см. stopClosed).
func (tm *TrafficMonitor) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.running && !tm.stopClosed {
		close(tm.stopCh)
		tm.stopClosed = true
	}
}

// GetStats возвращает последние собранные метрики (копия, потокобезопасно).
func (tm *TrafficMonitor) GetStats() TrafficStats {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.stats
}

// poll делает одиночный запрос к API и обновляет stats.
func (tm *TrafficMonitor) poll() {
	// API sing-box слушает на петле, барьер её пропускает. Клиент всё равно взят у
	// netguard: единая точка выхода дешевле, чем помнить, какой адрес тут возможен.
	client := netguard.Client(3 * time.Second)

	// /connections — суммарный трафик и число активных соединений
	resp, err := client.Get(tm.baseURL + "/connections")
	if err != nil {
		if tm.OnLog != nil {
			tm.OnLog(fmt.Sprintf("traffic_monitor: /connections error: %v", err))
		}
		return
	}
	defer resp.Body.Close()

	var connResp clashConnectionsResp
	if err := json.NewDecoder(resp.Body).Decode(&connResp); err != nil {
		if tm.OnLog != nil {
			tm.OnLog(fmt.Sprintf("traffic_monitor: decode error: %v", err))
		}
		return
	}

	// /traffic — мгновенная скорость (байт/с)
	var upSpeed, downSpeed int64
	if r2, err2 := client.Get(tm.baseURL + "/traffic"); err2 == nil {
		defer r2.Body.Close()
		var tResp clashTrafficResp
		if json.NewDecoder(r2.Body).Decode(&tResp) == nil {
			upSpeed = tResp.Up
			downSpeed = tResp.Down
		}
	}

	newStats := TrafficStats{
		UpBytes:   connResp.UploadTotal,
		DownBytes: connResp.DownloadTotal,
		UpSpeed:   upSpeed,
		DownSpeed: downSpeed,
		Conns:     len(connResp.Connections),
		UpdatedAt: time.Now(),
	}
	tm.mu.Lock()
	tm.stats = newStats
	tm.mu.Unlock()

	// Вне лока — тот же приём, что и у cancelCurrentCtx в engine.go: колбэк не должен
	// выполняться под tm.mu (может дёргать чужой код с собственными локами).
	if tm.OnStats != nil {
		tm.OnStats(newStats)
	}
}
