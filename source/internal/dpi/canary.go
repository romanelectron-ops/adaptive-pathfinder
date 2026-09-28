// Package dpi — обход Deep Packet Inspection. Фаза 6.
// bypass-engineer: детектируем видит ли провайдер VPN, применяем counter-measures.
package dpi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// CanaryResult — результат Canary-теста
type CanaryResult struct {
	// Видит ли провайдер VPN-трафик
	VPNDetectable bool `json:"vpn_detectable"`

	// Детальные флаги
	TLSFingerprintLeaked bool `json:"tls_fingerprint_leaked"` // Go TLS fingerprint виден
	TimingAnomaly        bool `json:"timing_anomaly"`         // нетипичный timing handshake
	EntropyHigh          bool `json:"entropy_high"`           // высокая энтропия (шифрованный поток)
	PortSuspicious       bool `json:"port_suspicious"`        // подозрительный порт

	// Диагноз и рекомендации
	Score          int    `json:"score"` // 0-100: чем выше, тем заметнее VPN
	Diagnosis      string `json:"diagnosis"`
	Recommendation string `json:"recommendation"`
	CounterMeasure string `json:"counter_measure"` // конкретный метод обхода

	TestedAt time.Time `json:"tested_at"`
	Duration int64     `json:"duration_ms"`
}

// tlsFingerprintURL is an injection hook for testing checkTLSFingerprint.
var tlsFingerprintURL = "https://tls.peet.ws/api/all"

// CanaryTester проверяет детектируемость VPN провайдером.
// bypass-engineer: проверяем TLS fingerprint, timing, энтропию.
type CanaryTester struct {
	socksAddr string
	rawClient *http.Client // клиент без SOCKS (прямой)

	// test injection hooks: nil means use real implementation
	timingAnomalyFn func(ctx context.Context) bool
	entropyHighFn   func(ctx context.Context) bool
}

// NewCanaryTester создаёт тестер
func NewCanaryTester(socksAddr string) *CanaryTester {
	directTransport := &http.Transport{
		// netguard.Guard: под `go test` выход за пределы петли отвергается (Т-5).
		DialContext: netguard.Guard((&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext),
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 5 * time.Second,
	}

	return &CanaryTester{
		socksAddr: socksAddr,
		rawClient: &http.Client{
			Transport: directTransport,
			Timeout:   10 * time.Second,
		},
	}
}

// Test запускает полный Canary-тест.
// bypass-engineer: 4 независимых теста, итоговый score = сумма весов.
func (c *CanaryTester) Test(ctx context.Context) (*CanaryResult, error) {
	started := time.Now()
	result := &CanaryResult{TestedAt: started}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Тест 1: TLS Fingerprint через публичный API
	wg.Add(1)
	go func() {
		defer wg.Done()
		leaked := c.checkTLSFingerprint(ctx)
		mu.Lock()
		result.TLSFingerprintLeaked = leaked
		mu.Unlock()
	}()

	// Тест 2: Timing Anomaly (сравниваем RTT через туннель vs. прямой)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var anomaly bool
		if c.timingAnomalyFn != nil {
			anomaly = c.timingAnomalyFn(ctx)
		} else {
			anomaly = c.checkTimingAnomaly(ctx)
		}
		mu.Lock()
		result.TimingAnomaly = anomaly
		mu.Unlock()
	}()

	// Тест 3: Порт (используем стандартный 443 или нет)
	wg.Add(1)
	go func() {
		defer wg.Done()
		suspicious := c.checkPortSuspicious()
		mu.Lock()
		result.PortSuspicious = suspicious
		mu.Unlock()
	}()

	// Тест 4: Entropy (эвристика — если SOCKS активен → шифрованный трафик)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var high bool
		if c.entropyHighFn != nil {
			high = c.entropyHighFn(ctx)
		} else {
			high = c.checkEntropyHeuristic(ctx)
		}
		mu.Lock()
		result.EntropyHigh = high
		mu.Unlock()
	}()

	wg.Wait()

	// Вычисляем итоговый score
	// bypass-engineer матрица весов:
	score := 0
	if result.TLSFingerprintLeaked {
		score += 40 // критично: JA3/JA3S виден
	}
	if result.TimingAnomaly {
		score += 25 // заметно: нетипичное время handshake
	}
	if result.EntropyHigh {
		score += 20 // подозрительно: высокая энтропия
	}
	if result.PortSuspicious {
		score += 15 // незначительно: нестандартный порт
	}

	result.Score = score
	result.VPNDetectable = score >= 50
	result.Duration = time.Since(started).Milliseconds()
	c.buildDiagnosis(result)

	return result, nil
}

// checkTLSFingerprint проверяет «утечку» Go TLS fingerprint.
// bypass-engineer: стандартный Go crypto/tls имеет уникальный JA3 fingerprint.
// Проверяем через https://tls.peet.ws/api/all (публичный fingerprint сервис).
func (c *CanaryTester) checkTLSFingerprint(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", tlsFingerprintURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.rawClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Читаем тело ограниченно (нам нужны первые 4KB)
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Известные JA3 Go клиентов — детект по фрагменту cipher suite list
	goIndicators := []string{
		`"golang"`,
		`"go "`,
	}
	for _, ind := range goIndicators {
		if strings.Contains(strings.ToLower(body), strings.ToLower(ind)) {
			return true
		}
	}

	return false
}

// checkTimingAnomaly проверяет нетипичный timing handshake.
// bypass-engineer: VPN-туннели имеют характерный «двойной RTT» при handshake.
//
// Находка (Task #8, нестабильные/зависающие прогоны engine_coverage10_test.go): раньше
// дозвон шёл голым &net.Dialer{}, в обход netguard.Guard — прямое нарушение инварианта
// пакета netguard («go test ./... не открывает ни одного соединения за пределы петли»,
// см. internal/netguard/netguard.go). Под `go test` это означало РЕАЛЬНЫЙ TCP-дозвон до
// 1.1.1.1:443/8.8.8.8:443 на каждый прогон — время теста зависело от сети (0-6с, по 3с на
// цель), а не от кода, ровно то, от чего netguard и должен был защищать. netguard.Guard
// сам решает: под тестом — быстрый ErrBlocked без реального дозвона (кроме петли, которой
// тут и нет), вне тестов — поведение не меняется. Тот же guardedDialFn переиспользован в
// checkEntropyHeuristic ниже (там цель обычно и так петля, но правило пакета — ЛЮБОЙ
// исходящий дозвон через netguard, без исключений по факту текущей цели).
var guardedDialFn = netguard.Guard(nil)

func (c *CanaryTester) checkTimingAnomaly(ctx context.Context) bool {
	// Измеряем RTT до нескольких публичных IP
	targets := []string{"1.1.1.1:443", "8.8.8.8:443"}
	var rtts []time.Duration

	for _, target := range targets {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		start := time.Now()
		conn, err := guardedDialFn(dialCtx, "tcp", target)
		cancel()
		if err != nil {
			continue
		}
		rtts = append(rtts, time.Since(start))
		conn.Close()
	}

	if len(rtts) == 0 {
		return false
	}

	var sum time.Duration
	for _, rtt := range rtts {
		sum += rtt
	}
	avg := sum / time.Duration(len(rtts))

	// bypass-engineer: RTT > 150ms к публичным IP = вероятно туннель или далёкий сервер
	// Типичный ping внутри страны: 5-40ms
	return avg > 150*time.Millisecond
}

// checkPortSuspicious — проверяет используем ли нестандартный порт.
func (c *CanaryTester) checkPortSuspicious() bool {
	// Консервативная оценка. Реальная проверка порта exit-узла — в engine.
	return false
}

// checkEntropyHeuristic — эвристика высокой энтропии трафика.
// bypass-engineer: зашифрованный VPN трафик → высокая энтропия.
func (c *CanaryTester) checkEntropyHeuristic(ctx context.Context) bool {
	if c.socksAddr == "" {
		return false
	}
	connCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := guardedDialFn(connCtx, "tcp", c.socksAddr)
	if err != nil {
		return false
	}
	conn.Close()
	// SOCKS работает → шифруем трафик → высокая энтропия → требуется маскировка
	return true
}

// buildDiagnosis формирует читаемый диагноз и рекомендацию.
func (c *CanaryTester) buildDiagnosis(r *CanaryResult) {
	switch {
	case r.Score >= 75:
		r.Diagnosis = "VPN легко обнаруживается провайдером. Требуется немедленная маскировка."
		r.Recommendation = "Включить Reality + uTLS fingerprint. Переключиться на порт 443."
		r.CounterMeasure = "reality+utls"

	case r.Score >= 50:
		r.Diagnosis = "VPN с высокой вероятностью детектируется (DPI анализ)."
		r.Recommendation = "Включить Traffic Padding и WebSocket/gRPC транспорт."
		r.CounterMeasure = "traffic_padding+websocket"

	case r.Score >= 25:
		r.Diagnosis = "VPN частично виден провайдеру. Маскировка рекомендована."
		r.Recommendation = "Включить uTLS fingerprint Chrome. Использовать порт 443."
		r.CounterMeasure = "utls"

	default:
		r.Diagnosis = "VPN хорошо замаскирован. Провайдеру сложно его детектировать."
		r.Recommendation = "Текущая конфигурация оптимальна."
		r.CounterMeasure = "none"
	}

	var details []string
	if r.TLSFingerprintLeaked {
		details = append(details, "Go TLS fingerprint виден (JA3 утечка)")
	}
	if r.TimingAnomaly {
		details = append(details, "нетипичный RTT через туннель")
	}
	if r.EntropyHigh {
		details = append(details, "высокая энтропия трафика (шифрование без маскировки)")
	}
	if len(details) > 0 {
		r.Diagnosis += "\nДетали: " + strings.Join(details, "; ")
	}
}

// QuickCheck — быстрая проверка без параллелизма (для встраивания в flow)
func (c *CanaryTester) QuickCheck(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Только timing check — быстрый и без внешних зависимостей
	return c.checkTimingAnomaly(ctx)
}

// FormatScore возвращает строку для UI
func FormatScore(score int) string {
	switch {
	case score >= 75:
		return fmt.Sprintf("🔴 %d/100 — провайдер видит VPN", score)
	case score >= 50:
		return fmt.Sprintf("🟠 %d/100 — вероятна детекция DPI", score)
	case score >= 25:
		return fmt.Sprintf("🟡 %d/100 — частично виден", score)
	default:
		return fmt.Sprintf("🟢 %d/100 — хорошо замаскирован", score)
	}
}
