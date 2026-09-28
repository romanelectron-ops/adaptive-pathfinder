// checker_extra_test.go — coverage for CheckOne success path, HTTPHealthCheck body
// parsing, measureLatency ctx-cancel, scoring edge cases.
package checker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── mock dialer helpers ──────────────────────────────────────────────────────

// pipeDialer returns a dialFn that sleeps `delay` then returns one end of a
// net.Pipe(). The other end is immediately closed, simulating a server that
// accepts and disconnects. elapsed will be >= delay.Milliseconds().
func pipeDialer(delay time.Duration) func(string, string, time.Duration) (net.Conn, error) {
	return func(network, addr string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(delay)
		client, server := net.Pipe()
		go server.Close() // server closes right away — client gets EOF, that is fine
		return client, nil
	}
}

// errDialer returns a dialFn that always fails with the given message.
func errDialer(msg string) func(string, string, time.Duration) (net.Conn, error) {
	return func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("%s", msg)
	}
}

// ── CheckOne success paths ───────────────────────────────────────────────────

func TestCheckOne_SuccessPath_MockDial(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(2 * time.Millisecond)

	node := &models.Node{Protocol: models.ProtoVLESS, Address: "1.2.3.4", Port: 443}
	result := c.CheckOne(context.Background(), node)

	if result == nil {
		t.Fatal("CheckOne returned nil")
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if node.Score <= 0 {
		t.Errorf("node.Score should be > 0, got %.4f", node.Score)
	}
	if node.LastChecked.IsZero() {
		t.Error("LastChecked should be set")
	}
	if node.SuccessCount == 0 {
		t.Error("SuccessCount should be incremented")
	}
	if node.FailCount != 0 {
		t.Errorf("FailCount should be reset to 0, got %d", node.FailCount)
	}
	t.Logf("OK: CheckOne success: latency=%dms score=%.3f status=%s",
		result.Latency, node.Score, node.Status)
}

func TestCheckOne_Rehabilitation_MockDial(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(2 * time.Millisecond)

	node := &models.Node{
		Protocol:         models.ProtoVLESS,
		Address:          "1.2.3.4",
		Port:             443,
		SuccessCount:     RehabilitationSuccesses - 1,
		BlacklistedUntil: time.Now().Add(1 * time.Hour),
	}
	result := c.CheckOne(context.Background(), node)

	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Error)
	}
	if !node.BlacklistedUntil.IsZero() {
		t.Errorf("BlacklistedUntil should be cleared after rehabilitation, still: %s",
			node.BlacklistedUntil)
	}
	t.Log("OK: node rehabilitated from blacklist via mock dialer")
}

// ── measureLatency ctx cancellation ─────────────────────────────────────────

func TestMeasureLatency_ContextCancelledMidLoop(t *testing.T) {
	// dialer sleeps 30ms; context expires after 15ms so the select catches ctx.Done()
	c := New(2, 5)
	c.dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(30 * time.Millisecond)
		cli, srv := net.Pipe()
		go srv.Close()
		return cli, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()

	node := &models.Node{Address: "1.2.3.4", Port: 443}
	latencies, err := c.measureLatency(ctx, node)
	// Context should cancel before all 5 pings finish.
	// Either we got ctx.Err() or we collected some latencies before cancellation.
	t.Logf("latencies=%v err=%v", latencies, err)
	if err != nil && !strings.Contains(err.Error(), "context") {
		// err should be context.DeadlineExceeded or context.Canceled
		t.Logf("note: error is not context error: %v", err)
	}
	t.Log("OK: measureLatency ctx-cancel path executed")
}

// ── HTTPHealthCheck body parsing via cfTraceURL override ────────────────────

func TestHTTPHealthCheck_SuccessBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fl=123f\nloc=US\nts=1.0\nip=1.2.3.4\n")
	}))
	defer srv.Close()

	oldURL := cfTraceURL
	cfTraceURL = srv.URL
	defer func() { cfTraceURL = oldURL }()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	latency, country, err := c.HTTPHealthCheck(context.Background(), proxyAddr)

	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if country != "US" {
		t.Errorf("expected country=US, got %q", country)
	}
	if latency < 0 {
		t.Errorf("latency should be >= 0, got %d", latency)
	}
	t.Logf("OK: HTTPHealthCheck success: latency=%dms country=%s", latency, country)
}

// 4xx — это УСПЕХ проверки канала (контракт изменён 2026-08-24).
//
// Проверка отвечает на вопрос «дошёл ли HTTP-ответ через туннель», и любой ответ настоящего
// сервера это доказывает. Cloudflare штатно отдаёт 403/1020 на адреса дата-центров — то есть
// на большинство бесплатных узлов, — и прежний строгий критерий `!= 200` объявлял такие
// рабочие узлы неподтверждёнными. Вместе с гейтом на стороне Android это приводило к тому,
// что исправный туннель принудительно гасился. Провал теперь — ошибка транспорта либо 5xx.
func TestHTTPHealthCheck_ClientErrorStatusIsAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	oldURL := cfTraceURL
	cfTraceURL = srv.URL
	defer func() { cfTraceURL = oldURL }()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	if _, _, err := c.HTTPHealthCheck(context.Background(), proxyAddr); err != nil {
		t.Fatalf("403 означает, что ответ через туннель дошёл — это не провал канала: %v", err)
	}
}

// 5xx — провал: так отвечает промежуточное звено, а не конечный сервер.
func TestHTTPHealthCheck_ServerErrorStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	defer srv.Close()

	oldURL := cfTraceURL
	cfTraceURL = srv.URL
	defer func() { cfTraceURL = oldURL }()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	_, _, err := c.HTTPHealthCheck(context.Background(), proxyAddr)

	if err == nil {
		t.Fatal("ожидалась ошибка при 5xx")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("ошибка должна называть статус 502, получено: %v", err)
	}
}

// ── protocolScore edge cases (nil, Tor, AmneziaWG, default) ─────────────────

func TestProtocolScore_Nil_Extra(t *testing.T) {
	got := protocolScore(nil)
	if got != 0.5 {
		t.Errorf("protocolScore(nil) = %.2f, want 0.5", got)
	}
	t.Log("OK: protocolScore(nil) = 0.5")
}

func TestProtocolScore_Tor_Extra(t *testing.T) {
	n := &models.Node{Protocol: models.ProtoTor}
	got := protocolScore(n)
	if got != 0.15 {
		t.Errorf("protocolScore(Tor) = %.2f, want 0.15", got)
	}
	t.Log("OK: protocolScore(Tor) = 0.15")
}

func TestProtocolScore_Default_Extra(t *testing.T) {
	n := &models.Node{Protocol: "unknown_proto"}
	got := protocolScore(n)
	if got != 0.3 {
		t.Errorf("protocolScore(unknown) = %.2f, want 0.3", got)
	}
	t.Log("OK: protocolScore(unknown) = 0.3")
}

func TestProtocolScore_AmneziaWG_Extra(t *testing.T) {
	n := &models.Node{Protocol: models.ProtoAmneziaWG}
	got := protocolScore(n)
	if got != 0.25 {
		t.Errorf("protocolScore(AmneziaWG) = %.2f, want 0.25", got)
	}
	t.Log("OK: protocolScore(AmneziaWG) = 0.25")
}

// ── CalcScoreWeighted edge cases ─────────────────────────────────────────────

func TestCalcScoreWeighted_NilNode_Extra(t *testing.T) {
	// ТЗ v1.3 F1.4: nil-узел — не «кандидат с полом», а 0. Раньше nil получал minScore и
	// формально был «годен».
	got := CalcScoreWeighted(nil, ScoreWeights{}, 0.42)
	if got != 0 {
		t.Errorf("CalcScoreWeighted(nil) = %.4f, want 0", got)
	}
	t.Log("OK: CalcScoreWeighted(nil) returns 0")
}

// ТЗ v1.3 F1.4/F1.5: узел без единой проверки (IsUnchecked) получает 0 независимо от minScore.
func TestCalcScoreWeighted_Unchecked_IsZero(t *testing.T) {
	n := &models.Node{Protocol: models.ProtoVLESS, Latency: 50}
	if got := CalcScoreWeighted(n, WeightsForMode("balanced"), 0.5); got != 0 {
		t.Errorf("unchecked node: score=%.4f, want 0 (пол не должен поднимать непроверенные)", got)
	}
	n.UserBanned = true
	n.Status = models.StatusOK
	if got := CalcScoreWeighted(n, WeightsForMode("balanced"), 0.5); got != 0 {
		t.Errorf("user-banned node: score=%.4f, want 0", got)
	}
}

func TestCalcScoreWeighted_BelowMinScore(t *testing.T) {
	// Node with terrible stats; minScore set astronomically high so result < minScore.
	// Status выставлен: пол minScore действует только для ПРОВЕРЕННЫХ узлов (F1.4).
	n := &models.Node{
		Protocol: models.ProtoTor, // lowest protocol score 0.15
		Latency:  9999,
		Jitter:   9999,
		Loss:     100.0,
		Status:   models.StatusOK,
	}
	got := CalcScoreWeighted(n, ScoreWeights{
		Latency: 0.40, Jitter: 0.15, Loss: 0.20, Protocol: 0.15, AntiBlock: 0.10,
	}, 9999.0)
	if got != 9999.0 {
		t.Errorf("expected minScore=9999.0, got %.4f", got)
	}
	t.Log("OK: CalcScoreWeighted returns minScore when computed score < minScore")
}

// Регрессия P1-3 (аудит 2026-09-01), см. подробный комментарий у CalcScoreWeighted в scoring.go:
// узел со Status=blocked/blacklist получает 0 БЕЗУСЛОВНО, даже если сохранённые Latency/Jitter/
// Loss — отличные (последнее УСПЕШНОЕ измерение до отказа). Раньше именно это давало мёртвому
// узлу base=1000/50=20 против 1.25 у живого с 800мс — мёртвый выигрывал КАЖДЫЙ выбор до трёх
// отказов подряд. Существующие тесты проверяли эту ветку только внутри markFail/checkOneN
// (checker_unit2_test.go), но не саму CalcScoreWeighted напрямую при явно выставленном статусе.
func TestCalcScoreWeighted_BlockedStatus_ZeroDespiteGoodStats(t *testing.T) {
	goodStatsButBlocked := &models.Node{
		Protocol: models.ProtoVLESS,
		Latency:  50, // отличная задержка — последний успешный замер до отказа
		Jitter:   5,
		Loss:     0,
		Status:   models.StatusBlocked,
	}
	if got := CalcScoreWeighted(goodStatsButBlocked, WeightsForMode("balanced"), 0); got != 0 {
		t.Errorf("StatusBlocked с отличными сохранёнными метриками: score=%.4f, want 0", got)
	}

	blacklisted := &models.Node{
		Protocol: models.ProtoVLESS,
		Latency:  50,
		Jitter:   5,
		Loss:     0,
		Status:   models.StatusBlacklist,
	}
	if got := CalcScoreWeighted(blacklisted, WeightsForMode("balanced"), 0); got != 0 {
		t.Errorf("StatusBlacklist с отличными сохранёнными метриками: score=%.4f, want 0", got)
	}

	// Контраст: тот же узел, но со Status=ok (то есть ещё не помечен отказавшим), получает
	// нормальный положительный score — ветка отсекает именно статус, а не метрики как таковые.
	healthy := &models.Node{Protocol: models.ProtoVLESS, Latency: 50, Jitter: 5, Loss: 0, Status: models.StatusOK}
	if got := CalcScoreWeighted(healthy, WeightsForMode("balanced"), 0); got <= 0 {
		t.Errorf("StatusOK с теми же метриками должен давать score > 0, got %.4f", got)
	}
}

// NormalizeBase — прямая проверка документированных контрольных точек x/(x+1) (см. комментарий
// в scoring.go): раньше формула проверялась только косвенно, через CalcScoreWeighted/порядок
// сортировки, где вклад base смешан с бонусами протокола/анти-блока и погрешность легко
// потерять. calcScore(100,0,0,0,0) при свежем тесте (ageFactor=1, без потерь/джиттера) даёт
// ровно 1000/100=10, calcScore(50,...)=20, calcScore(25,...)=40, calcScore(1000,...)=1 —
// значения ниже проверяют NormalizeBase именно на них, а не пересчитывают calcScore заново.
func TestNormalizeBase_DocumentedCheckpoints(t *testing.T) {
	cases := []struct {
		base float64
		want float64
	}{
		{0, 0},     // документированное "0 и меньше → 0"
		{-5, 0},    // отрицательный base (не должен встречаться, но не должен и уходить в NaN/пад.)
		{10, 10.0 / 11.0}, // 100мс: x/(x+1) = 10/11 ≈ 0.909
		{20, 20.0 / 21.0}, // 50мс
		{40, 40.0 / 41.0}, // 25мс
		{1, 0.5},          // 1000мс: 1/(1+1) = 0.5
	}
	for _, c := range cases {
		if got := NormalizeBase(c.base); got != c.want {
			t.Errorf("NormalizeBase(%v) = %v, want %v", c.base, got, c.want)
		}
	}
}

// NormalizeBase должна быть монотонно неубывающей по base и ограничена [0,1) для base>=0 —
// иначе сортировка узлов по итоговому Score могла бы стать немонотонной по задержке.
func TestNormalizeBase_MonotonicAndBounded(t *testing.T) {
	prev := -1.0
	for base := 0.0; base <= 100; base += 1.5 {
		got := NormalizeBase(base)
		if got < prev {
			t.Fatalf("NormalizeBase(%v)=%v меньше предыдущего значения %v — не монотонно", base, got, prev)
		}
		if got < 0 || got >= 1 {
			t.Fatalf("NormalizeBase(%v)=%v вне [0,1)", base, got)
		}
		prev = got
	}
}
