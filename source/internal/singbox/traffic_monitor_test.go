// traffic_monitor_test.go — тесты TrafficMonitor: идемпотентность Start/Stop,
// отсутствие гонок и паники на двойном Stop(), проводка колбэков OnStats/OnLog.
//
// Пакет тестов НЕ singbox_test, а singbox — тестам нужен доступ к приватным полям
// (baseURL, running, stopCh) для подмены адреса на httptest-сервер и для белого-ящикового
// ожидания завершения фоновой горутины опроса без хрупких искусственных sleep.
package singbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClashServer — httptest-сервер, эмулирующий Clash-API sing-box: /connections и
// /traffic. Считает обращения к каждому эндпоинту атомарно, чтобы тесты могли проверять
// количество тиков опроса наблюдаемо, а не «на глаз».
type fakeClashServer struct {
	*httptest.Server
	connHits    int32
	trafficHits int32
}

func newFakeClashServer(t *testing.T, conn clashConnectionsResp, traf clashTrafficResp) *fakeClashServer {
	t.Helper()
	fs := &fakeClashServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fs.connHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(conn)
	})
	mux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fs.trafficHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(traf)
	})
	fs.Server = httptest.NewServer(mux)
	return fs
}

func (fs *fakeClashServer) connectionsHits() int { return int(atomic.LoadInt32(&fs.connHits)) }
func (fs *fakeClashServer) trafficHitsCount() int { return int(atomic.LoadInt32(&fs.trafficHits)) }

// waitUntilStopped — белый-ящиковое ожидание того, что фоновая горутина опроса дошла до
// своего defer и выставила running=false. Нужно, чтобы тест Start→Stop→Start детерминированно
// ждал реального завершения предыдущего цикла, а не гадал с фиксированным sleep (что было бы
// источником флакинеса: планировщик может не успеть докрутить горутину до defer).
func waitUntilStopped(tm *TrafficMonitor, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tm.mu.RLock()
		running := tm.running
		tm.mu.RUnlock()
		if !running {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// TestStop_DoubleCallDoesNotPanic — регрессия на основной баг брифа: два подряд идущих
// Stop() до того, как отложенная очистка в горутине опроса успела выставить running=false,
// не должны приводить к повторному close() на уже закрытом stopCh.
func TestStop_DoubleCallDoesNotPanic(t *testing.T) {
	tm := NewTrafficMonitor(19999)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stop() запаниковал: %v", r)
		}
	}()
	tm.Stop()
	tm.Stop() // до фикса: паника close of closed channel
}

// TestNewTrafficMonitor_FieldWiring — проверка развязки полей конструктором.
func TestNewTrafficMonitor_FieldWiring(t *testing.T) {
	tm := NewTrafficMonitor(9092)
	if tm.port != 9092 {
		t.Errorf("port = %d, хочу 9092", tm.port)
	}
	wantURL := "http://127.0.0.1:9092"
	if tm.baseURL != wantURL {
		t.Errorf("baseURL = %q, хочу %q", tm.baseURL, wantURL)
	}
	if tm.stopCh == nil {
		t.Error("stopCh не должен быть nil сразу после NewTrafficMonitor")
	}
}

// TestGetStats_ZeroBeforeFirstPoll — до первого успешного опроса статистика нулевая.
func TestGetStats_ZeroBeforeFirstPoll(t *testing.T) {
	tm := NewTrafficMonitor(19999)
	got := tm.GetStats()
	want := TrafficStats{}
	if got != want {
		t.Errorf("GetStats() до опроса = %+v, хочу нулевое значение", got)
	}
}

// TestReset_ClearsStats — Reset() реально очищает накопленную статистику.
func TestReset_ClearsStats(t *testing.T) {
	tm := NewTrafficMonitor(19999)
	tm.mu.Lock()
	tm.stats = TrafficStats{UpBytes: 100, DownBytes: 200, Conns: 3}
	tm.mu.Unlock()

	tm.Reset()

	got := tm.GetStats()
	want := TrafficStats{}
	if got != want {
		t.Errorf("GetStats() после Reset() = %+v, хочу нулевое значение", got)
	}
}

// TestStop_BeforeStartDoesNotPanic — Stop() без единого предшествующего Start() не паникует
// (stopCh конструктора ещё не закрыт, running=false — Stop() должен быть no-op).
func TestStop_BeforeStartDoesNotPanic(t *testing.T) {
	tm := NewTrafficMonitor(19999)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stop() без Start() запаниковал: %v", r)
		}
	}()
	tm.Stop()
}

// TestStart_SecondCallIsNoop — повторный Start() при уже работающем опросе не поднимает
// вторую горутину поллинга. Проверяется наблюдаемо: считаем реальные HTTP-обращения к
// фейковому Clash-API за один тик опроса — при двух живых горутинах их было бы вдвое больше.
func TestStart_SecondCallIsNoop(t *testing.T) {
	srv := newFakeClashServer(t, clashConnectionsResp{}, clashTrafficResp{})
	defer srv.Close()

	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm.Start(ctx)
	tm.Start(ctx) // второй вызов должен быть no-op

	// Ждём чуть больше одного интервала опроса (defaultPollInterval = 2s), чтобы тикер
	// успел сработать хотя бы один раз.
	time.Sleep(defaultPollInterval + 700*time.Millisecond)
	tm.Stop()

	// Один живой поллер за один тик делает ровно один GET /connections и один GET /traffic.
	// Если бы второй Start() поднял вторую горутину, оба тикера (стартовавшие практически
	// одновременно) сработали бы в то же окно — итог: 2 обращения к каждому эндпоинту.
	if hits := srv.connectionsHits(); hits != 1 {
		t.Errorf("GET /connections вызван %d раз(а), хочу ровно 1 (второй Start() не должен плодить горутину)", hits)
	}
	if hits := srv.trafficHitsCount(); hits != 1 {
		t.Errorf("GET /traffic вызван %d раз(а), хочу ровно 1", hits)
	}
}

// TestStartStopStart_PollsAgain — цикл Start→Stop→Start снова реально запускает опрос.
func TestStartStopStart_PollsAgain(t *testing.T) {
	srv := newFakeClashServer(t, clashConnectionsResp{}, clashTrafficResp{})
	defer srv.Close()

	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL

	ctx1, cancel1 := context.WithCancel(context.Background())
	tm.Start(ctx1)
	time.Sleep(defaultPollInterval + 500*time.Millisecond)
	firstHits := srv.connectionsHits()
	if firstHits < 1 {
		t.Fatalf("первый Start(): GET /connections не вызван ни разу за %v", defaultPollInterval+500*time.Millisecond)
	}

	tm.Stop()
	cancel1()
	if !waitUntilStopped(tm, 2*time.Second) {
		t.Fatal("горутина опроса не завершилась (running всё ещё true) после Stop()+cancel() первого цикла")
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	tm.Start(ctx2)
	time.Sleep(defaultPollInterval + 700*time.Millisecond)
	tm.Stop()

	secondHits := srv.connectionsHits()
	if secondHits <= firstHits {
		t.Errorf("после Start→Stop→Start новых обращений к /connections нет: было %d, стало %d — опрос не перезапустился", firstHits, secondHits)
	}
}

// TestConcurrentStop_NoPanicUnderRace — несколько одновременных Stop() на запущенном
// мониторе не должны паниковать и не должны гонять данные (проверяется -race).
func TestConcurrentStop_NoPanicUnderRace(t *testing.T) {
	srv := newFakeClashServer(t, clashConnectionsResp{}, clashTrafficResp{})
	defer srv.Close()

	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tm.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	const n = 25
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Stop() запаниковал при конкурентном вызове: %v", r)
				}
			}()
			tm.Stop()
		}()
	}
	wg.Wait()
}

// TestConcurrentStartStop_Mixed — вперемешку Start()/Stop() из нескольких горутин: тоже не
// должно ни паниковать, ни гонять данные под -race. Это отдельный сценарий от простого
// «много Stop() подряд»: здесь ещё и stopCh/running переписываются конкурентно из Start().
func TestConcurrentStartStop_Mixed(t *testing.T) {
	srv := newFakeClashServer(t, clashConnectionsResp{}, clashTrafficResp{})
	defer srv.Close()

	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n * 2)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Start() запаниковал при конкурентном вызове: %v", r)
				}
			}()
			tm.Start(ctx)
		}()
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Stop() запаниковал при конкурентном вызове: %v", r)
				}
			}()
			tm.Stop()
		}()
	}
	wg.Wait()
	tm.Stop() // финальная зачистка, тоже не должна паниковать
}

// TestPoll_ParsesResponsesAndInvokesOnStats — проводка колбэка OnStats: poll() ходит
// GET {baseURL}/connections, затем GET {baseURL}/traffic, разбирает обе формы ответа и
// передаёт колбэку собранный TrafficStats. Вызывается poll() напрямую (а не через Start()),
// чтобы не зависеть от реального тикера — это модульная проверка самого разбора ответов.
func TestPoll_ParsesResponsesAndInvokesOnStats(t *testing.T) {
	conn := clashConnectionsResp{
		DownloadTotal: 123456,
		UploadTotal:   654321,
		Connections: []struct {
			ID string `json:"id"`
		}{{ID: "a"}, {ID: "b"}, {ID: "c"}},
	}
	traf := clashTrafficResp{Up: 10, Down: 20}

	srv := newFakeClashServer(t, conn, traf)
	defer srv.Close()

	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL

	statsCh := make(chan TrafficStats, 1)
	tm.OnStats = func(s TrafficStats) {
		select {
		case statsCh <- s:
		default:
		}
	}
	var logMu sync.Mutex
	var logs []string
	tm.OnLog = func(s string) {
		logMu.Lock()
		logs = append(logs, s)
		logMu.Unlock()
	}

	tm.poll()

	select {
	case got := <-statsCh:
		if got.UpBytes != conn.UploadTotal {
			t.Errorf("UpBytes = %d, хочу %d", got.UpBytes, conn.UploadTotal)
		}
		if got.DownBytes != conn.DownloadTotal {
			t.Errorf("DownBytes = %d, хочу %d", got.DownBytes, conn.DownloadTotal)
		}
		if got.UpSpeed != traf.Up {
			t.Errorf("UpSpeed = %d, хочу %d", got.UpSpeed, traf.Up)
		}
		if got.DownSpeed != traf.Down {
			t.Errorf("DownSpeed = %d, хочу %d", got.DownSpeed, traf.Down)
		}
		if got.Conns != len(conn.Connections) {
			t.Errorf("Conns = %d, хочу %d", got.Conns, len(conn.Connections))
		}
		if got.UpdatedAt.IsZero() {
			t.Error("UpdatedAt не выставлен")
		}
	default:
		t.Fatal("OnStats не был вызван после успешного poll()")
	}

	logMu.Lock()
	gotLogs := append([]string(nil), logs...)
	logMu.Unlock()
	if len(gotLogs) != 0 {
		t.Errorf("OnLog вызван на успешном опросе без ошибок: %v", gotLogs)
	}

	if got := tm.GetStats(); got.Conns != len(conn.Connections) {
		t.Errorf("GetStats() после poll() не отражает новые данные: %+v", got)
	}
}

// TestPoll_ConnectionsErrorInvokesOnLog — при ошибке GET /connections (сервер недоступен)
// poll() не падает, а сообщает через OnLog и не трогает статистику.
func TestPoll_ConnectionsErrorInvokesOnLog(t *testing.T) {
	srv := newFakeClashServer(t, clashConnectionsResp{}, clashTrafficResp{})
	srv.Close() // сразу закрываем — GET на этот адрес вернёт ошибку соединения

	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL

	var logMu sync.Mutex
	var logs []string
	tm.OnLog = func(s string) {
		logMu.Lock()
		logs = append(logs, s)
		logMu.Unlock()
	}
	statsCalled := false
	tm.OnStats = func(TrafficStats) { statsCalled = true }

	tm.poll()

	logMu.Lock()
	gotLogs := append([]string(nil), logs...)
	logMu.Unlock()
	if len(gotLogs) == 0 {
		t.Fatal("OnLog не был вызван при недоступном /connections")
	}
	if statsCalled {
		t.Error("OnStats не должен вызываться, если /connections вернул ошибку")
	}
	if got := tm.GetStats(); got != (TrafficStats{}) {
		t.Errorf("статистика не должна меняться при ошибке опроса, получено %+v", got)
	}
}
