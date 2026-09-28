// engine_v13_f4_test.go — ТЗ v1.3 F4, P0-часть (консилиум 2026-09-03, BB-3/BB-4/BB-5, ND-3/ND-6,
// G-B9): single-flight переключения, ре-арминг после исчерпания резервов, цикл по top-K,
// TCP-предпроверка в циклическом поиске, персистентные времена источников, откат sysproxy.
package engine

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// logCapture — потокобезопасный сборщик строк лога: движок пишет из своих горутин
// (emergencySwitch/Stop через goTracked), тест читает — без мьютекса это гонка (-race).
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func captureLogs(e *Engine) *logCapture {
	lc := &logCapture{}
	e.OnLog = func(msg string) {
		lc.mu.Lock()
		lc.lines = append(lc.lines, msg)
		lc.mu.Unlock()
	}
	return lc
}

func (lc *logCapture) all() []string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return append([]string(nil), lc.lines...)
}

func (lc *logCapture) has(sub string) bool {
	for _, l := range lc.all() {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// BB-4: второй вызов emergencySwitch во время первого — выходит сразу, ничего не делая.
func TestEmergencySwitch_SingleFlight(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)
	e.switching.Store(true) // «первый» вызов ещё в работе
	defer e.switching.Store(false)

	e.emergencySwitch()
	if !logs.has("уже выполняется") {
		t.Fatalf("повторный вызов должен пропускаться с логом, logs=%v", logs.all())
	}
	if logs.has("Emergency switch initiated") {
		t.Error("повторный вызов не должен начинать переключение")
	}
}

// BB-5: ре-арминг планируется один раз (второй вызов — no-op), пауза растёт экспоненциально,
// отмена контекста (Disconnect/Stop) снимает ожидание без повторного поиска.
func TestScheduleReArm_OnceGrowsAndCancels(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	e.scheduleReArm(errors.New("all fallbacks failed"))
	e.scheduleReArm(errors.New("second"))
	if !e.reArmPending.Load() || e.reArmAttempts.Load() != 1 {
		t.Fatalf("ожидался ровно один запланированный ре-арминг: pending=%v attempts=%d",
			e.reArmPending.Load(), e.reArmAttempts.Load())
	}
	if !logs.has("Ре-арминг") {
		t.Errorf("ре-арминг должен логироваться: %v", logs.all())
	}

	e.cancelCurrentCtx() // Disconnect/Stop
	e.wg.Wait()
	if e.reArmPending.Load() {
		t.Error("после отмены контекста флаг ожидания должен сняться")
	}
	if logs.has("повторный поиск рабочего узла") {
		t.Error("после отмены контекста повторный поиск не должен запускаться")
	}
}

func TestReArmDelay_Backoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := reArmDelay(int32(i + 1)); got != w {
			t.Errorf("attempt %d: %v, want %v", i+1, got, w)
		}
	}
}

// ND-6: список кандидатов на переключение — упорядоченный, pinned первым, ex исключён.
func TestSelectCandidatesExcluding_OrderAndPinnedFirst(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a, b, pinned := okNode("a", 0.9), okNode("b", 0.8), okNode("pin", 0.1)
	setNodes(e, a, b, pinned)
	if got := strings.Join(ids(e.selectCandidatesExcluding(nil)), ","); got != "a,b,pin" {
		t.Errorf("без pin: %q, want a,b,pin", got)
	}
	if err := e.Pin(pinned.ID); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ids(e.selectCandidatesExcluding(nil)), ","); got != "pin,a,b" {
		t.Errorf("с pin: %q, want pin,a,b", got)
	}
	if got := strings.Join(ids(e.selectCandidatesExcluding(a)), ","); got != "pin,b" {
		t.Errorf("исключая a: %q, want pin,b", got)
	}
	if got := strings.Join(ids(e.rankCandidatesForStrategy()), ","); !strings.HasPrefix(got, "pin,") || len(strings.Split(got, ",")) != 3 {
		t.Errorf("rankCandidatesForStrategy: %q, want pin первым и 3 узла", got)
	}
}

// G-B9: циклический поиск сначала проверяет пачку по TCP и НЕ подключается к мёртвым узлам.
func TestTryCyclicSearch_TCPPrecheckSkipsDeadNodes(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)
	deadPorts := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		deadPorts = append(deadPorts, ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	nodes := make([]*models.Node, 0, 3)
	for i, p := range deadPorts {
		nodes = append(nodes, &models.Node{ID: "d" + string(rune('a'+i)), Name: "dead" + string(rune('a'+i)),
			Address: "127.0.0.1", Port: p, Protocol: models.ProtoVLESS, Status: models.StatusOK})
	}
	setNodes(e, nodes...)

	if ok, _ := e.tryCyclicSearch(nil); ok {
		t.Fatal("среди мёртвых узлов рабочий найтись не может")
	}
	if !logs.has("TCP-проверка пачки") {
		t.Errorf("ожидалась TCP-предпроверка пачки: %v", logs.all())
	}
	if logs.has("Циклический поиск: пробую") {
		t.Errorf("к мёртвым узлам подключаться нельзя: %v", logs.all())
	}
	if !logs.has("полный круг пройден") {
		t.Errorf("круг должен завершиться: %v", logs.all())
	}
}

// Stage 0: время загрузки источника персистентно (cfg.Sources[i].LastUpdatedAt + config.json),
// более старое время не затирает более новое.
func TestPersistSourceTimestamps(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	// Сохранение перехватываем стабом: реальный config.json в общем каталоге могут писать
	// фоновые горутины соседних тестов (updateSources после runPoolScan) — на диске тогда
	// чужое содержимое, а проверять надо именно наш вызов saveConfig.
	var saved *models.AppConfig
	saves := 0
	e.saveConfig = func(c *models.AppConfig) error { saved = c; saves++; return nil }
	e.mu.Lock()
	e.cfg.Sources = []models.SourceConfig{{ID: "s1", Enabled: true}, {ID: "s2", Enabled: true, LastUpdatedAt: 2_000_000_000}}
	e.mu.Unlock()

	now := time.Now()
	e.persistSourceTimestamps(map[string]time.Time{"s1": now, "s2": time.Unix(1_000_000_000, 0)})
	if e.cfg.Sources[0].LastUpdatedAt != now.Unix() {
		t.Errorf("s1: %d want %d", e.cfg.Sources[0].LastUpdatedAt, now.Unix())
	}
	if e.cfg.Sources[1].LastUpdatedAt != 2_000_000_000 {
		t.Errorf("s2: более старое время не должно затирать: %d", e.cfg.Sources[1].LastUpdatedAt)
	}
	if saves != 1 || saved == nil || len(saved.Sources) != 2 || saved.Sources[0].LastUpdatedAt != now.Unix() {
		t.Errorf("время должно уйти в saveConfig ровно один раз: saves=%d saved=%+v", saves, saved)
	}
	e.persistSourceTimestamps(nil)                                                     // no-op
	e.persistSourceTimestamps(map[string]time.Time{"s2": time.Unix(1_500_000_000, 0)}) // старее — без записи
	if saves != 1 {
		t.Errorf("без изменений saveConfig вызываться не должен: saves=%d", saves)
	}
}

// BB-3: откат подключения снимает системный прокси, только если он был выставлен нами.
func TestRollbackConnectionAttempt_ClearsAppliedSysProxyFlag(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.SetSystemProxy = false // sysproxy.Disable не трогает реестр хоста в тесте
	e.sysProxyApplied.Store(true)
	cause := errors.New("boom")
	if err := e.rollbackConnectionAttempt("test", cause, true); !errors.Is(err, cause) {
		t.Errorf("rollback должен вернуть причину: %v", err)
	}
	if e.sysProxyApplied.Load() {
		t.Error("после отката признак «прокси выставлен нами» должен сняться")
	}
}
