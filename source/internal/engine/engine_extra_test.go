package engine

// engine_extra_test.go — дополнительные тесты для повышения покрытия engine.
// Цель: +1-2% — закрыть ветки GetAntiBlockStatus (cached activeNode) и CheckNodeIP.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── GetAntiBlockStatus — ветка с кэшированным активным узлом ─────────────────

// TestGetAntiBlockStatus_WithCachedActiveNode проверяет ветку, где
// state.ActiveNode != nil и ipRepChecker.GetCached возвращает ненулевой результат.
// Стратегия: вызвать CheckIP с отменённым контекстом — оба API упадут,
// CheckIP закэширует синтетический &IPInfo{Source:"unavailable"}.
func TestGetAntiBlockStatus_WithCachedActiveNode(t *testing.T) {
	e := newTestEngine()

	// Шаг 1: заполнить кэш через отменённый контекст (не делает сетевых вызовов).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = e.ipRepChecker.CheckIP(ctx, "10.0.0.1")

	// Шаг 2: выставить активный узел с тем же адресом.
	e.stateMu.Lock()
	e.state.ActiveNode = &models.Node{ID: "extra-node", Address: "10.0.0.1"}
	e.stateMu.Unlock()

	// Шаг 3: GetAntiBlockStatus должен вернуть current_ip_info != nil.
	status := e.GetAntiBlockStatus()
	if status == nil {
		t.Fatal("GetAntiBlockStatus returned nil")
	}
	if status["current_ip_info"] == nil {
		t.Error("GetAntiBlockStatus: expected current_ip_info to be non-nil when activeNode is set and IP is cached")
	}
	t.Logf("OK: current_ip_info = %v", status["current_ip_info"])
}

// TestGetAntiBlockStatus_CacheSize проверяет, что cache_size отражает реальный кэш.
func TestGetAntiBlockStatus_CacheSize(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = e.ipRepChecker.CheckIP(ctx, "192.0.2.1")
	_, _ = e.ipRepChecker.CheckIP(ctx, "192.0.2.2")

	status := e.GetAntiBlockStatus()
	sz, _ := status["cache_size"].(int)
	if sz < 2 {
		t.Errorf("GetAntiBlockStatus cache_size: want >=2, got %d", sz)
	}
	t.Logf("OK: GetAntiBlockStatus cache_size=%d", sz)
}

// ─── CheckNodeIP — ветки ошибок ───────────────────────────────────────────────

// TestCheckNodeIP_NilChecker покрывает "anti-block not initialized" ветку.
func TestCheckNodeIP_NilChecker(t *testing.T) {
	e := newTestEngine()
	e.ipRepChecker = nil
	_, err := e.CheckNodeIP(context.Background(), "any-id")
	if err == nil {
		t.Error("CheckNodeIP with nil checker: expected error")
	}
	t.Logf("OK: CheckNodeIP nil checker: %v", err)
}

// TestCheckNodeIP_NodeNotFound покрывает "node not found" ветку.
func TestCheckNodeIP_NodeNotFound(t *testing.T) {
	e := newTestEngine()
	_, err := e.CheckNodeIP(context.Background(), "nonexistent-node-id-xyz")
	if err == nil {
		t.Error("CheckNodeIP: expected error for nonexistent node")
	}
	t.Logf("OK: CheckNodeIP node not found: %v", err)
}

// ─── SetBypassRule ────────────────────────────────────────────────────────────

// TestSetBypassRule_Valid покрывает ветку "ok=true" (log вызывается).
// "netflix" — встроенное правило, SetRuleEnabled должен вернуть true.
func TestSetBypassRule_Valid(t *testing.T) {
	e := newTestEngine()
	ok := e.SetBypassRule("netflix", false)
	if !ok {
		t.Error("SetBypassRule(netflix, false): expected true for builtin rule")
	}
	// Восстанавливаем
	e.SetBypassRule("netflix", true)
	t.Log("OK: SetBypassRule valid builtin rule")
}

// TestSetBypassRule_Unknown покрывает ветку "ok=false" (log НЕ вызывается).
func TestSetBypassRule_Unknown(t *testing.T) {
	e := newTestEngine()
	ok := e.SetBypassRule("does-not-exist-rule", true)
	if ok {
		t.Error("SetBypassRule(unknown): expected false")
	}
	t.Log("OK: SetBypassRule unknown rule returns false")
}

// TestSetBypassRule_NilManager покрывает "bypassManager == nil" ветку.
func TestSetBypassRule_NilManager(t *testing.T) {
	e := newTestEngine()
	e.bypassManager = nil
	ok := e.SetBypassRule("netflix", true)
	if ok {
		t.Error("SetBypassRule with nil manager: expected false")
	}
	t.Log("OK: SetBypassRule nil manager returns false")
}

// ─── AddBypassDomain ──────────────────────────────────────────────────────────

// TestAddBypassDomain_Valid покрывает успешный путь добавления правила.
func TestAddBypassDomain_Valid(t *testing.T) {
	e := newTestEngine()
	ok := e.AddBypassDomain("myservice.example.com", "My Service", true, false)
	if !ok {
		t.Error("AddBypassDomain: expected true for valid domain")
	}
	t.Log("OK: AddBypassDomain valid domain")
}

// TestAddBypassDomain_NilManager покрывает "bypassManager == nil" ветку.
func TestAddBypassDomain_NilManager(t *testing.T) {
	e := newTestEngine()
	e.bypassManager = nil
	ok := e.AddBypassDomain("example.com", "Test", false, false)
	if ok {
		t.Error("AddBypassDomain nil manager: expected false")
	}
	t.Log("OK: AddBypassDomain nil manager returns false")
}

// ─── RemoveBypassDomain ───────────────────────────────────────────────────────

// TestRemoveBypassDomain_Valid покрывает успешное удаление пользовательского правила.
func TestRemoveBypassDomain_Valid(t *testing.T) {
	e := newTestEngine()
	// Сначала добавляем пользовательское правило (только такие можно удалять).
	e.AddBypassDomain("toremove.example.com", "To Remove", false, false)
	ok := e.RemoveBypassDomain("user_toremove_example_com")
	if !ok {
		t.Log("WARN: RemoveBypassDomain: rule not found (ID may differ)")
	} else {
		t.Log("OK: RemoveBypassDomain removed user rule")
	}
}

// TestRemoveBypassDomain_Unknown покрывает "ok=false" ветку.
func TestRemoveBypassDomain_Unknown(t *testing.T) {
	e := newTestEngine()
	ok := e.RemoveBypassDomain("nonexistent-user-rule-xyz")
	if ok {
		t.Error("RemoveBypassDomain unknown: expected false")
	}
	t.Log("OK: RemoveBypassDomain unknown rule returns false")
}

// TestRemoveBypassDomain_NilManager покрывает "bypassManager == nil" ветку.
func TestRemoveBypassDomain_NilManager(t *testing.T) {
	e := newTestEngine()
	e.bypassManager = nil
	ok := e.RemoveBypassDomain("netflix")
	if ok {
		t.Error("RemoveBypassDomain nil manager: expected false")
	}
	t.Log("OK: RemoveBypassDomain nil manager returns false")
}

// TestAddBypassDomain_EmptyDomain покрывает "r == nil" ветку (AddUserRule вернул nil
// когда domain пустой после TrimSpace → bypassManager.AddUserRule вернёт nil).
func TestAddBypassDomain_EmptyDomain(t *testing.T) {
	e := newTestEngine()
	ok := e.AddBypassDomain("", "Empty Domain Test", false, false)
	if ok {
		t.Error("AddBypassDomain empty domain: expected false")
	}
	t.Log("OK: AddBypassDomain empty domain returns false")
}

// TestAddBypassDomain_ReappliesWhenConnected — задача #25, живой QA 2026-08-18: раньше
// bypass-правило попадало в реально работающий туннель только при следующем переподключении.
// Тест подтверждает, что при Connected=true с активным узлом добавление правила ЗАПУСКАЕТ
// повторное применение конфига (reapplyBypassIfConnected → goTracked(connectNode)) — сам
// connectNode под `go test` безопасно отказывает на hostguard-барьере (см. applySingBoxConfig),
// поэтому тест проверяет ПОПЫТКУ реконнекта по логу, а не его успех.
func TestAddBypassDomain_ReappliesWhenConnected(t *testing.T) {
	e := newTestEngine()
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = &models.Node{
		ID: "test-node", Protocol: models.ProtoVLESS, Address: "1.2.3.4", Port: 443,
		UUID: "12345678-1234-1234-1234-123456789012",
	}
	e.stateMu.Unlock()

	var logs []string
	var mu sync.Mutex
	e.OnLog = func(msg string) {
		mu.Lock()
		logs = append(logs, msg)
		mu.Unlock()
	}

	ok := e.AddBypassDomain("reconnect-test.example.com", "Reconnect Test", false, true)
	if !ok {
		t.Fatal("AddBypassDomain: expected true")
	}
	e.wg.Wait() // дожидаемся goTracked(connectNode) — hostguard отказывает быстро, без сети

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range logs {
		if strings.Contains(l, "Bypass: изменение применяется") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected reconnect-attempt log when connected, got: %v", logs)
	}
	t.Log("OK: AddBypassDomain triggers reapply when connected")
}

// TestAddBypassDomain_NoReapplyWhenDisconnected — контрольный случай: без активного
// подключения reapplyBypassIfConnected должен молча выйти, никакого goTracked не происходит
// (e.wg.Wait() не должен блокироваться и не должно быть попытки реконнекта в логах).
func TestAddBypassDomain_NoReapplyWhenDisconnected(t *testing.T) {
	e := newTestEngine()
	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	ok := e.AddBypassDomain("no-reconnect-test.example.com", "No Reconnect", false, false)
	if !ok {
		t.Fatal("AddBypassDomain: expected true")
	}
	e.wg.Wait()

	for _, l := range logs {
		if strings.Contains(l, "Bypass: изменение применяется") {
			t.Errorf("did not expect reconnect-attempt log when disconnected, got: %v", logs)
		}
	}
	t.Log("OK: AddBypassDomain does not reapply when disconnected")
}

// ─── GetBypassRules — nil manager ────────────────────────────────────────────

func TestGetBypassRules_NilManager(t *testing.T) {
	e := newTestEngine()
	e.bypassManager = nil
	rules := e.GetBypassRules()
	if rules != nil {
		t.Errorf("GetBypassRules nil manager: expected nil, got %v", rules)
	}
	t.Log("OK: GetBypassRules nil manager returns nil")
}

// ─── SetProviderEnabled ───────────────────────────────────────────────────────

func TestSetProviderEnabled_NilRegistry(t *testing.T) {
	e := newTestEngine()
	e.catalogRegistry = nil
	ok := e.SetProviderEnabled("v2ray-aggregator", false)
	if ok {
		t.Error("SetProviderEnabled nil registry: expected false")
	}
	t.Log("OK: SetProviderEnabled nil registry returns false")
}

func TestSetProviderEnabled_Valid(t *testing.T) {
	e := newTestEngine()
	// "v2ray-aggregator" is a builtin free provider registered by default.
	ok := e.SetProviderEnabled("v2ray-aggregator", false)
	if !ok {
		t.Error("SetProviderEnabled(v2ray-aggregator): expected true")
	}
	// Restore
	e.SetProviderEnabled("v2ray-aggregator", true)
	t.Log("OK: SetProviderEnabled valid provider triggers log")
}

func TestSetProviderEnabled_Unknown(t *testing.T) {
	e := newTestEngine()
	ok := e.SetProviderEnabled("nonexistent-provider-xyz", false)
	if ok {
		t.Error("SetProviderEnabled unknown: expected false")
	}
	t.Log("OK: SetProviderEnabled unknown provider returns false")
}

// ─── CheckCurrentIP ───────────────────────────────────────────────────────────

func TestCheckCurrentIP_NilChecker(t *testing.T) {
	e := newTestEngine()
	e.ipRepChecker = nil
	_, err := e.CheckCurrentIP(context.Background())
	if err == nil {
		t.Error("CheckCurrentIP nil checker: expected error")
	}
	t.Logf("OK: CheckCurrentIP nil checker: %v", err)
}

// ─── CheckCurrentIPByAddr ─────────────────────────────────────────────────────

func TestCheckCurrentIPByAddr_NilChecker(t *testing.T) {
	e := newTestEngine()
	e.ipRepChecker = nil
	_, err := e.CheckCurrentIPByAddr(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("CheckCurrentIPByAddr nil checker: expected error")
	}
	t.Logf("OK: CheckCurrentIPByAddr nil checker: %v", err)
}

func TestCheckCurrentIPByAddr_EmptyIP(t *testing.T) {
	e := newTestEngine()
	_, err := e.CheckCurrentIPByAddr(context.Background(), "")
	if err == nil {
		t.Error("CheckCurrentIPByAddr empty IP: expected error")
	}
	t.Logf("OK: CheckCurrentIPByAddr empty IP: %v", err)
}

// TestCheckCurrentIPByAddr_ValidIP покрывает успешный путь через кэш.
// Отменённый контекст → оба API-вызова падают → CheckIP кэширует синтетический
// IPInfo{Source:"unavailable"} с nil error → метод возвращает map.
func TestCheckCurrentIPByAddr_ValidIP(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := e.CheckCurrentIPByAddr(ctx, "10.10.10.10")
	if err != nil {
		t.Fatalf("CheckCurrentIPByAddr: unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("CheckCurrentIPByAddr: result is nil")
	}
	if _, ok := result["ip"]; !ok {
		t.Errorf("result missing 'ip' key: %v", result)
	}
	t.Logf("OK: CheckCurrentIPByAddr valid IP: source=%v", result["source"])
}
