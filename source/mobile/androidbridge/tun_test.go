package androidbridge

import (
	"os"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/engine"
)

type fakeProtectCB struct{}

func (fakeProtectCB) Protect(fd int) bool { return true }

func withTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	e := engine.New(androidConfig())
	globalMu.Lock()
	globalEngine = e
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
		tunMu.Lock()
		protectCB = nil
		tunFdHolder = nil
		tunMu.Unlock()
	})
	return e
}

// Контракт StartTun (B-A13) — не инициализировано.
func TestStartTun_NotInitialized(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом")
	}
	if got := StartTun(5, 1400); got != "not initialized" {
		t.Errorf("StartTun() = %q, ожидалось \"not initialized\"", got)
	}
}

// Контракт StartTun — отвергает fd <= 0.
func TestStartTun_RejectsInvalidFd(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	for _, fd := range []int{0, -1} {
		if got := StartTun(fd, 1400); !strings.Contains(got, "fd") {
			t.Errorf("StartTun(%d, 1400) = %q, ожидался отказ по fd", fd, got)
		}
	}
}

// Контракт StartTun — отвергает mtu вне диапазона 576..9000.
func TestStartTun_RejectsInvalidMTU(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	for _, mtu := range []int{0, 575, 9001, -1} {
		got := StartTun(7, mtu)
		if !strings.Contains(got, "mtu") {
			t.Errorf("StartTun(7, %d) = %q, ожидался отказ по mtu", mtu, got)
		}
	}
}

// Контракт StartTun — отвергает отсутствующий ProtectCallback (B-A02).
//
// Инвариант: без ProtectCallback InProcessRunner всё равно не поднимется правильно —
// AutoDetectInterfaceControl откажет на КАЖДОМ сокете. Честнее отказать раньше, на входе.
func TestStartTun_RejectsMissingProtectCallback(t *testing.T) {
	withTestEngine(t)
	// ProtectCallback намеренно не установлен.

	got := StartTun(7, 1400)
	if !strings.Contains(got, "ProtectCallback") {
		t.Errorf("StartTun() = %q, ожидался отказ по отсутствующему ProtectCallback", got)
	}
}

// Находка Ш-6: у StartTun не было пути «подключиться именно к этой ссылке» —
// ScanAndConnect тестирует случайную выборку из всего пула, и вручную добавленный
// узел имел ~1% шанс попасть в неё за одну попытку (воспроизведено на устройстве).
// StartTunToNode закрепляет узел (Engine.PinNode, B-08.3) и подключается напрямую
// (Engine.ConnectByID, B-08.2/FR-4) — тот же путь, что уже использовался для
// закрепления в режиме «прокси», а не новый код выбора узла.

const testVlessLink = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=abc&sni=example.com#test"

// Контракт StartTunToNode — отвергает невалидную ссылку до какого-либо монтажа TUN.
func TestStartTunToNode_RejectsInvalidLink(t *testing.T) {
	got := StartTunToNode(7, 1400, "not-a-valid-link")
	if !strings.Contains(got, "StartTunToNode") {
		t.Errorf("StartTunToNode(invalid link) = %q, ожидался отказ парсера", got)
	}
}

// Контракт StartTunToNode — валидная ссылка, но движок не инициализирован.
func TestStartTunToNode_NotInitialized(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом")
	}
	if got := StartTunToNode(7, 1400, testVlessLink); got != "not initialized" {
		t.Errorf("StartTunToNode() = %q, ожидалось \"not initialized\"", got)
	}
}

// Контракт StartTunToNode — переиспользует те же проверки fd/mtu, что и StartTun
// (общий prepareTun), даже когда ссылка валидна.
func TestStartTunToNode_RejectsInvalidFd(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	if got := StartTunToNode(0, 1400, testVlessLink); !strings.Contains(got, "fd") {
		t.Errorf("StartTunToNode(fd=0, ...) = %q, ожидался отказ по fd", got)
	}
}

// Регрессия (консилиум 2026-08-10, CRITICAL): раньше StartTunToNode монтировал TUN
// (SetRunner/SetTunMode/tunFdHolder через prepareTun) ДО семантической проверки узла —
// ValidateNode срабатывал только внутри AddNodeFromLink, вызываемого ПОСЛЕ монтажа.
// Синтаксически валидная, но семантически невалидная ссылка не должна трогать TUN вообще:
// tunFdHolder обязан остаться nil, если StartTunToNode отказал.
func TestStartTunToNode_RejectsInvalidUUID_BeforeMountingTun(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	// UUID ПУСТОЙ, а не «неканонический»: с 2026-08-24 неканонические идентификаторы —
	// валидны (sing-box/Xray отображают любую строку в UUIDv5), и прежний "not-a-uuid"
	// больше не отказ. Проверяемое свойство от этого не меняется — семантически невалидный
	// узел не должен трогать TUN.
	badLink := "vless://@example.com:443?security=reality&pbk=abc&sni=example.com#test"
	got := StartTunToNode(7, 1400, badLink)
	if !strings.Contains(got, "StartTunToNode") {
		t.Errorf("StartTunToNode(invalid uuid) = %q, ожидался отказ валидатора", got)
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("tunFdHolder != nil — TUN был смонтирован до отказа валидации узла")
	}
}

// Тот же класс отказа (Reality без обязательного pbk), другое поле — обе ветки
// validateRealityIfPresent должны срабатывать ДО prepareTun.
func TestStartTunToNode_RejectsRealityWithoutPublicKey_BeforeMountingTun(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	badLink := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=example.com#test"
	got := StartTunToNode(7, 1400, badLink)
	if !strings.Contains(got, "StartTunToNode") {
		t.Errorf("StartTunToNode(reality без pbk) = %q, ожидался отказ валидатора", got)
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("tunFdHolder != nil — TUN был смонтирован до отказа валидации узла")
	}
}

// Контракт StartTunToChainPartner (живая находка 2026-09-28): те же ранние отказы, что у
// StartTunToNode, — невалидная ссылка или пустой fd не должны монтировать TUN.
func TestStartTunToChainPartner_RejectsBeforeMountingTun(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	if got := StartTunToChainPartner(0, 1400, testVlessLink); !strings.Contains(got, "fd") {
		t.Errorf("StartTunToChainPartner(fd=0) = %q, ожидался отказ по fd", got)
	}
	if got := StartTunToChainPartner(7, 1400, "not-a-valid-link"); !strings.Contains(got, "StartTunToChainPartner") {
		t.Errorf("StartTunToChainPartner(невалидная ссылка) = %q, ожидался отказ парсера", got)
	}
	badReality := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=example.com#p"
	if got := StartTunToChainPartner(7, 1400, badReality); !strings.Contains(got, "StartTunToChainPartner") {
		t.Errorf("StartTunToChainPartner(reality без pbk) = %q, ожидался отказ валидатора", got)
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("tunFdHolder != nil — TUN смонтирован до отказа проверки ссылки партнёра")
	}
}

// Отказ подключения к партнёру ПОСЛЕ монтажа TUN обязан откатываться обратимым путём
// (restartEngine, не engine.Stop — D-A17) и чистить tunFdHolder. Под go test подключение
// гарантированно отказывает на барьере hostguard — ровно тот случай.
func TestStartTunToChainPartner_ConnectFailure_RollsBack(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	restartCalls, stopCalls := 0, 0
	origRestart, origStop := restartEngine, stopEngine
	restartEngine = func(*engine.Engine) error { restartCalls++; return nil }
	stopEngine = func(*engine.Engine) { stopCalls++ }
	t.Cleanup(func() { restartEngine, stopEngine = origRestart, origStop })

	got := StartTunToChainPartner(7, 1400, testVlessLink)
	if !strings.Contains(got, "StartTunToChainPartner") {
		t.Fatalf("StartTunToChainPartner под go test = %q, ожидался отказ подключения", got)
	}
	if restartCalls != 1 || stopCalls != 0 {
		t.Errorf("откат: restartEngine=%d (ожидался 1), engine.Stop=%d (ожидался 0)", restartCalls, stopCalls)
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("rollbackTun не очистил tunFdHolder после отказа подключения к партнёру")
	}
}

func heldTunFdForTest() *os.File {
	tunMu.Lock()
	defer tunMu.Unlock()
	return tunFdHolder
}

// Регрессия (консилиум 2026-08-10, HIGH): rollbackTun — общий откат, которым
// StartTunToNode обязан пользоваться, когда AddNodeFromLink/ConnectByID отказывают ПОСЛЕ
// того, как prepareTun уже смонтировал TUN. Тот же обратимый путь, что у StopTun
// (restartEngine, не терминальный stopEngine — дефект D-A17), плюс очистка tunFdHolder.
func TestRollbackTun_UsesReversiblePath_AndClearsFdHolder(t *testing.T) {
	e := withTestEngine(t)

	restartCalls, stopCalls := 0, 0
	origRestart, origStop := restartEngine, stopEngine
	restartEngine = func(*engine.Engine) error { restartCalls++; return nil }
	stopEngine = func(*engine.Engine) { stopCalls++ }
	t.Cleanup(func() { restartEngine, stopEngine = origRestart, origStop })

	tunMu.Lock()
	tunFdHolder = os.NewFile(uintptr(999999), "apf-tun-test-marker")
	tunMu.Unlock()

	rollbackTun(e)

	if restartCalls != 1 {
		t.Errorf("rollbackTun вызвал restartEngine %d раз, ожидался 1", restartCalls)
	}
	if stopCalls != 0 {
		t.Fatal("rollbackTun пошёл ТЕРМИНАЛЬНЫМ путём (engine.Stop) — " +
			"после него StartTun в этом сеансе не сработал бы")
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("rollbackTun не очистил tunFdHolder")
	}
}

// Контракт StopTun — вызов до инициализации не паникует и не ошибается.
func TestStopTun_SafeBeforeInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом")
	}
	if got := StopTun(); got != "" {
		t.Errorf("StopTun() до инициализации = %q, ожидалась пустая строка", got)
	}
}

// ─── StartTunToNodeID (ТЗ v1.3 F6/КТ-14) ──────────────────────────────────────────────────
//
// Как StartTunToNode, но узел уже в пуле («Мои серверы») — задаётся ID, а не разбирается
// заново из ссылки. Использует тот же prepareTun, поэтому переиспользует его проверки
// fd/mtu/ProtectCallback без дублирования логики.

// Контракт StartTunToNodeID — не инициализировано.
func TestStartTunToNodeID_NotInitialized(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом")
	}
	if got := StartTunToNodeID(7, 1400, "some-id"); got != "not initialized" {
		t.Errorf("StartTunToNodeID() = %q, ожидалось \"not initialized\"", got)
	}
}

// Контракт StartTunToNodeID — отвергает fd <= 0 ДО какой-либо проверки nodeID.
func TestStartTunToNodeID_RejectsInvalidFd(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом")
	}
	for _, fd := range []int{0, -1} {
		if got := StartTunToNodeID(fd, 1400, "some-id"); !strings.Contains(got, "fd") {
			t.Errorf("StartTunToNodeID(%d, 1400, ...) = %q, ожидался отказ по fd", fd, got)
		}
	}
}

// Контракт StartTunToNodeID — отвергает пустой/пробельный nodeID ДО монтажа TUN (fd не
// должен быть смонтирован — тот же принцип, что и у StartTunToNode с невалидной ссылкой).
func TestStartTunToNodeID_RejectsEmptyNodeID(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	for _, id := range []string{"", "   "} {
		got := StartTunToNodeID(7, 1400, id)
		if !strings.Contains(got, "empty node id") {
			t.Errorf("StartTunToNodeID(7, 1400, %q) = %q, ожидался отказ \"empty node id\"", id, got)
		}
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("tunFdHolder != nil — TUN был смонтирован до отказа по пустому nodeID")
	}
}

// Контракт StartTunToNodeID — неизвестный ID: prepareTun успевает смонтировать TUN
// (fd/mtu/ProtectCallback валидны), но ConnectOnce отказывает — rollbackTun обязан вернуть
// движок и fd в состояние ДО вызова (тот же путь, что уже проверен для StartTunToNode в
// TestRollbackTun_UsesReversiblePath_AndClearsFdHolder).
func TestStartTunToNodeID_RejectsUnknownNodeID_RollsBack(t *testing.T) {
	withTestEngine(t)
	SetProtectCallback(fakeProtectCB{})

	restartCalls, stopCalls := 0, 0
	origRestart, origStop := restartEngine, stopEngine
	restartEngine = func(*engine.Engine) error { restartCalls++; return nil }
	stopEngine = func(*engine.Engine) { stopCalls++ }
	t.Cleanup(func() { restartEngine, stopEngine = origRestart, origStop })

	got := StartTunToNodeID(7, 1400, "no-such-node-id")
	if !strings.Contains(got, "StartTunToNodeID") {
		t.Errorf("StartTunToNodeID(неизвестный id) = %q, ожидался отказ ConnectOnce", got)
	}
	if restartCalls != 1 {
		t.Errorf("rollbackTun вызвал restartEngine %d раз, ожидался 1", restartCalls)
	}
	if stopCalls != 0 {
		t.Fatal("StartTunToNodeID пошёл ТЕРМИНАЛЬНЫМ путём отката (engine.Stop)")
	}
	if holder := heldTunFdForTest(); holder != nil {
		t.Error("rollbackTun не очистил tunFdHolder после отказа StartTunToNodeID")
	}
}

// Контракт StopTun — идёт ОБРАТИМОЙ дорогой (тот же урок, что D-A17 у Disconnect):
// терминальный Stop сделал бы повторный StartTun в этом сеансе приложения невозможным.
func TestStopTun_IsReversible_NotTerminal(t *testing.T) {
	withTestEngine(t)

	restartCalls, stopCalls := 0, 0
	origRestart, origStop := restartEngine, stopEngine
	restartEngine = func(*engine.Engine) error { restartCalls++; return nil }
	stopEngine = func(*engine.Engine) { stopCalls++ }
	t.Cleanup(func() { restartEngine, stopEngine = origRestart, origStop })

	if got := StopTun(); got != "" {
		t.Fatalf("StopTun() = %q, ожидался успех", got)
	}
	if restartCalls != 1 {
		t.Errorf("обратимая остановка вызвана %d раз, ожидался 1", restartCalls)
	}
	if stopCalls != 0 {
		t.Fatal("StopTun пошёл ТЕРМИНАЛЬНЫМ путём (engine.Stop) — " +
			"после него StartTun в этом сеансе не сработал бы")
	}
}
