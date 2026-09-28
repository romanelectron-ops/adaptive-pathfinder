package androidbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
)

// Этот файл дополняет bridge_test.go/tun_test.go/server_role_test.go сценариями для
// экспортируемых функций моста, которые до 2026-09-05 не были покрыты вообще (100-300
// сценариев на весь проект APF, эта доля — Android-мост). Тот же принцип, что и во всём
// остальном пакете: ни один тест не поднимает настоящий движок (.Start()), не трогает
// реальную сеть на успешном пути и не запускает sing-box/apf.exe.

// ─── Общий помощник: снимок/восстановление файла в config.DataDir() ──────────────────────
//
// БАГ (найден 2026-09-05 при составлении этого списка сценариев, см. правки в
// TestNodePin_AfterInit/TestDPIStatus_AfterInit в bridge_test.go): часть тестов этого пакета
// зовёт функции движка, которые персистят в config.DataDir() (config.json/nodes_cache.json/
// nodes_tombstones.json) — на Windows это %APPDATA%\APF, поскольку тамошняя ветка
// config.DataDir() НЕ читает APF_DATA_DIR (см. комментарий у TestAdBlockStatus_AfterInit).
// Без снимка/восстановления `go test` необратимо портит config.json/nodes_cache.json НА
// РЕАЛЬНОЙ МАШИНЕ, на которой запущен тест, — что и было обнаружено при проверке (в
// %APPDATA%\APF\config.json уже лежали "pinned_node":{"name":"TestSS"} и
// "shadowtls_password":"pass" — следы прошлых прогонов тестов без защиты). Этот помощник
// обобщает уже принятый в файле приём (снимок ДО, restore ПОСЛЕ через t.Cleanup) на любое
// имя файла, чтобы каждый новый тест ниже был обязан явно защитить то, что трогает.
func snapshotAndRestoreDataFile(t *testing.T, filename string) {
	t.Helper()
	path := filepath.Join(config.DataDir(), filename)
	original, readErr := os.ReadFile(path)
	existed := readErr == nil
	t.Cleanup(func() {
		if existed {
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Logf("не удалось восстановить %s: %v", path, err)
			}
		} else {
			os.Remove(path)
		}
	})
}

// ─── Последняя линия защиты файлов реальной машины (K2-A, 2026-09-07) ────────────────────
//
// ИЗМЕРЕНО, а не предположено: до этой правки `go test ./mobile/androidbridge/... -race`
// оставлял в РЕАЛЬНОМ %APPDATA%\APF\nodes_cache.json тестовый узел «TestSS»
// (192.168.1.1:8388) — файл менялся при каждом прогоне, хотя семь тестов уже защищены
// snapshotAndRestoreDataFile выше. Проверка: md5 файла до и после прогона различались, а
// diff показывал ровно обновившиеся added_at/last_failed_at тестового узла. Значит запись
// происходит ПОЗЖЕ, чем t.Cleanup конкретного теста: движки, созданные тестами, не
// останавливаются, и их фоновые сохранения приземляются уже после восстановления снимка.
//
// Поэтому снимок делается ещё и на весь пакет: что бы ни писали пережившие тест горутины,
// после m.Run() файлы возвращаются в исходное состояние.
//
// Чего эта защита НЕ даёт: запись, которая случится в промежутке между restore() и
// os.Exit, всё равно останется — гарантия здесь вероятностная, а не абсолютная. Настоящее
// решение — не создавать движки, чей фон продолжает жить после теста, но это правка самих
// тестов/движка, и она за периметром лота K2-A.
func TestMain(m *testing.M) {
	restore := snapshotDataFilesForPackage(
		"config.json",
		"nodes_cache.json",
		"nodes_tombstones.json",
	)
	code := m.Run()
	restore()
	os.Exit(code)
}

// snapshotDataFilesForPackage — тот же приём, что snapshotAndRestoreDataFile, но без
// *testing.T: TestMain выполняется вне теста, и t.Cleanup там недоступен.
func snapshotDataFilesForPackage(names ...string) func() {
	type snapshot struct {
		path    string
		data    []byte
		existed bool
	}
	snaps := make([]snapshot, 0, len(names))
	for _, name := range names {
		path := filepath.Join(config.DataDir(), name)
		data, err := os.ReadFile(path)
		snaps = append(snaps, snapshot{path: path, data: data, existed: err == nil})
	}
	return func() {
		for _, s := range snaps {
			if !s.existed {
				// Файла не было до прогона — значит его создали тесты, и оставлять его
				// на машине владельца нельзя.
				os.Remove(s.path)
				continue
			}
			if err := os.WriteFile(s.path, s.data, 0o644); err != nil {
				os.Stderr.WriteString(
					"androidbridge: не удалось восстановить " + s.path + ": " + err.Error() + "\n")
			}
		}
	}
}

// newBareTestEngine — общий приём этого пакета (engine.New без .Start()): движок готов
// принимать вызовы моста, но не трогает сеть/диск, пока конкретный вызов сам этого не
// потребует (см. комментарии TestCatalogStatus_AfterInit и др. в bridge_test.go).
func newBareTestEngine(t *testing.T) *engine.Engine {
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
	})
	return e
}

// ─── Расширенный контракт «до инициализации» ──────────────────────────────────────────────
//
// TestAccessors_SafeBeforeInit в bridge_test.go покрывает первую волну функций моста
// (осень 2026-08-хх). С тех пор появились StartSweep/CancelSweep/GetScanProgressJSON, полное
// управление узлами (RemoveNode/BanNode/UpdateNodeJSON/ResetNodeStats/RestoreRemovedNodes),
// избранное, платные провайдеры, IPv6-блок, диагностика и приложения вне VPN — ни одна из
// них не проверялась на паникоустойчивость и честные значения ДО Init. Паника в Go,
// вызванном из Kotlin, убивает процесс приложения целиком (см. bridgeRecover в bridge.go) —
// это тот же самый барьер, применённый к оставшейся части публичного API.
func TestAccessors_SafeBeforeInit_ExtendedCoverage(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — проверка неинформативна")
	}

	// Обход пула (ТЗ v1.3 F4).
	if got := StartSweep(); got != "not initialized" {
		t.Errorf("StartSweep() = %q, ожидалось \"not initialized\"", got)
	}
	CancelSweep() // не должно паниковать
	if got := GetScanProgressJSON(); got != `{"phase":"idle"}` {
		t.Errorf("GetScanProgressJSON() = %q, ожидалось {\"phase\":\"idle\"}", got)
	}

	// Управление узлами (ТЗ v1.3 F3).
	if got := RemoveNode("some-id"); got != "not initialized" {
		t.Errorf("RemoveNode() = %q, ожидалось \"not initialized\"", got)
	}
	if got := BanNode("some-id", true); got != "not initialized" {
		t.Errorf("BanNode() = %q, ожидалось \"not initialized\"", got)
	}
	if got := UpdateNodeJSON("some-id", `{"name":"x"}`); got != "not initialized" {
		t.Errorf("UpdateNodeJSON() = %q, ожидалось \"not initialized\"", got)
	}
	if got := ResetNodeStats("some-id"); got != "not initialized" {
		t.Errorf("ResetNodeStats() = %q, ожидалось \"not initialized\"", got)
	}
	if got := RestoreRemovedNodes(); got != 0 {
		t.Errorf("RestoreRemovedNodes() = %d, ожидалось 0", got)
	}

	// Избранное (ТЗ v1.3 F2).
	if got := GetFavoriteIDsJSON(); got != "[]" {
		t.Errorf("GetFavoriteIDsJSON() = %q, ожидалось \"[]\"", got)
	}
	if got := AddFavorite("some-id"); got != "not initialized" {
		t.Errorf("AddFavorite() = %q, ожидалось \"not initialized\"", got)
	}
	if got := RemoveFavorite("some-id"); got != "not initialized" {
		t.Errorf("RemoveFavorite() = %q, ожидалось \"not initialized\"", got)
	}

	// Подключение.
	if got := ConnectNode("vless://x@example.com:443"); got != "not initialized" {
		t.Errorf("ConnectNode() = %q, ожидалось \"not initialized\"", got)
	}
	if got := ConnectOnce("some-id"); got != "not initialized" {
		t.Errorf("ConnectOnce() = %q, ожидалось \"not initialized\"", got)
	}
	if got := ConnectChainPartner("vless://x@example.com:443"); got != "not initialized" {
		t.Errorf("ConnectChainPartner() = %q, ожидалось \"not initialized\"", got)
	}
	if IsVerified() {
		t.Error("IsVerified() = true до инициализации")
	}
	if got := GetActiveNodeLatency(); got != 0 {
		t.Errorf("GetActiveNodeLatency() = %d, ожидалось 0", got)
	}
	if got := GetStateJSON(); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("GetStateJSON() = %q, ожидалась ошибка not initialized", got)
	}

	// Платные провайдеры (TZ_TAILS_HARDENING кластер C).
	if got := GetPaidProvidersJSON(); got != "[]" {
		t.Errorf("GetPaidProvidersJSON() = %q, ожидалось \"[]\"", got)
	}
	if got := AddPaidProvider(`{"name":"x"}`); got != "not initialized" {
		t.Errorf("AddPaidProvider() = %q, ожидалось \"not initialized\"", got)
	}
	if got := RemovePaidProvider("some-id"); got != "not initialized" {
		t.Errorf("RemovePaidProvider() = %q, ожидалось \"not initialized\"", got)
	}
	if got := TestPaidProvider(`{"name":"x"}`); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("TestPaidProvider() = %q, ожидалась ошибка not initialized", got)
	}

	// Приложения вне VPN.
	if got := GetDisallowedAppsJSON(); got != "[]" {
		t.Errorf("GetDisallowedAppsJSON() = %q, ожидалось \"[]\"", got)
	}
	if got := SetDisallowedAppsJSON(`["com.example.app"]`); got != "not initialized" {
		t.Errorf("SetDisallowedAppsJSON() = %q, ожидалось \"not initialized\"", got)
	}

	// IPv6-блок, диагностика, тумблеры автопереключения/циклического поиска.
	if got := SetIPv6Block(true); got != "not initialized" {
		t.Errorf("SetIPv6Block() = %q, ожидалось \"not initialized\"", got)
	}
	// K2-A (свод C трек 1 п.2): геттеры для начального состояния экрана. До Init —
	// fail-closed «защиты нет» и «политика неизвестна», а не выдуманные значения.
	if IsIPv6BlockEnabled() {
		t.Error("IsIPv6BlockEnabled() = true до инициализации, ожидалось false (fail-closed)")
	}
	if got := GetStickySessionPolicy(); got != "" {
		t.Errorf("GetStickySessionPolicy() = %q до инициализации, ожидалась пустая строка", got)
	}
	if got := GetDiagnosticsJSON(); got != "{}" {
		t.Errorf("GetDiagnosticsJSON() = %q, ожидалось \"{}\"", got)
	}
	if !IsNodeAutoSwitchEnabled() {
		t.Error("IsNodeAutoSwitchEnabled() = false до инициализации, ожидалось true (безопасный дефолт)")
	}
	SetNodeAutoSwitchEnabled(false) // не должно паниковать
	if IsCyclicNodeSearchEnabled() {
		t.Error("IsCyclicNodeSearchEnabled() = true до инициализации, ожидалось false")
	}
	SetCyclicNodeSearch(true) // не должно паниковать

	// Логи/состояние/утечки — колбэки не должны падать без движка.
	SetLogCallback(nil)
	SetStateCallback(nil)
	SetLeakCallback(nil)
}

// GetLocalIPCandidatesJSON (server_role.go) не зависит от getEngine() вообще — её
// естественное место было бы в server_role_test.go, но раз уж вся секция "до инициализации"
// собрана здесь, проверяем тут же: интерфейсы этой машины перечисляются независимо от
// состояния движка.
func TestGetLocalIPCandidatesJSON_NeverNull(t *testing.T) {
	out := GetLocalIPCandidatesJSON()
	var decoded []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("GetLocalIPCandidatesJSON() = %q, не парсится как JSON-массив: %v", out, err)
	}
	// Инвариант из doc-комментария: "[]", НЕ "null" — Kotlin вызывает JSONArray(...) без
	// проверки на null.
	if strings.TrimSpace(out) == "null" {
		t.Fatal("GetLocalIPCandidatesJSON() = \"null\" — JSONArray(...) на Kotlin-стороне упадёт")
	}
}

// ─── ConnectNode / ConnectOnce / ConnectChainPartner — контракт после инициализации ───────

// Контракт ConnectNode: невалидная ссылка отвергается синхронно (AddNodeFromLink), до
// какого-либо фонового ScanAndConnect; валидная ссылка добавляет узел (нужен снимок
// nodes_cache.json — AddNodeFromLink зовёт saveNodes) и возвращает успех, а ScanAndConnect
// уходит в фон (не блокирует вызов — hostguard всё равно не даст ему поднять sing-box
// под `go test`, см. комментарий у TestAdBlockStatus_AfterInit про hostguard).
func TestConnectNode_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "nodes_cache.json")
	newBareTestEngine(t)

	if got := ConnectNode("not-a-valid-link"); got == "" {
		t.Error("ConnectNode(невалидная ссылка) вернул успех")
	}

	if got := ConnectNode("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.2:8388#ConnNode"); got != "" {
		t.Errorf("ConnectNode(валидная ссылка) = %q, ожидался успех", got)
	}
}

// Контракт ConnectOnce (ТЗ v1.3 F2, PIN-8): подключение БЕЗ изменения закрепления — в
// отличие от ConnectByID (уже покрыт TestNodePin_AfterInit), который закрепляет узел сам.
func TestConnectOnce_AfterInit_DoesNotPin(t *testing.T) {
	snapshotAndRestoreDataFile(t, "nodes_cache.json")
	snapshotAndRestoreDataFile(t, "config.json")
	newBareTestEngine(t)

	if got := AddNode("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.3:8388#ConnOnce"); got != "" {
		t.Fatalf("AddNode() = %q, ожидался успех", got)
	}
	var nodes []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil || len(nodes) == 0 {
		t.Fatalf("GetNodesJSON() не вернул добавленный узел: %v", err)
	}
	id := nodes[0].ID

	if got := ConnectOnce(id); got != "" {
		t.Errorf("ConnectOnce(%q) = %q, ожидался успех", id, got)
	}
	if pid := getEngine().PinnedNodeID(); pid != "" {
		t.Errorf("ConnectOnce закрепил узел (PinnedNodeID=%q) — по контракту F2/PIN-8 не должен", pid)
	}

	if got := ConnectOnce(""); got == "" {
		t.Error("ConnectOnce(\"\") вернул успех, ожидалась ошибка (пустой id)")
	}
	if got := ConnectOnce("no-such-id"); got == "" {
		t.Error("ConnectOnce с несуществующим ID вернул успех")
	}
}

// Контракт ConnectChainPartner (роль «Вход», §4): невалидная ссылка отвергается синтаксисом
// parser.ParseLink ДО каких-либо побочных эффектов; валидная ссылка добавляет партнёра в
// пул (нужен снимок nodes_cache.json) и синхронно пытается подключиться — hostguard
// отклоняет попытку быстро (та же гарантия, что и у ConnectByID в TestNodePin_AfterInit),
// поэтому итоговый ответ — текст ошибки «партнёр недоступен…», не пустая строка.
func TestConnectChainPartner_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "nodes_cache.json")
	newBareTestEngine(t)

	if got := ConnectChainPartner("not-a-valid-link"); got == "" {
		t.Error("ConnectChainPartner(невалидная ссылка) вернул успех")
	}

	got := ConnectChainPartner(testVlessLink)
	if got == "" {
		t.Fatal("ConnectChainPartner(валидная ссылка) вернул успех — под hostguard подключение обязано отказать")
	}
	if !strings.Contains(got, "партнёр недоступен") {
		t.Errorf("ConnectChainPartner() = %q, ожидался текст «партнёр недоступен…»", got)
	}
}

// ─── Избранное (ТЗ v1.3 F2) ────────────────────────────────────────────────────────────────

func TestFavorites_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "nodes_cache.json")
	snapshotAndRestoreDataFile(t, "config.json")
	newBareTestEngine(t)

	if got := AddNode("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.4:8388#Fav"); got != "" {
		t.Fatalf("AddNode() = %q, ожидался успех", got)
	}
	var nodes []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil || len(nodes) == 0 {
		t.Fatalf("GetNodesJSON() не вернул добавленный узел: %v", err)
	}
	id := nodes[0].ID

	if ids := GetFavoriteIDsJSON(); ids != "[]" {
		t.Errorf("GetFavoriteIDsJSON() до AddFavorite = %q, ожидалось \"[]\"", ids)
	}
	if got := AddFavorite(id); got != "" {
		t.Errorf("AddFavorite(%q) = %q, ожидался успех", id, got)
	}
	if ids := GetFavoriteIDsJSON(); !strings.Contains(ids, id) {
		t.Errorf("GetFavoriteIDsJSON() = %q, ожидался %q", ids, id)
	}
	// Идемпотентность — повторное добавление не ошибка (см. Engine.AddFavorite).
	if got := AddFavorite(id); got != "" {
		t.Errorf("повторный AddFavorite(%q) = %q, ожидался успех (идемпотентно)", id, got)
	}

	if got := RemoveFavorite(id); got != "" {
		t.Errorf("RemoveFavorite(%q) = %q, ожидался успех", id, got)
	}
	if ids := GetFavoriteIDsJSON(); ids != "[]" {
		t.Errorf("GetFavoriteIDsJSON() после RemoveFavorite = %q, ожидалось \"[]\"", ids)
	}

	if got := AddFavorite(""); got == "" {
		t.Error("AddFavorite(\"\") вернул успех, ожидалась ошибка")
	}
	if got := AddFavorite("no-such-id"); got == "" {
		t.Error("AddFavorite с несуществующим ID вернул успех")
	}
	// Неизвестный/неизбранный ID — не ошибка (см. doc-комментарий Engine.RemoveFavorite).
	if got := RemoveFavorite("no-such-id"); got != "" {
		t.Errorf("RemoveFavorite с неизбранным ID = %q, ожидался успех (не ошибка)", got)
	}
}

// ─── Управление узлами (ТЗ v1.3 F3) ────────────────────────────────────────────────────────

// Контракт RemoveNode/BanNode/UpdateNodeJSON/ResetNodeStats/RestoreRemovedNodes:
// позитивный путь + неизвестный ID → ошибка без побочных эффектов. ResetNodeStats
// проверяется только по возвращаемому значению: узел, только что добавленный AddNode,
// параллельно проверяется фоновой горутиной checker.CheckOne (см. AddNodeFromLink) — сверка
// точных нулевых полей сразу после ResetNodeStats была бы гонкой с этой горутиной, не
// дефектом моста.
func TestNodeLifecycleManagement_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "nodes_cache.json")
	snapshotAndRestoreDataFile(t, "nodes_tombstones.json")
	snapshotAndRestoreDataFile(t, "config.json")
	newBareTestEngine(t)

	if got := AddNode("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.5:8388#Lifecycle"); got != "" {
		t.Fatalf("AddNode() = %q, ожидался успех", got)
	}
	var nodes []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Banned bool   `json:"banned"`
		Note   string `json:"note"`
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil || len(nodes) == 0 {
		t.Fatalf("GetNodesJSON() не вернул добавленный узел: %v", err)
	}
	id := nodes[0].ID

	// BanNode — позитивный путь и отражение в GetNodesJSON.
	if got := BanNode(id, true); got != "" {
		t.Errorf("BanNode(%q, true) = %q, ожидался успех", id, got)
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil {
		t.Fatalf("GetNodesJSON() после BanNode не распарсился: %v", err)
	}
	if !nodes[0].Banned {
		t.Error("GetNodesJSON() не отражает banned=true после BanNode(true)")
	}
	if got := BanNode(id, false); got != "" {
		t.Errorf("BanNode(%q, false) = %q, ожидался успех (снятие бана)", id, got)
	}
	if got := BanNode("no-such-id", true); got == "" {
		t.Error("BanNode с несуществующим ID вернул успех")
	}

	// UpdateNodeJSON — имя/заметка и отражение в GetNodesJSON.
	if got := UpdateNodeJSON(id, `{"name":"Renamed","user_note":"моя заметка"}`); got != "" {
		t.Errorf("UpdateNodeJSON(%q, ...) = %q, ожидался успех", id, got)
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil {
		t.Fatalf("GetNodesJSON() после UpdateNodeJSON не распарсился: %v", err)
	}
	if nodes[0].Name != "Renamed" || nodes[0].Note != "моя заметка" {
		t.Errorf("GetNodesJSON() после UpdateNodeJSON = name=%q note=%q, ожидалось Renamed/моя заметка",
			nodes[0].Name, nodes[0].Note)
	}
	if got := UpdateNodeJSON(id, "{not valid json"); !strings.HasPrefix(got, "bad json:") {
		t.Errorf("UpdateNodeJSON(невалидный JSON) = %q, ожидался префикс \"bad json:\"", got)
	}
	if got := UpdateNodeJSON("no-such-id", `{"name":"x"}`); got == "" {
		t.Error("UpdateNodeJSON с несуществующим ID вернул успех")
	}

	// ResetNodeStats — только контракт успех/отказ (см. doc-комментарий выше про гонку).
	if got := ResetNodeStats(id); got != "" {
		t.Errorf("ResetNodeStats(%q) = %q, ожидался успех", id, got)
	}
	if got := ResetNodeStats("no-such-id"); got == "" {
		t.Error("ResetNodeStats с несуществующим ID вернул успех")
	}

	// RestoreRemovedNodes — пока ничего не удалено, 0.
	if got := RestoreRemovedNodes(); got != 0 {
		t.Errorf("RestoreRemovedNodes() без удалений = %d, ожидалось 0", got)
	}

	// RemoveNode — узел пропадает из GetNodesJSON, повторное удаление — ошибка.
	if got := RemoveNode(id); got != "" {
		t.Errorf("RemoveNode(%q) = %q, ожидался успех", id, got)
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil {
		t.Fatalf("GetNodesJSON() после RemoveNode не распарсился: %v", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			t.Fatalf("узел %q всё ещё в GetNodesJSON() после RemoveNode", id)
		}
	}
	if got := RemoveNode(id); got == "" {
		t.Error("повторный RemoveNode на уже удалённом узле вернул успех")
	}
	if got := RemoveNode("no-such-id"); got == "" {
		t.Error("RemoveNode с несуществующим ID вернул успех")
	}

	// Надгробие теперь есть — RestoreRemovedNodes обязан его снять и вернуть 1.
	if got := RestoreRemovedNodes(); got != 1 {
		t.Errorf("RestoreRemovedNodes() после удаления одного узла = %d, ожидалось 1", got)
	}
}

// ─── Обход пула (ТЗ v1.3 F4 Stage 1) ────────────────────────────────────────────────────────

// StartSweep/CancelSweep/GetScanProgressJSON на СВЕЖЕМ движке с пустым пулом: runSweep
// (internal/engine/sweep.go) при total==0 завершается немедленно и НЕ пишет scan_state.json
// (saveScanCursor вызывается только внутри цикла по непустым пачкам) — единственный случай,
// который можно проверить без риска потрогать реальный диск/сеть на этой машине.
func TestSweepContract_AfterInit(t *testing.T) {
	newBareTestEngine(t)

	if got := StartSweep(); got != "" {
		t.Errorf("StartSweep() = %q, ожидался успех", got)
	}
	// Не должно паниковать вне зависимости от того, успел ли фоновый обход пустого пула
	// завершиться раньше этого вызова.
	CancelSweep()

	var progress struct {
		Phase string `json:"phase"`
	}
	if err := json.Unmarshal([]byte(GetScanProgressJSON()), &progress); err != nil {
		t.Fatalf("GetScanProgressJSON() не парсится: %v", err)
	}
	if progress.Phase == "" {
		t.Error("GetScanProgressJSON().phase пуст — ожидалось непустое значение (idle/running/done/cancelled)")
	}
}

// ─── Платные провайдеры (TZ_TAILS_HARDENING кластер C) — безопасные пути ──────────────────
//
// AddPaidProvider/TestPaidProvider на УСПЕШНОМ пути реально ходят в сеть (catalog.Fetch, до
// 15-20с) — та же причина, по которой RunDNSLeakTestJSON/RunCanaryTestJSON не тестируются
// успешным путём в этом пакете (см. комментарии в bridge_test.go). Здесь проверяются только
// пути, возвращающиеся ДО сетевого вызова.
func TestPaidProviders_SafePaths_AfterInit(t *testing.T) {
	newBareTestEngine(t)

	if got := GetPaidProvidersJSON(); got != "[]" {
		t.Errorf("GetPaidProvidersJSON() сразу после Init = %q, ожидалось \"[]\"", got)
	}

	if got := AddPaidProvider("{not valid json"); !strings.HasPrefix(got, "bad json:") {
		t.Errorf("AddPaidProvider(невалидный JSON) = %q, ожидался префикс \"bad json:\"", got)
	}

	if got := RemovePaidProvider("no-such-provider"); !strings.HasPrefix(got, "not found:") {
		t.Errorf("RemovePaidProvider(неизвестный ID) = %q, ожидался префикс \"not found:\"", got)
	}

	got := TestPaidProvider("{not valid json")
	var decoded struct {
		Count int    `json:"count"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("TestPaidProvider(невалидный JSON) = %q, не парсится: %v", got, err)
	}
	if decoded.Count != 0 || !strings.HasPrefix(decoded.Error, "bad json:") {
		t.Errorf("TestPaidProvider(невалидный JSON) = %q, ожидался count=0 и error с префиксом \"bad json:\"", got)
	}
}

// ─── Приложения вне VPN ─────────────────────────────────────────────────────────────────────

func TestDisallowedApps_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "config.json")
	newBareTestEngine(t)

	if got := GetDisallowedAppsJSON(); got != "[]" {
		t.Errorf("GetDisallowedAppsJSON() сразу после Init = %q, ожидалось \"[]\"", got)
	}

	if got := SetDisallowedAppsJSON("{not valid json"); !strings.Contains(got, "некорректный") {
		t.Errorf("SetDisallowedAppsJSON(невалидный JSON) = %q, ожидался отказ с пояснением", got)
	}
	if got := GetDisallowedAppsJSON(); got != "[]" {
		t.Errorf("GetDisallowedAppsJSON() после отказа SetDisallowedAppsJSON = %q, список не должен был измениться", got)
	}

	if got := SetDisallowedAppsJSON(`["com.example.bank"," com.example.gov ", "", "com.example.bank"]`); got != "" {
		t.Errorf("SetDisallowedAppsJSON(валидный список) = %q, ожидался успех", got)
	}
	var pkgs []string
	if err := json.Unmarshal([]byte(GetDisallowedAppsJSON()), &pkgs); err != nil {
		t.Fatalf("GetDisallowedAppsJSON() после SetDisallowedAppsJSON не парсится: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("GetDisallowedAppsJSON() = %v, ожидалось 2 пакета (пустая строка и дубликат отсеяны)", pkgs)
	}
}

// ─── IPv6-блок ──────────────────────────────────────────────────────────────────────────────
//
// На Windows EnableIPv6Block — чистое состояние в памяти (internal/leakguard/ipv6.go: ветка
// currentGOOS=="linux" делает sysctl, Windows-ветка сознательно не трогает ОС, см.
// doc-комментарий IPv6Guard.Enable) и не персистит в config.json — безопасно для этого пакета
// без снимка/восстановления.
func TestSetIPv6Block_AfterInit(t *testing.T) {
	newBareTestEngine(t)

	if got := SetIPv6Block(true); got != "" {
		t.Errorf("SetIPv6Block(true) = %q, ожидался успех", got)
	}
	if got := SetIPv6Block(false); got != "" {
		t.Errorf("SetIPv6Block(false) = %q, ожидался успех", got)
	}
}

// K2-A (свод C трек 1 п.2, B4 #1): геттер, из которого экран Android берёт НАЧАЛЬНОЕ
// положение тумблера «IPv6 Block». Раньше положение бралось из XML-дефолта, и после
// перезапуска активити выключенная пользователем защита выглядела включённой.
//
// Вход:      SetIPv6Block(true/false) на поднятом движке.
// Выход:     IsIPv6BlockEnabled() повторяет ровно то, что применено.
// Инвариант: геттер читает состояние ядра, а не собственную копию.
func TestIsIPv6BlockEnabled_ReflectsApplied(t *testing.T) {
	newBareTestEngine(t)

	if got := SetIPv6Block(true); got != "" {
		t.Fatalf("SetIPv6Block(true) = %q, ожидался успех", got)
	}
	if !IsIPv6BlockEnabled() {
		t.Error("IsIPv6BlockEnabled() = false после SetIPv6Block(true)")
	}
	if got := SetIPv6Block(false); got != "" {
		t.Fatalf("SetIPv6Block(false) = %q, ожидался успех", got)
	}
	if IsIPv6BlockEnabled() {
		t.Error("IsIPv6BlockEnabled() = true после SetIPv6Block(false)")
	}
}

// ─── Sticky Session: политика читается, а не угадывается ─────────────────────────────────
//
// K2-A (свод C трек 1 п.2, B4 #1): у моста был только сеттер, и спиннер на Android всегда
// стартовал с первой строки («Держаться узла»), а его onItemSelected при построении списка
// тут же возвращал движок на "sticky" — выбор пользователя молча отменялся при каждом
// открытии экрана.
//
// Вход:      SetStickySession("free"/"timed"/"sticky") на поднятом движке.
// Выход:     GetStickySessionPolicy() — ровно применённая политика.
// Инвариант: неизвестная строка не ломает движок (SetStickyPolicy трактует её как "sticky",
// см. internal/engine.SetStickyPolicy) и геттер остаётся в контракте трёх значений.
func TestStickySessionPolicy_AfterInit(t *testing.T) {
	newBareTestEngine(t)

	if got := GetStickySessionPolicy(); got != "sticky" {
		t.Errorf("GetStickySessionPolicy() = %q сразу после Init, ожидался дефолт \"sticky\"", got)
	}
	for _, policy := range []string{"free", "timed", "sticky"} {
		SetStickySession(policy)
		if got := GetStickySessionPolicy(); got != policy {
			t.Errorf("GetStickySessionPolicy() = %q после SetStickySession(%q)", got, policy)
		}
	}
	SetStickySession("чепуха")
	if got := GetStickySessionPolicy(); got != "sticky" {
		t.Errorf("GetStickySessionPolicy() = %q после неизвестной политики, ожидался \"sticky\"", got)
	}
}

// ─── Тумблеры автопереключения/циклического поиска (паритет с desktop GUI) ────────────────

func TestNodeAutoSwitchAndCyclicSearch_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "config.json")
	// Тест проверяет ФАБРИЧНЫЕ дефолты после Init, а androidConfig() читает config.json ПОВЕРХ
	// DefaultConfig() (bridge.go:155-163). На реальной машине разработчика в %APPDATA%\APF\config.json
	// могут лежать включённые пользователем тумблеры (напр. cyclic_node_search=true) — тогда
	// «ожидался дефолт false» падал НЕ по вине кода, а из-за реального конфига. Нейтрализуем файл
	// пустым объектом (снимок выше вернёт оригинал в t.Cleanup): LoadInto накатывает "{}" на
	// DefaultConfig => чистые дефолты (NodeAutoSwitchEnabled=true, CyclicNodeSearch=false, node.go:936/938).
	if err := os.WriteFile(filepath.Join(config.DataDir(), "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("не удалось нейтрализовать config.json для проверки дефолтов: %v", err)
	}
	newBareTestEngine(t)

	if !IsNodeAutoSwitchEnabled() {
		t.Error("IsNodeAutoSwitchEnabled() = false сразу после Init, ожидался дефолт true")
	}
	SetNodeAutoSwitchEnabled(false)
	if IsNodeAutoSwitchEnabled() {
		t.Error("IsNodeAutoSwitchEnabled() = true после SetNodeAutoSwitchEnabled(false)")
	}
	SetNodeAutoSwitchEnabled(true)
	if !IsNodeAutoSwitchEnabled() {
		t.Error("IsNodeAutoSwitchEnabled() = false после SetNodeAutoSwitchEnabled(true)")
	}

	if IsCyclicNodeSearchEnabled() {
		t.Error("IsCyclicNodeSearchEnabled() = true сразу после Init, ожидался дефолт false")
	}
	SetCyclicNodeSearch(true)
	if !IsCyclicNodeSearchEnabled() {
		t.Error("IsCyclicNodeSearchEnabled() = false после SetCyclicNodeSearch(true)")
	}
	SetCyclicNodeSearch(false)
	if IsCyclicNodeSearchEnabled() {
		t.Error("IsCyclicNodeSearchEnabled() = true после SetCyclicNodeSearch(false)")
	}
}

// TestChainModeAndMultihop_AfterInit — Android до этой правки не имел вообще никакого пути
// включить режим цепочки/многохоповую цепочку (найдено полным QA 2026-09-22): ни UI, ни
// моста. Тот же контракт, что и у SetCyclicNodeSearch/SetNodeAutoSwitchEnabled выше.
func TestChainModeAndMultihop_AfterInit(t *testing.T) {
	snapshotAndRestoreDataFile(t, "config.json")
	if err := os.WriteFile(filepath.Join(config.DataDir(), "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("не удалось нейтрализовать config.json для проверки дефолтов: %v", err)
	}
	newBareTestEngine(t)

	if IsChainModeEnabled() {
		t.Error("IsChainModeEnabled() = true сразу после Init, ожидался дефолт false")
	}
	SetChainMode(true)
	if !IsChainModeEnabled() {
		t.Error("IsChainModeEnabled() = false после SetChainMode(true)")
	}
	SetChainMode(false)
	if IsChainModeEnabled() {
		t.Error("IsChainModeEnabled() = true после SetChainMode(false)")
	}

	if IsMultihopEnabled() {
		t.Error("IsMultihopEnabled() = true сразу после Init, ожидался дефолт false")
	}
	SetMultihopEnabled(true)
	if !IsMultihopEnabled() {
		t.Error("IsMultihopEnabled() = false после SetMultihopEnabled(true)")
	}
	SetMultihopEnabled(false)
	if IsMultihopEnabled() {
		t.Error("IsMultihopEnabled() = true после SetMultihopEnabled(false)")
	}

	if got := GetMultihopCount(); got != 2 {
		t.Errorf("GetMultihopCount() = %d сразу после Init, ожидался дефолт 2", got)
	}
	SetMultihopCount(3)
	if got := GetMultihopCount(); got != 3 {
		t.Errorf("GetMultihopCount() = %d после SetMultihopCount(3), ожидалось 3", got)
	}
	// Недопустимое значение откатывается на 2, а не сохраняется как есть.
	SetMultihopCount(7)
	if got := GetMultihopCount(); got != 2 {
		t.Errorf("GetMultihopCount() = %d после SetMultihopCount(7), ожидался откат на 2", got)
	}

	// GetToggleState — тот же трёхзначный контракт, что у остальных тумблеров экрана.
	SetChainMode(true)
	if got := GetToggleState(ToggleChainMode); got != ToggleOn {
		t.Errorf("GetToggleState(ToggleChainMode) = %q после SetChainMode(true), ожидалось %q", got, ToggleOn)
	}
	SetMultihopEnabled(true)
	if got := GetToggleState(ToggleMultihop); got != ToggleOn {
		t.Errorf("GetToggleState(ToggleMultihop) = %q после SetMultihopEnabled(true), ожидалось %q", got, ToggleOn)
	}
}

// ─── Диагностика / состояние / колбэки ─────────────────────────────────────────────────────

// GetDiagnosticsJSON/GetStateJSON/IsVerified/GetActiveNodeLatency — чисто читающие вызовы
// (никакого config.SaveConfig/saveNodes внутри), поэтому без снимка/восстановления.
func TestDiagnosticsAndStateAccessors_AfterInit(t *testing.T) {
	newBareTestEngine(t)

	var diag map[string]interface{}
	if err := json.Unmarshal([]byte(GetDiagnosticsJSON()), &diag); err != nil {
		t.Fatalf("GetDiagnosticsJSON() не парсится: %v", err)
	}
	for _, key := range []string{"blockage_type", "apf_version", "sing_box_version"} {
		if _, ok := diag[key]; !ok {
			t.Errorf("GetDiagnosticsJSON() не содержит ожидаемое поле %q: %v", key, diag)
		}
	}
	// C-5, 2026-09-08: fsm_state убран из диагностики движка — поле никто не читал,
	// а автомат не выбирает outbound, так что показывать его было нечестно.
	if _, ok := diag["fsm_state"]; ok {
		t.Errorf("GetDiagnosticsJSON() всё ещё содержит убранное поле fsm_state (C-5): %v", diag)
	}

	var state struct {
		Connected bool `json:"connected"`
	}
	if err := json.Unmarshal([]byte(GetStateJSON()), &state); err != nil {
		t.Fatalf("GetStateJSON() не парсится: %v", err)
	}
	if state.Connected {
		t.Error("GetStateJSON().connected = true на свежем движке")
	}
	if IsVerified() {
		t.Error("IsVerified() = true на свежем движке без активного узла")
	}
	if got := GetActiveNodeLatency(); got != 0 {
		t.Errorf("GetActiveNodeLatency() = %d, ожидалось 0 без активного узла", got)
	}
}

// fakeLogCB/fakeStateCB/fakeLeakCB — минимальные реализации колбэк-интерфейсов моста для
// проверки, что SetLogCallback/SetStateCallback/SetLeakCallback реально подключают eng.OnLog/
// OnStateChange/OnLeakDetected, а не просто молча принимают значение.
type fakeLogCB struct{ messages []string }

func (f *fakeLogCB) OnLog(message string) { f.messages = append(f.messages, message) }

type fakeStateCB struct{ lastJSON string }

func (f *fakeStateCB) OnStateChanged(connectedJSON string) { f.lastJSON = connectedJSON }

type fakeLeakCB struct{ leakType, details string }

func (f *fakeLeakCB) OnLeakDetected(leakType string, details string) {
	f.leakType, f.details = leakType, details
}

// Контракт SetLogCallback/SetStateCallback/SetLeakCallback: после установки движок реально
// зовёт колбэк через eng.OnLog/OnStateChange/OnLeakDetected (мост лишь оборачивает вызов —
// проверяем именно проводку, без реального события подключения/утечки).
func TestCallbacks_AfterInit_WireThroughToEngine(t *testing.T) {
	e := newBareTestEngine(t)

	log := &fakeLogCB{}
	SetLogCallback(log)
	if e.OnLog == nil {
		t.Fatal("SetLogCallback не установил eng.OnLog")
	}
	e.OnLog("тестовое сообщение")
	if len(log.messages) != 1 || log.messages[0] != "тестовое сообщение" {
		t.Errorf("OnLog не дошёл до колбэка: %v", log.messages)
	}

	state := &fakeStateCB{}
	SetStateCallback(state)
	if e.OnStateChange == nil {
		t.Fatal("SetStateCallback не установил eng.OnStateChange")
	}
	e.OnStateChange(e.GetState())
	if state.lastJSON == "" || !strings.Contains(state.lastJSON, `"connected"`) {
		t.Errorf("OnStateChange не дошёл до колбэка (или не JSON): %q", state.lastJSON)
	}

	leak := &fakeLeakCB{}
	SetLeakCallback(leak)
	if e.OnLeakDetected == nil {
		t.Fatal("SetLeakCallback не установил eng.OnLeakDetected")
	}
	e.OnLeakDetected("dns", "подробности")
	if leak.leakType != "dns" || leak.details != "подробности" {
		t.Errorf("OnLeakDetected не дошёл до колбэка: type=%q details=%q", leak.leakType, leak.details)
	}

	// nil-колбэк не должен паниковать и не должен затирать уже установленный (bridge.go:
	// `if eng == nil || cb == nil { return }`).
	SetLogCallback(nil)
	if e.OnLog == nil {
		t.Error("SetLogCallback(nil) стёр уже установленный eng.OnLog")
	}
}
