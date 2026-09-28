package androidbridge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// Тесты моста намеренно НЕ вызывают Init с настоящим каталогом: Init поднимает движок,
// а движок ходит в сеть и трогает состояние ОС. Проверяем только контрактные границы —
// то, что можно проверить, ничего не запуская.

// Контракт Init (дефекты D-A11, D-A1).
//
// Вход:      dataDir (обязателен), nativeLibDir (может быть пуст).
// Отвергает: пустой dataDir — с внятным текстом, а не паникой и не тихим успехом.
// Инвариант: отказ не оставляет инициализированного движка.
func TestInit_RejectsEmptyDataDir(t *testing.T) {
	err := Init("", "")
	if err == "" {
		t.Fatal("Init(\"\", \"\") вернул успех — пустой каталог данных недопустим")
	}
	if !strings.Contains(err, "dataDir") {
		t.Errorf("текст ошибки не называет причину: %q", err)
	}
	if getEngine() != nil {
		t.Fatal("после отказа Init остался инициализированный движок")
	}
}

// Контракт Init при повторном вызове (дефект D-A18).
//
// Вход:      Init вызван второй раз при уже поднятом движке.
// Выход:     "" — «ядро готово», потому что оно готово.
// Инвариант: повторный Init не пересоздаёт движок и не роняет текущий сеанс.
//
// Служба Android уничтожается и создаётся заново внутри живого процесса, и onCreate
// вызывает Init каждый раз. Прежний ответ "already initialized" нативный слой понимал
// как отказ и навсегда оставлял ядро «неинициализированным».
func TestInit_SecondCallReportsReady(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	stub := engine.New(androidConfig())
	globalMu.Lock()
	globalEngine = stub
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	if err := Init("D:\\APF-Stand\\phone\\nonexistent", ""); err != "" {
		t.Fatalf("повторный Init вернул %q, ожидалась пустая строка", err)
	}
	if getEngine() != stub {
		t.Fatal("повторный Init подменил уже работающий движок")
	}
}

// Контракт Disconnect (дефект D-A17).
//
// Вход:      нет.
// Тело:      ОБРАТИМАЯ остановка сеанса.
// Выход:     "" при успехе, текст ошибки при неудаче.
// Инвариант: Disconnect НЕ ИМЕЕТ ПРАВА идти терминальным путём (engine.Stop), иначе
// следующее подключение в том же сеансе приложения невозможно, и испытание циклами
// Connect/Disconnect (TG-1A) обрывается на втором круге.
func TestDisconnect_IsReversible_NotTerminal(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()

	restartCalls, stopCalls := 0, 0
	origRestart, origStop := restartEngine, stopEngine
	restartEngine = func(*engine.Engine) error { restartCalls++; return nil }
	stopEngine = func(*engine.Engine) { stopCalls++ }
	t.Cleanup(func() {
		restartEngine, stopEngine = origRestart, origStop
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	if err := Disconnect(); err != "" {
		t.Fatalf("Disconnect() = %q, ожидался успех", err)
	}
	if restartCalls != 1 {
		t.Errorf("обратимая остановка вызвана %d раз, ожидался 1", restartCalls)
	}
	if stopCalls != 0 {
		t.Fatal("Disconnect пошёл ТЕРМИНАЛЬНЫМ путём (engine.Stop) — " +
			"после него повторное подключение невозможно")
	}

	// Отказ обратимой остановки обязан быть виден вызывающей стороне, а не проглочен.
	restartEngine = func(*engine.Engine) error { return errors.New("сеть не сброшена") }
	if err := Disconnect(); !strings.Contains(err, "сеть не сброшена") {
		t.Errorf("Disconnect() скрыл причину отказа: %q", err)
	}
}

// Контракт androidConfig.
//
// Каждое отличие от DefaultConfig существует по причине; молчаливая его потеря ломает
// стенд. Главное — ConnectionMode: он управляет флагом tunMode в сборщике конфигурации
// sing-box, а TUN на Android выдаёт только VpnService (этап Э-4).
func TestAndroidConfig_NeverRequestsTun(t *testing.T) {
	cfg := androidConfig()

	if cfg.ConnectionMode != models.ModeProxy {
		t.Fatalf("ConnectionMode = %q, на Android допустим только %q: "+
			"иначе в конфигурацию sing-box попадёт tun-inbound, который процессу без root не создать",
			cfg.ConnectionMode, models.ModeProxy)
	}
	if cfg.AutoConnect {
		t.Error("AutoConnect = true: телефон уходил бы в туннель до того, как за ним наблюдают")
	}
	if cfg.WebUIPort != 0 {
		t.Errorf("WebUIPort = %d, на телефоне Web UI не нужен", cfg.WebUIPort)
	}
	if cfg.ListenPort != 10808 {
		t.Errorf("ListenPort = %d, стендовые инструменты пробрасывают 10808", cfg.ListenPort)
	}
	// Дефект D-A24: с EnableKillSwitch=true подключение на Android невозможно ВООБЩЕ.
	// Движок при fail-closed обязан применить защиту, androidKS честно отвечает, что не
	// защищает ничего (системная защита выключена, включить её из приложения нельзя), и
	// подключение откатывается на стадии killswitch — на каждой попытке, включая fallback.
	if cfg.EnableKillSwitch {
		t.Fatal("EnableKillSwitch = true: на Android это гарантированный откат подключения " +
			"на стадии killswitch, а защиты всё равно не появится — включить её может только ОС")
	}
}

// Контракт SetKillSwitch (дефект D-A24).
//
// Вход:      требование защиты.
// Тело:      включение проходит, только если система её уже обеспечивает.
// Выход:     "" — принято; иначе причина отказа.
// Инвариант: конфигурация никогда не оказывается в состоянии «защита требуется, применить
//
//	невозможно» — именно оно делало подключение невозможным.
func TestSetKillSwitch_RefusesWhenSystemCannotProtect(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()

	old := killswitch.AndroidSystemProtection()
	t.Cleanup(func() {
		killswitch.SetAndroidSystemProtection(old)
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	// Системной защиты нет — требовать её нельзя.
	killswitch.SetAndroidSystemProtection(false)
	err := SetKillSwitch(true)
	if err == "" {
		t.Fatal("SetKillSwitch(true) принят без системной защиты — после этого движок " +
			"откатывал бы каждое подключение на стадии killswitch")
	}
	if !strings.Contains(err, "Always-on VPN") {
		t.Errorf("отказ не объясняет, что делать пользователю: %q", err)
	}
	if getEngine().GetConfig().EnableKillSwitch {
		t.Fatal("отказ не помешал записать требование в конфигурацию")
	}

	// Выключение доступно всегда: снять требование должно быть можно в любой момент.
	if err := SetKillSwitch(false); err != "" {
		t.Errorf("SetKillSwitch(false) = %q, выключение обязано проходить всегда", err)
	}

	// Система защиту обеспечивает — требование осмысленно и принимается.
	killswitch.SetAndroidSystemProtection(true)
	if err := SetKillSwitch(true); err != "" {
		t.Fatalf("SetKillSwitch(true) отвергнут при активной системной защите: %q", err)
	}
	if !getEngine().GetConfig().EnableKillSwitch {
		t.Fatal("требование принято, но в конфигурацию не записано")
	}
}

// Версия обязана браться из единого источника: отчёт об испытании должен соотноситься
// со сборкой. Раньше здесь был хардкод "1.0.7" при продукте 1.1.0.
func TestVersion_ComesFromSingleSource(t *testing.T) {
	if got := Version(); got != version.Version {
		t.Fatalf("Version() = %q, а internal/version.Version = %q — источники разошлись",
			got, version.Version)
	}
	if strings.HasPrefix(Version(), "v") {
		t.Errorf("Version() = %q — префикс \"v\" здесь не нужен (для UI есть version.Label)", Version())
	}
}

// Контракт SetSystemKillSwitch (дефект D-A5).
//
// Вход:      фактическое состояние системной защиты Android.
// Тело:      проброс в ядро killswitch.
// Выход:     IsSystemKillSwitchActive() отражает переданное значение.
// Fail-safe: пока нативный слой не вызвал метод, ядро считает, что защиты нет.
func TestSetSystemKillSwitch_ReachesKillSwitchCore(t *testing.T) {
	old := killswitch.AndroidSystemProtection()
	t.Cleanup(func() { killswitch.SetAndroidSystemProtection(old) })

	SetSystemKillSwitch(true)
	if !IsSystemKillSwitchActive() {
		t.Fatal("IsSystemKillSwitchActive() = false после SetSystemKillSwitch(true)")
	}
	if !killswitch.AndroidSystemProtection() {
		t.Fatal("состояние не дошло до пакета killswitch")
	}

	SetSystemKillSwitch(false)
	if IsSystemKillSwitchActive() || killswitch.AndroidSystemProtection() {
		t.Fatal("состояние не сбросилось после SetSystemKillSwitch(false)")
	}
}

// Методы, вызываемые из Kotlin до инициализации, обязаны возвращать безопасные значения,
// а не падать: на Android паника в Go убивает процесс приложения целиком.
func TestAccessors_SafeBeforeInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже инициализирован другим тестом — проверка неинформативна")
	}
	if got := Connect(); got != "not initialized" {
		t.Errorf("Connect() = %q, ожидалось \"not initialized\"", got)
	}
	if IsConnected() {
		t.Error("IsConnected() = true до инициализации")
	}
	if got := GetActiveNodeName(); got != "" {
		t.Errorf("GetActiveNodeName() = %q, ожидалась пустая строка", got)
	}
	if got := GetNodesJSON(); got != "[]" {
		t.Errorf("GetNodesJSON() = %q, ожидалось \"[]\"", got)
	}
	// §5 ТЗ: список «Мои серверы» — те же гарантии до инициализации.
	if got := ConnectByID("some-id"); got != "not initialized" {
		t.Errorf("ConnectByID() = %q, ожидалось \"not initialized\"", got)
	}
	if got := PinNode("some-id"); got != "not initialized" {
		t.Errorf("PinNode() = %q, ожидалось \"not initialized\"", got)
	}
	if got := UnpinNode(); got != "not initialized" {
		t.Errorf("UnpinNode() = %q, ожидалось \"not initialized\"", got)
	}
	if got := GetStatsJSON(); got != "{}" {
		t.Errorf("GetStatsJSON() = %q, ожидалось \"{}\"", got)
	}
	if got := GetSOCKSPort(); got != 10808 {
		t.Errorf("GetSOCKSPort() = %d, ожидался порт по умолчанию 10808", got)
	}
	// Отключать нечего — это не ошибка, а нормальное состояние.
	if got := Disconnect(); got != "" {
		t.Errorf("Disconnect() до инициализации = %q, ожидалась пустая строка", got)
	}
	// Не должно паниковать.
	ForceSwitch()
	if got := SetKillSwitch(true); got != "not initialized" {
		t.Errorf("SetKillSwitch(true) до инициализации = %q, ожидалось \"not initialized\"", got)
	}
	SetStickySession("sticky")

	// Э-UI-2: те же гарантии для каталог-обёрток.
	if got := GetCatalogStatusJSON(); got != "[]" {
		t.Errorf("GetCatalogStatusJSON() = %q, ожидалось \"[]\"", got)
	}
	if got := RefreshCatalog(); got != "not initialized" {
		t.Errorf("RefreshCatalog() = %q, ожидалось \"not initialized\"", got)
	}
	if got := SetCatalogProviderEnabled("free-1", true); got != "not initialized" {
		t.Errorf("SetCatalogProviderEnabled() = %q, ожидалось \"not initialized\"", got)
	}

	// Э-UI-3: те же гарантии для AdBlock-обёрток.
	if got := GetAdBlockStatusJSON(); got != "{}" {
		t.Errorf("GetAdBlockStatusJSON() = %q, ожидалось \"{}\"", got)
	}
	if got := SetAdBlockProfile("light"); got != "not initialized" {
		t.Errorf("SetAdBlockProfile() = %q, ожидалось \"not initialized\"", got)
	}
	AdBlockToggleAllowlist("example.com", true) // не должно паниковать

	// Э-UI-4: те же гарантии для приватности (DNS-leak/WebRTC).
	if got := GetLeakGuardStatusJSON(); got != "{}" {
		t.Errorf("GetLeakGuardStatusJSON() = %q, ожидалось \"{}\"", got)
	}
	if got := RunDNSLeakTestJSON(); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("RunDNSLeakTestJSON() = %q, ожидалась ошибка not initialized", got)
	}
	if got := SetWebRTCBlock(true); got != "not initialized" {
		t.Errorf("SetWebRTCBlock() = %q, ожидалось \"not initialized\"", got)
	}

	// Э-UI-5: те же гарантии для анти-DPI-обёрток.
	if got := GetDPIStatusJSON(); got != "{}" {
		t.Errorf("GetDPIStatusJSON() = %q, ожидалось \"{}\"", got)
	}
	if got := RunCanaryTestJSON(); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("RunCanaryTestJSON() = %q, ожидалась ошибка not initialized", got)
	}
	if got := AutoSelectShadowTLSSNIJSON(); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("AutoSelectShadowTLSSNIJSON() = %q, ожидалась ошибка not initialized", got)
	}
	SetTrafficPadding(true, false)               // не должно паниковать
	SetShadowTLSConfig(true, "p", "s", "h", "a") // не должно паниковать
	SetCDNConfig("w", "h", 443)                  // не должно паниковать

	// Э-UI-6: те же гарантии для анти-блокировки.
	if got := GetAntiBlockStatusJSON(); got != "{}" {
		t.Errorf("GetAntiBlockStatusJSON() = %q, ожидалось \"{}\"", got)
	}
	if got := CheckCurrentIPJSON(); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("CheckCurrentIPJSON() = %q, ожидалась ошибка not initialized", got)
	}
	if got := GetBypassRulesJSON(); got != "[]" {
		t.Errorf("GetBypassRulesJSON() = %q, ожидалось \"[]\"", got)
	}
	if got := SetBypassRule("netflix", true); got != "not initialized" {
		t.Errorf("SetBypassRule() = %q, ожидалось \"not initialized\"", got)
	}
	if got := AddBypassDomain("example.com", "Example", false, false); got != "not initialized" {
		t.Errorf("AddBypassDomain() = %q, ожидалось \"not initialized\"", got)
	}
	if got := UpdateBypassDomain("x", "example.com", "Example", false, false); got != "not initialized" {
		t.Errorf("UpdateBypassDomain() = %q, ожидалось \"not initialized\"", got)
	}
	if got := RemoveBypassDomain("x"); got != "not initialized" {
		t.Errorf("RemoveBypassDomain() = %q, ожидалось \"not initialized\"", got)
	}
	SetAntiBlockConfig(true, false, true, "") // не должно паниковать

	// Э-UI-7: те же гарантии для аварийной очистки/шифрования.
	SetMasterPassword("pw") // не должно паниковать
	SetMasterPassword("")   // не должно паниковать
	if got := EmergencyWipeJSON(false, "WIPE"); !strings.Contains(got, `"error":"not initialized"`) {
		t.Errorf("EmergencyWipeJSON() до инициализации = %q, ожидалась ошибка not initialized", got)
	}

	Shutdown()
}

// Контракт GetCatalogStatusJSON/SetCatalogProviderEnabled после инициализации
// (Э-UI-2, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.2).
//
// Вход:      движок поднят напрямую через engine.New (тот же приём, что
// TestDisconnect_IsReversible_NotTerminal/TestInit_SecondCallReportsReady) — БЕЗ .Start()
// и без настоящего Init: engine.New уже наполняет catalogRegistry дефолтными
// провайдерами (internal/catalog.NewRegistry — 4 бесплатных + Tor + Manual), сеть не
// трогает. RefreshCatalog() намеренно НЕ вызывается здесь: он реально идёт в сеть
// (Fetch на каждого провайдера) — та же причина, по которой этот файл в целом не
// вызывает настоящий Init (см. комментарий в начале файла).
// Тело:      статус непустой; включение/выключение известного провайдера ("v2ray-aggregator",
// internal/catalog/providers.go DefaultFreeProviders) проходит; неизвестный ID — отказ.
// Инвариант: SetCatalogProviderEnabled никогда не подменяет и не роняет движок.
func TestCatalogStatus_AfterInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	status := GetCatalogStatusJSON()
	if status == "[]" || status == "" {
		t.Fatalf("GetCatalogStatusJSON() = %q, ожидался непустой список (дефолтные провайдеры)", status)
	}
	if !strings.Contains(status, "v2ray-aggregator") {
		t.Errorf("GetCatalogStatusJSON() не содержит известный провайдер v2ray-aggregator: %s", status)
	}

	if got := SetCatalogProviderEnabled("v2ray-aggregator", false); got != "" {
		t.Errorf("SetCatalogProviderEnabled(v2ray-aggregator, false) = %q, ожидался успех", got)
	}
	if got := SetCatalogProviderEnabled("v2ray-aggregator", true); got != "" {
		t.Errorf("SetCatalogProviderEnabled(v2ray-aggregator, true) = %q, ожидался успех", got)
	}
	if got := SetCatalogProviderEnabled("no-such-provider", true); got == "" {
		t.Error("SetCatalogProviderEnabled с несуществующим ID вернул успех")
	}
}

// Контракт GetNodesJSON(pinned)/PinNode/UnpinNode/ConnectByID (docs/
// TZ_APF_QA_AND_BACKLOG_v1.0.md §5 — список «Мои серверы»): бэкенд (engine.PinNode/
// UnpinNode/ConnectByID/PinnedNodeID) существовал и раньше, но ни разу не вызывался ни
// из Android, ни из Windows GUI — только из headless HTTP API. Эти три обёртки в
// bridge.go были добавлены именно для Android-экрана «Мои серверы».
func TestNodePin_AfterInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	// БАГ (найден при составлении сценариев верификации, 2026-09-05): этот тест зовёт AddNode
	// (пишет nodes_cache.json через engine.saveNodes) и PinNode/UnpinNode (пишут config.json
	// через persistPinAndFavorites → e.saveConfig — ОН НЕ nil, engine.New всегда подставляет
	// config.SaveConfig, см. internal/engine/engine.go) — но, в отличие от
	// TestAdBlockStatus_AfterInit/TestAntiBlockStatus_AfterInit в этом же файле, здесь не было
	// снимка/восстановления. Проверено на этой машине: РЕАЛЬНЫЙ config.json в
	// %APPDATA%\APF\config.json уже содержал "pinned_node":{"id":"...","name":"TestSS"} —
	// тестовый узел просочился в файл боевого стенда и остаётся там перманентно при каждом
	// прогоне `go test`. Тот же снимок/восстановление, что уже применяется ниже в файле.
	snapshotAndRestoreDataFile(t, "config.json")
	snapshotAndRestoreDataFile(t, "nodes_cache.json")

	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	if got := AddNode("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.1:8388#TestSS"); got != "" {
		t.Fatalf("AddNode() = %q, ожидался успех", got)
	}

	var nodes []struct {
		ID     string `json:"id"`
		Pinned bool   `json:"pinned"`
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil {
		t.Fatalf("GetNodesJSON() не распарсился: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("GetNodesJSON() пуст после AddNode")
	}
	id := nodes[0].ID
	if nodes[0].Pinned {
		t.Error("узел закреплён сразу после AddNode — ожидалось pinned=false")
	}

	if got := PinNode(id); got != "" {
		t.Errorf("PinNode(%q) = %q, ожидался успех", id, got)
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil {
		t.Fatalf("GetNodesJSON() после PinNode не распарсился: %v", err)
	}
	if !nodes[0].Pinned {
		t.Error("GetNodesJSON() не отражает pinned=true после PinNode")
	}

	if got := UnpinNode(); got != "" {
		t.Errorf("UnpinNode() = %q, ожидался успех", got)
	}
	if err := json.Unmarshal([]byte(GetNodesJSON()), &nodes); err != nil {
		t.Fatalf("GetNodesJSON() после UnpinNode не распарсился: %v", err)
	}
	if nodes[0].Pinned {
		t.Error("GetNodesJSON() всё ещё отражает pinned=true после UnpinNode")
	}

	// ConnectByID сам закрепляет узел (см. engine.ConnectByID) — не проверяем реальное
	// подключение (hostguard блокирует запуск sing-box под `go test`), только что вызов
	// проходит без ошибки и закрепление применяется.
	if got := ConnectByID(id); got != "" {
		t.Errorf("ConnectByID(%q) = %q, ожидался успех", id, got)
	}
	if got := ConnectByID("no-such-id"); got == "" {
		t.Error("ConnectByID с несуществующим ID вернул успех")
	}
	if got := PinNode(""); got == "" {
		t.Error("PinNode(\"\") вернул успех, ожидалась ошибка")
	}
}

// Контракт GetAdBlockStatusJSON/SetAdBlockProfile/AdBlockToggleAllowlist после
// инициализации (Э-UI-3, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.3).
//
// Вход:      движок поднят напрямую через engine.New, без .Start() — та же причина,
// что у TestCatalogStatus_AfterInit: profile="disabled" (единственный, что здесь
// используется) не идёт в сеть (adblock.Blocker.SetProfile — короткий путь для
// ProfileDisabled, см. internal/adblock/blocker.go), "light"/"standard"/"strict"
// реально скачивают блок-листы и намеренно НЕ вызываются в этом тесте.
// Тело:      валидный профиль применяется; невалидный — отказ с текстом причины;
// allowlist не паникует до и после инициализации.
// Инвариант: SetAdBlockProfile никогда не паникует и не роняет движок.
func TestAdBlockStatus_AfterInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}

	// SetAdBlockProfile НА УСПЕШНОМ пути зовёт config.SaveConfig(e.cfg) — реальный
	// файл на диске (internal/engine/engine.go: SetAdBlockProfile). В отличие от
	// APF_DATA_DIR на Android, ветка Windows в config.DataDir() ничем не
	// перенаправляется (internal/config/config.go: DataDir — Windows читает только
	// %APPDATA%) — вызов ниже писал бы поверх НАСТОЯЩЕГО config.json этой машины.
	// Снимок/восстановление ДО и ПОСЛЕ — тест не имеет права оставить хост в другом
	// состоянии, чем застал (тот же принцип, что hostguard проверяет для всего пакета).
	cfgPath := filepath.Join(config.DataDir(), "config.json")
	original, readErr := os.ReadFile(cfgPath)
	existed := readErr == nil
	t.Cleanup(func() {
		if existed {
			if err := os.WriteFile(cfgPath, original, 0o644); err != nil {
				t.Logf("не удалось восстановить %s: %v", cfgPath, err)
			}
		} else {
			os.Remove(cfgPath)
		}
	})

	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	status := GetAdBlockStatusJSON()
	if !strings.Contains(status, `"profile":"disabled"`) {
		t.Errorf("GetAdBlockStatusJSON() до смены профиля = %q, ожидался profile=disabled", status)
	}

	if got := SetAdBlockProfile("disabled"); got != "" {
		t.Errorf("SetAdBlockProfile(disabled) = %q, ожидался успех", got)
	}
	if got := SetAdBlockProfile("not-a-real-profile"); got == "" {
		t.Error("SetAdBlockProfile с неизвестным профилем вернул успех")
	}

	AdBlockToggleAllowlist("example.com", true)
	AdBlockToggleAllowlist("example.com", false)
	status = GetAdBlockStatusJSON()
	if !strings.Contains(status, `"allowlist_size":0`) {
		t.Errorf("GetAdBlockStatusJSON() после add+remove того же домена = %q, ожидался allowlist_size=0", status)
	}
}

// Контракт GetLeakGuardStatusJSON/SetWebRTCBlock после инициализации (Э-UI-4,
// docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.4).
//
// RunDNSLeakTestJSON() НЕ вызывается здесь на успешном пути: internal/leakguard.
// DNSLeakTester.Test реально резолвит DNS (сравнивает системный и туннельный
// путь) — та же причина, по которой RefreshCatalog()/SetAdBlockProfile("light")
// тоже не тестируются успешным путём в этом файле. webrtcGuard.Enable/Disable
// (internal/leakguard/webrtc.go) — чистое состояние в памяти, без сети и без
// config.SaveConfig, безопасно для позитивного теста.
func TestLeakGuardStatus_AfterInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	status := GetLeakGuardStatusJSON()
	if !strings.Contains(status, `"webrtc_guard_enabled":false`) {
		t.Errorf("GetLeakGuardStatusJSON() = %q, ожидался webrtc_guard_enabled=false по умолчанию", status)
	}

	if got := SetWebRTCBlock(true); got != "" {
		t.Errorf("SetWebRTCBlock(true) = %q, ожидался успех", got)
	}
	status = GetLeakGuardStatusJSON()
	if !strings.Contains(status, `"webrtc_guard_enabled":true`) {
		t.Errorf("GetLeakGuardStatusJSON() после SetWebRTCBlock(true) = %q, ожидался webrtc_guard_enabled=true", status)
	}

	if got := SetWebRTCBlock(false); got != "" {
		t.Errorf("SetWebRTCBlock(false) = %q, ожидался успех", got)
	}
}

// Контракт GetDPIStatusJSON/SetTrafficPadding/SetShadowTLSConfig/SetCDNConfig
// после инициализации (Э-UI-5, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.5).
//
// RunCanaryTestJSON()/AutoSelectShadowTLSSNIJSON() НЕ вызываются здесь на
// успешном пути — оба реально идут в сеть (internal/dpi: canary-проверка,
// подбор SNI), та же причина, что и у остальных сетевых тестов в этом файле.
// SetTrafficPadding/SetCDNConfig — чистое состояние в памяти (internal/engine/engine.go),
// без сети и без config.SaveConfig. SetShadowTLSConfig — исключение (P1-1, аудит
// 2026-09-01): персистит в config.SaveConfig — БАГ (найден при составлении сценариев
// верификации, 2026-09-05): комментарий утверждал, что "тест это уже переживает для AdBlock",
// но AdBlockToggleAllowlist НЕ зовёт config.SaveConfig вообще (только SetAdBlockProfile, а
// TestAdBlockStatus_AfterInit защищает именно его снимком/восстановлением) — аналогия была
// ложной, и этот тест реально писал в РЕАЛЬНЫЙ config.json БЕЗ восстановления. Проверено:
// %APPDATA%\APF\config.json на этой машине содержал "shadowtls_password":"pass" и
// "shadowtls_server_addr":"5.6.7.8:8443" из этого теста — просочилось в боевой стенд и
// оставалось там после каждого прогона `go test`. Тот же снимок/восстановление, что и в
// TestAdBlockStatus_AfterInit/TestAntiBlockStatus_AfterInit.
func TestDPIStatus_AfterInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	snapshotAndRestoreDataFile(t, "config.json")

	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	status := GetDPIStatusJSON()
	if !strings.Contains(status, `"padding_enabled":false`) {
		t.Errorf("GetDPIStatusJSON() = %q, ожидался padding_enabled=false по умолчанию", status)
	}

	// K2-A (свод C трек 1 п.9), после правки движка лотом K2-E. БЫЛО: тест требовал, чтобы
	// после SetTrafficPadding(true) статус отдавал padding_enabled=true — то есть ЗАКРЕПЛЯЛ
	// ложь (один из «7 тестов, закрепляющих дефекты» из аудита 2026-09-01). Методы данных
	// padding'а (dpi.TrafficPadder.WrapConn/.JitteredDial, dpi.NewPaddedConn) не вызываются
	// ни одной строкой продакшн-кода: трафик через них не идёт, размеры пакетов не меняются,
	// и «включено» означало лишь состояние внутреннего флага (обоснование построчно у ключа
	// "padding_enabled" в engine.GetDPIStatus).
	//
	// СТАЛО: контракт моста проверяет обратное — поднятие флага НЕ должно превращаться в
	// обещание защиты. Экран Android этот тумблер больше не показывает вовсе (K2-A,
	// MainActivity.showDpiDialog), а сама запись значения в конфигурацию сохранена, поэтому
	// вызов остаётся здесь: он обязан быть безопасным и не менять ответ статуса.
	SetTrafficPadding(true, true)
	status = GetDPIStatusJSON()
	if !strings.Contains(status, `"padding_enabled":false`) {
		t.Errorf("GetDPIStatusJSON() после SetTrafficPadding(true) = %q — статус обещает маскировку, которой нет; ожидался padding_enabled=false", status)
	}
	SetTrafficPadding(false, false)

	// Не должны паниковать — проверяем только это, точная форма cdn_status/
	// shadowtls_status здесь не контракт (внутренние структуры internal/dpi).
	SetShadowTLSConfig(true, "pass", "example.com", "1.2.3.4", "5.6.7.8:8443")
	SetCDNConfig("worker.example.workers.dev", "1.2.3.4", 443)
	SetCDNConfig("", "", 0) // выключение — тоже не должно паниковать
}

// Контракт анти-блокировки после инициализации (Э-UI-6,
// docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.6).
//
// SetAntiBlockConfig БЕЗУСЛОВНО зовёт config.SaveConfig (internal/engine/
// engine.go) — та же ловушка, что уже нашлась и была исправлена для
// SetAdBlockProfile (см. TestAdBlockStatus_AfterInit): снимок/восстановление
// config.json вокруг вызова, тот же приём. bypass_list.json (internal/bypass:
// saveUserRules) — ВТОРОЙ файл с идентичным риском, но SetBypassRule/
// AddBypassDomain/RemoveBypassDomain здесь вызываются только с заведомо
// НЕсуществующими id/пустым доменом — эти пути возвращают false ДО вызова
// saveUserRules (проверено чтением internal/bypass/rules.go), поэтому файл не
// трогается и отдельный снимок для него не нужен. CheckCurrentIPJSON тоже не
// идёт в сеть здесь: eng.CheckCurrentIP проверяет activeNode==nil (его нет на
// свежем движке) и возвращает ошибку РАНЬШE любого сетевого вызова.
func TestAntiBlockStatus_AfterInit(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}

	cfgPath := filepath.Join(config.DataDir(), "config.json")
	original, readErr := os.ReadFile(cfgPath)
	existed := readErr == nil
	t.Cleanup(func() {
		if existed {
			if err := os.WriteFile(cfgPath, original, 0o644); err != nil {
				t.Logf("не удалось восстановить %s: %v", cfgPath, err)
			}
		} else {
			os.Remove(cfgPath)
		}
	})

	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	status := GetAntiBlockStatusJSON()
	if !strings.Contains(status, `"enabled":false`) {
		t.Errorf("GetAntiBlockStatusJSON() = %q, ожидался enabled=false по умолчанию", status)
	}

	SetAntiBlockConfig(true, true, false, "")
	status = GetAntiBlockStatusJSON()
	if !strings.Contains(status, `"enabled":true`) || !strings.Contains(status, `"residential_only":true`) {
		t.Errorf("GetAntiBlockStatusJSON() после SetAntiBlockConfig = %q, ожидался enabled=true, residential_only=true", status)
	}
	SetAntiBlockConfig(false, false, false, "")

	if got := CheckCurrentIPJSON(); !strings.Contains(got, `"error":"not connected"`) {
		t.Errorf("CheckCurrentIPJSON() без подключения = %q, ожидалась ошибка not connected", got)
	}

	rules := GetBypassRulesJSON()
	if rules == "" {
		t.Error("GetBypassRulesJSON() вернул пустую строку вместо JSON")
	}

	if got := SetBypassRule("no-such-rule", true); got == "" {
		t.Error("SetBypassRule с несуществующим ID вернул успех")
	}
	if got := AddBypassDomain("", "Empty", false, false); got == "" {
		t.Error("AddBypassDomain с пустым доменом вернул успех")
	}
	if got := RemoveBypassDomain("no-such-rule"); got == "" {
		t.Error("RemoveBypassDomain с несуществующим ID вернул успех")
	}
}

// Контракт SetMasterPassword/EmergencyWipeJSON после инициализации (Э-UI-7,
// docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.7).
//
// EmergencyWipeJSON с confirm="WIPE" НИКОГДА не вызывается здесь с реальным
// движком: eng.EmergencyWipe удаляет содержимое РЕАЛЬНОГО config.DataDir() этой
// машины (та же причина, по которой config.DataDir() не переопределяется на
// Windows-ветке — см. TestAdBlockStatus_AfterInit) и необратимо отменяет
// контекст движка. Проверяется только защитный контракт: НЕверный confirm не
// доходит до eng.EmergencyWipe вообще. SetMasterPassword — чистое состояние в
// памяти (eng.cryptoStore), без файлового ввода-вывода, безопасно для
// позитивного пути.
func TestEmergencyWipe_RequiresExactConfirmString(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена состояния небезопасна")
	}
	globalMu.Lock()
	globalEngine = engine.New(androidConfig())
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalEngine = nil
		globalMu.Unlock()
	})

	for _, bad := range []string{"", "wipe", "Wipe", "WIPE ", "confirm"} {
		if got := EmergencyWipeJSON(false, bad); !strings.Contains(got, "confirmation required") {
			t.Errorf("EmergencyWipeJSON(confirm=%q) = %q, ожидался отказ confirmation required", bad, got)
		}
	}

	// Позитивный путь — только SetMasterPassword (чистая память, без файлов).
	SetMasterPassword("correct horse battery staple")
	SetMasterPassword("") // выключение шифрования тоже не должно паниковать
}
