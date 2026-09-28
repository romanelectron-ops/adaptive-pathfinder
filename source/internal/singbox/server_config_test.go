package singbox

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func testIdentity(t *testing.T) ServerIdentity {
	t.Helper()
	id, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("GenerateServerIdentity: %v", err)
	}
	return id
}

// BuildServerConfig — контракт: один VLESS+Reality inbound на заданном порту, с identity
// внутри, без который сервер принял бы кого угодно или не принял бы никого.
func TestBuildServerConfig_Structure(t *testing.T) {
	id := testIdentity(t)
	doc := BuildServerConfig(id, 8443, "www.microsoft.com")

	if len(doc.Inbounds) != 1 {
		t.Fatalf("len(Inbounds) = %d, ожидался 1", len(doc.Inbounds))
	}
	in := doc.Inbounds[0]
	if in.Type != "vless" {
		t.Errorf("Type = %q, ожидался vless", in.Type)
	}
	if in.ListenPort != 8443 {
		t.Errorf("ListenPort = %d, ожидался 8443", in.ListenPort)
	}
	// [CRITICAL] Регресс-страж: listenPort здесь — ВСЕГДА внутренний эфемерный порт за
	// AdmissionProxy (Фаза C/D/E, docs/TZ_APF_RELAY_v1.0.md §10.2), не публичный. "::" вместо
	// "127.0.0.1" открывал бы прямой обход admission-control лимита мимо AdmissionProxy —
	// живой баг, найденный 2026-08-29 (см. комментарий у BuildServerConfig).
	if in.Listen != "127.0.0.1" {
		t.Errorf("Listen = %q, ожидался 127.0.0.1 (внутренний порт не должен быть достижим снаружи, в обход AdmissionProxy)", in.Listen)
	}
	if len(in.Users) != 1 || in.Users[0].UUID != id.UUID {
		t.Fatalf("Users = %+v, ожидался один пользователь с UUID %q", in.Users, id.UUID)
	}
	if in.TLS == nil || in.TLS.Reality == nil {
		t.Fatal("TLS.Reality = nil — Reality обязателен для основного протокола (ТЗ §2)")
	}
	if in.TLS.Reality.PrivateKey != id.PrivateKey {
		t.Errorf("Reality.PrivateKey = %q, ожидался %q", in.TLS.Reality.PrivateKey, id.PrivateKey)
	}
	if len(in.TLS.Reality.ShortID) != 1 || in.TLS.Reality.ShortID[0] != id.ShortID {
		t.Errorf("Reality.ShortID = %v, ожидался [%q]", in.TLS.Reality.ShortID, id.ShortID)
	}
	if in.TLS.Reality.Handshake.Server != "www.microsoft.com" || in.TLS.Reality.Handshake.ServerPort != 443 {
		t.Errorf("Handshake = %+v, ожидался www.microsoft.com:443", in.TLS.Reality.Handshake)
	}

	// Приватный ключ никогда не покидает сервер (ТЗ §2) — outbound/route этого не касаются,
	// но явная проверка на direct-only outbound фиксирует, что «Выход» не проксирует себя
	// куда-то ещё по умолчанию.
	if len(doc.Outbounds) != 1 || doc.Outbounds[0].Type != "direct" {
		t.Errorf("Outbounds = %+v, ожидался ровно один direct", doc.Outbounds)
	}
	if doc.Route.Final != "direct" {
		t.Errorf("Route.Final = %q, ожидался direct", doc.Route.Final)
	}
	if doc.Route.DefaultDomainResolver == nil {
		t.Error("Route.DefaultDomainResolver = nil — sing-box 1.12+ отказывает целиком без него (D-A27)")
	}
}

// §5 (docs/PLAN_2026-08-28_stubs_and_realfunc.md): ServerDoc обязан объявлять clash_api,
// иначе GetServerRoleStatus/QueryConnectionsCount опрашивают порт, на котором sing-box
// никогда ничего не откроет — ровно та же тихая деградация, что уже была найдена (и
// оставалась незамеченной) у клиентского TrafficMonitor.
func TestBuildServerConfig_ClashAPI_Enabled(t *testing.T) {
	doc := BuildServerConfig(testIdentity(t), 8443, "www.microsoft.com")
	if doc.Experimental == nil || doc.Experimental.ClashAPI == nil {
		t.Fatal("Experimental.ClashAPI = nil — §5 видимость подключений не заработает")
	}
	want := "127.0.0.1:8444" // ServerClashAPIPort(8443)
	if doc.Experimental.ClashAPI.ExternalController != want {
		t.Errorf("ExternalController = %q, ожидался %q", doc.Experimental.ClashAPI.ExternalController, want)
	}
}

// [найдено 2026-08-29, живой тест Redmi+ПК] ServerDoc обязан задавать СВОЙ cache_file, с
// путём, отличным от клиентского (config_builder.go, Builder.baseConfig — "cache.db").
// Оба используют libbox.CommandServer и оба безусловно требуют cache-file (needCacheFile,
// см. комментарий у Builder.baseConfig); без явного (и РАЗНОГО) пути одновременная работа
// роли «Выход» и роли «Вход» на одном устройстве (ТЗ §1: обе роли должны уметь работать
// одновременно) воспроизводимо валила вторую роль на старте: "initialize cache-file:
// timeout" — оба живых прогона на Redmi (02:44 и 02:45) упали ровно на этом.
func TestBuildServerConfig_HasOwnCacheFile(t *testing.T) {
	doc := BuildServerConfig(testIdentity(t), 8443, "www.microsoft.com")
	if doc.Experimental == nil || doc.Experimental.CacheFile == nil {
		t.Fatal("Experimental.CacheFile = nil — коллизия с клиентским sing-box при одновременной работе обеих ролей")
	}
	if !doc.Experimental.CacheFile.Enabled {
		t.Error("CacheFile.Enabled = false, ожидался true")
	}
	if doc.Experimental.CacheFile.Path == "" {
		t.Fatal("CacheFile.Path пуст")
	}
	if filepath.Base(doc.Experimental.CacheFile.Path) == "cache.db" {
		t.Errorf("CacheFile.Path = %q — совпадает с именем клиентского файла (config_builder.go), ожидалось отдельное имя", doc.Experimental.CacheFile.Path)
	}
}

// ServerClashAPIPort не должен коллидировать с самим listenPort и обязан оставаться в
// валидном диапазоне даже у верхней границы (ошибка в этой формуле молча ломает §5 на
// узлах, поднятых на порту 65535).
func TestServerClashAPIPort_Bounds(t *testing.T) {
	if p := ServerClashAPIPort(8443); p != 8444 {
		t.Errorf("ServerClashAPIPort(8443) = %d, ожидался 8444", p)
	}
	if p := ServerClashAPIPort(65535); p > 65535 || p < 1 {
		t.Errorf("ServerClashAPIPort(65535) = %d вне диапазона 1..65535", p)
	}
}

// Регрессия живого прогона Э-Выход-2 (2026-08-18): Type:"local" разбирается на localhost
// DNS ([::1]:53), которого на Android нет ("read: connection refused" на каждом запросе,
// включая обязательный дозвон Reality до realityDest) — обязан быть реальный резолвер.
func TestBuildServerConfig_DNSServer_IsRealResolver_NotLocal(t *testing.T) {
	doc := BuildServerConfig(testIdentity(t), 8443, "www.microsoft.com")
	if len(doc.DNS.Servers) != 1 {
		t.Fatalf("len(DNS.Servers) = %d, ожидался 1", len(doc.DNS.Servers))
	}
	srv := doc.DNS.Servers[0]
	if srv.Type == "local" {
		t.Error(`DNS.Servers[0].Type = "local" — на Android это неразрешимый [::1]:53, ` +
			"а не системный резолвер")
	}
	if srv.Server == "" {
		t.Error("DNS.Servers[0].Server пуст — резолвер обязан указывать на реальный адрес")
	}
}

// ToServerJSON — контракт: валидный JSON, приватный ключ не потерян при сериализации
// (omitempty на некоторых полях не должен случайно съесть непустое значение).
func TestToServerJSON_RoundTrips(t *testing.T) {
	id := testIdentity(t)
	doc := BuildServerConfig(id, 8443, "www.microsoft.com")

	data, err := ToServerJSON(doc)
	if err != nil {
		t.Fatalf("ToServerJSON: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("ToServerJSON вернул пустые данные")
	}

	var decoded ServerDoc
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("сериализованный конфиг сам не парсится: %v", err)
	}
	if len(decoded.Inbounds) != 1 || decoded.Inbounds[0].TLS.Reality.PrivateKey != id.PrivateKey {
		t.Fatalf("PrivateKey потерян при round-trip сериализации: %+v", decoded)
	}
}

// Регрессия живого прогона Э-Выход-2 (2026-08-18): AutoDetectInterface=true на Android
// роняло КАЖДОЕ подключение к Reality-инбаунду ("no available network interface",
// vendor/.../common/dialer/default_parallel_interface.go) — Reality-сервер дозванивается
// до realityDest через тот же "direct" outbound, что и попадает в dialParallelInterface,
// которому нужен непустой список интерфейсов от PlatformInterface.GetInterfaces()
// (mobile/androidbridge/platform_adapter.go честно возвращает пустой). Тот же класс, что
// уже пойман для клиента (D-A28, TestAutoDetectInterface_DisabledOnAndroid) —
// BuildServerConfig обязан использовать ту же платформенную развилку, а не собственный
// хардкод.
func TestBuildServerConfig_AutoDetectInterface_DisabledOnAndroid(t *testing.T) {
	restore := builderGOOS
	builderGOOS = func() string { return "android" }
	defer func() { builderGOOS = restore }()

	doc := BuildServerConfig(testIdentity(t), 8443, "www.microsoft.com")
	if doc.Route.AutoDetectInterface {
		t.Error("Route.AutoDetectInterface = true на Android — Reality-сервер откажет " +
			"каждому подключению (\"no available network interface\")")
	}
}

// На Windows/Linux (Э-Выход-1/3) поле обязано остаться включённым — там нет ограничений
// PlatformInterface, обычный net.Dialer видит интерфейсы сам, регрессия здесь означала бы
// потерю уже работающей защиты от петли собственного трафика.
func TestBuildServerConfig_AutoDetectInterface_EnabledOnDesktop(t *testing.T) {
	restore := builderGOOS
	defer func() { builderGOOS = restore }()

	for _, goos := range []string{"windows", "linux", "darwin"} {
		builderGOOS = func() string { return goos }
		doc := BuildServerConfig(testIdentity(t), 8443, "www.microsoft.com")
		if !doc.Route.AutoDetectInterface {
			t.Errorf("%s: Route.AutoDetectInterface = false", goos)
		}
	}
}
