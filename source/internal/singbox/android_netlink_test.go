package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Контракт «конфигурация для Android не содержит запрещённых системой возможностей»
// (дефект D-A28).
//
// Вход:      целевая ОС + любой из способов сборки конфигурации.
// Тело:      Build* → baseConfig → autoDetectInterfaceSupported.
// Выход:     route.auto_detect_interface.
// Fail-safe: на Android — всегда false, независимо от режима (TUN, цепочка, Tor).
// Инвариант: ни один путь сборки не выдаёт для Android конфигурацию, которую sing-box
//
//	откажется запускать из-за netlink.
//
// Цена ошибки, которую ловит тест: sing-box падает ДО разбора остальной конфигурации, и
// снаружи это неотличимо от сетевой неисправности — SOCKS-порт не открыт, watchdog пишет
// «connection refused», движок объявляет таймаут и уходит в фаллбэк. Ни сборка, ни vet,
// ни запуск приложения ничего не покажут: видно только на устройстве, после подключения.
func TestAutoDetectInterface_DisabledOnAndroid(t *testing.T) {
	restore := builderGOOS
	builderGOOS = func() string { return "android" }
	defer func() { builderGOOS = restore }()

	node := &models.Node{
		ID:       "n1",
		Name:     "test",
		Address:  "198.51.100.7",
		Port:     443,
		Protocol: models.ProtoVLESS,
		UUID:     "11111111-2222-3333-4444-555555555555",
	}

	single, err := NewBuilder(10808, false).BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}

	cases := map[string]*Config{
		"BuildSingle":         single,
		"BuildTor":            NewBuilder(10808, false).BuildTor(),
		"BuildTor + TUN-mode": NewBuilder(10808, true).BuildTor(),
	}
	for name, cfg := range cases {
		if cfg.Route.AutoDetectInterface {
			t.Errorf("%s: auto_detect_interface = true на Android — sing-box не запустится: "+
				"«netlink socket in Android is banned by Google»", name)
		}
	}

	// Поле обязано ПРИСУТСТВОВАТЬ со значением false, а не исчезнуть: у sing-box значение
	// по умолчанию тоже false, но молчаливое отсутствие поля скрывает намерение — при
	// добавлении omitempty никто бы не заметил, что защита испарилась.
	raw, err := ToJSON(single)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if !strings.Contains(string(raw), `"auto_detect_interface": false`) {
		t.Errorf("в JSON нет явного \"auto_detect_interface\": false:\n%s", raw)
	}
}

// На остальных системах поле обязано остаться включённым: там оно защищает от петли
// «исходящие сокеты sing-box уходят в его же TUN», и выключение сломало бы десктоп.
func TestAutoDetectInterface_EnabledOnDesktop(t *testing.T) {
	restore := builderGOOS
	defer func() { builderGOOS = restore }()

	for _, goos := range []string{"windows", "linux", "darwin"} {
		builderGOOS = func() string { return goos }
		cfg := NewBuilder(10808, true).BuildTor()
		if !cfg.Route.AutoDetectInterface {
			t.Errorf("%s: auto_detect_interface = false — трафик sing-box рискует уйти "+
				"обратно в его собственный TUN", goos)
		}
	}
}

// Проверка самой точки подмены: если builderGOOS перестанет читаться, оба теста выше
// станут проверять текущую систему разработчика и всегда проходить.
func TestBuilderGOOS_IsActuallyConsulted(t *testing.T) {
	restore := builderGOOS
	defer func() { builderGOOS = restore }()

	called := false
	builderGOOS = func() string { called = true; return "android" }
	NewBuilder(10808, false).BuildTor()
	if !called {
		t.Error("baseConfig не спросил builderGOOS — платформенная развилка мертва")
	}
}

// Контракт «detour указывается только там, где он что-то меняет» (дефект D-A30).
//
// Вход:      любая собранная конфигурация.
// Тело:      buildDNS.
// Выход:     поле detour у DNS-серверов.
// Fail-safe: локальный DNS остаётся без detour; удалённый — обязан его сохранить.
// Инвариант: ни один DNS-сервер не отсылает к пустому outbound direct.
//
// Обе половины проверки одинаково важны. Лишний detour у dns-local роняет sing-box при
// старте («detour to an empty direct outbound makes no sense»). Потерянный detour у
// dns-remote тише и хуже: конфигурация запустится, а DNS-запросы пойдут мимо туннеля —
// это утечка DNS, ради устранения которой сервер и заведён.
func TestDNS_DetourOnlyWhereItChangesSomething(t *testing.T) {
	// Собираем список пустых outbound'ов direct — именно на них ссылаться запрещено.
	cfg := NewBuilder(10808, false).BuildTor()
	empty := map[string]bool{}
	for _, out := range cfg.Outbounds {
		if out.Type == "direct" && out.Server == "" && out.Detour == "" {
			empty[out.Tag] = true
		}
	}

	sawRemote := false
	for _, srv := range cfg.DNS.Servers {
		if empty[srv.Detour] {
			t.Errorf("DNS-сервер %q отсылает к пустому outbound direct (%q) — "+
				"sing-box 1.12+ откажется стартовать", srv.Tag, srv.Detour)
		}
		if srv.Tag == "dns-remote" {
			sawRemote = true
			if srv.Detour != "proxy" {
				t.Errorf("dns-remote.detour = %q вместо \"proxy\": запросы уйдут мимо "+
					"туннеля — это утечка DNS", srv.Detour)
			}
		}
	}
	if !sawRemote {
		t.Error("сервера dns-remote нет — проверка защиты от утечки DNS выродилась")
	}
}

// Побочная гарантия: конфигурация остаётся валидным JSON после развилки (чтобы поломка
// структуры не проскочила незамеченной вместе с изменением одного поля).
func TestAndroidConfig_IsValidJSON(t *testing.T) {
	restore := builderGOOS
	builderGOOS = func() string { return "android" }
	defer func() { builderGOOS = restore }()

	raw, err := ToJSON(NewBuilder(10808, false).BuildTor())
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var any map[string]interface{}
	if err := json.Unmarshal(raw, &any); err != nil {
		t.Fatalf("конфигурация перестала быть валидным JSON: %v", err)
	}
}
