package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
)

// Правки по независимой рецензии лотов L1/L2/L4. Данные синтетические (RFC 5737, выдуманные UUID).

// l12LinkUUID - как l12Link, но с заданным UUID: два РАЗНЫХ сервера за одним адресом:портом.
func l12LinkUUID(host, uuid, fp string) string {
	return fmt.Sprintf("vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.org&fp=%s&pbk=%s&sid=ab12&type=tcp#n", uuid, host, fp, l12PBK)
}

const (
	l12UUIDa = "00000000-0000-4000-8000-0000000000a1"
	l12UUIDb = "00000000-0000-4000-8000-0000000000b2"
)

func setPinAndFavorites(e *Engine, pin *models.NodeRef, favs ...models.NodeRef) {
	e.mu.Lock()
	e.cfg.PinnedNode = pin
	e.cfg.Favorites = favs
	e.mu.Unlock()
}

// HIGH-1: два разных сервера за одним адресом:портом (обычное дело для CDN :443). Закреплённый по
// ТОЧНОМУ ID второй узел не подменяется первым «по адресу».
func TestL2Review_PinByExactIDDoesNotJumpToOtherServerAtSameAddress(t *testing.T) {
	e, _ := newL12Engine(t)
	nodes := l12Parse(t, l12LinkUUID("192.0.2.77", l12UUIDa, "chrome"), l12LinkUUID("192.0.2.77", l12UUIDb, "chrome"))
	if nodes[0].ID == nodes[1].ID {
		t.Fatal("разные UUID дали один ID")
	}
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()
	ref := models.NodeRefOf(nodes[1])
	setPinAndFavorites(e, &ref, ref)

	e.restorePinAndFavorites()

	if got := e.PinnedNodeID(); got != nodes[1].ID {
		t.Errorf("закреплён %q, ожидался второй узел %q", got, nodes[1].ID)
	}
	if !e.IsFavorite(nodes[1].ID) || e.IsFavorite(nodes[0].ID) {
		t.Errorf("избранное: второй=%v первый=%v", e.IsFavorite(nodes[1].ID), e.IsFavorite(nodes[0].ID))
	}
}

// HIGH-1: ссылка хранит ID по схеме до L2 (узел с другим fp), за адресом живут два сервера - находится
// именно тот, чей старый ID совпал, а не первый по адресу.
func TestL2Review_PinWithLegacyIDPicksTheRightServerAmongSameAddress(t *testing.T) {
	e, _ := newL12Engine(t)
	nodes := l12Parse(t, l12LinkUUID("192.0.2.78", l12UUIDa, "chrome"), l12LinkUUID("192.0.2.78", l12UUIDb, "firefox"))
	legacyB := parser.LegacyNodeID(nodes[1]) // как сохранила старая сборка (fp=firefox в хеше)
	nodes[1].TLS.Fingerprint = "chrome"      // сейчас основной отпечаток другой
	nodes[1].FPCandidates = nil
	nodes[1].ID = parser.GenerateNodeID(nodes[1])
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()
	ref := models.NodeRef{ID: legacyB, Address: "192.0.2.78", Port: 443, Protocol: models.ProtoVLESS, Name: "n"}
	setPinAndFavorites(e, &ref)

	e.restorePinAndFavorites()

	if got := e.PinnedNodeID(); got != nodes[1].ID {
		t.Fatalf("закреплён %q, ожидался узел со старым ID %q", got, nodes[1].ID)
	}
	// Новый ID записан в config.json: тот же путь не повторяется при каждом запуске.
	e.mu.RLock()
	saved := e.cfg.PinnedNode
	e.mu.RUnlock()
	if saved == nil || saved.ID != nodes[1].ID {
		t.Errorf("в config.json остался %+v, ожидался новый ID %s", saved, nodes[1].ID)
	}
}

// HIGH-1: ID не найден, по адресу кандидатов несколько и имена не помогают - закреп остаётся «missing»,
// а не уходит на случайного соседа. Одно совпадение по имени разрешает неоднозначность.
func TestL2Review_AmbiguousAddressIsNotGuessed(t *testing.T) {
	e, _ := newL12Engine(t)
	nodes := l12Parse(t, l12LinkUUID("192.0.2.79", l12UUIDa, "chrome"), l12LinkUUID("192.0.2.79", l12UUIDb, "chrome"))
	nodes[0].Name, nodes[1].Name = "первый", "второй"
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()

	gone := models.NodeRef{ID: "deadbeefdeadbeef", Address: "192.0.2.79", Port: 443, Protocol: models.ProtoVLESS, Name: "чужое имя"}
	setPinAndFavorites(e, &gone)
	e.restorePinAndFavorites()
	if got := e.PinnedNodeID(); got != "deadbeefdeadbeef" {
		t.Errorf("неоднозначный закреп переехал на %q", got)
	}
	if st := e.pinnedStatusLocked(); st != pinStatusMissing {
		t.Errorf("статус закрепа %q, ожидался %q", st, pinStatusMissing)
	}

	byName := models.NodeRef{ID: "deadbeefdeadbeef", Address: "192.0.2.79", Port: 443, Protocol: models.ProtoVLESS, Name: "второй"}
	setPinAndFavorites(e, &byName)
	e.restorePinAndFavorites()
	if got := e.PinnedNodeID(); got != nodes[1].ID {
		t.Errorf("совпадение по имени не разрешило неоднозначность: %q", got)
	}
}

// pinnedStatusLocked - статус закрепа для теста.
func (e *Engine) pinnedStatusLocked() string {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.pinnedStatus
}

// HIGH-1: последний рабочий узел, записанный под ID до L2, находится по старому ID.
func TestL2Review_LastActiveNodeWithLegacyIDIsStillPreferred(t *testing.T) {
	e, _ := newL12Engine(t)
	n := l12Parse(t, l12Link("192.0.2.80", "chrome", "tcp"))[0]
	legacy := parser.LegacyNodeID(n)
	if legacy == n.ID {
		t.Fatal("старый и новый ID совпали - тест ничего не проверяет")
	}
	e.mu.Lock()
	e.nodes = []*models.Node{n}
	e.cfg.LastActiveNodeID = legacy
	e.mu.Unlock()

	found := false
	for _, c := range e.preferredCandidates() {
		if c.node == n && strings.Contains(c.why, "последний") {
			found = true
		}
	}
	if !found {
		t.Error("последний рабочий узел под старым ID не найден среди приоритетных кандидатов")
	}
}

// HIGH-2: мусорные fp=junkN из огромной выдачи не раздувают список, а слияние остаётся быстрым.
func TestL2Review_FingerprintListIsCapped(t *testing.T) {
	e, _ := newL12Engine(t)
	var lines []string
	for i := 0; i < 5000; i++ {
		lines = append(lines, l12Link("192.0.2.81", fmt.Sprintf("junk%d", i), "tcp"))
	}
	start := time.Now()
	e.mergeFetchedNodes(l12Parse(t, lines...), "Тест")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("слияние 5000 вариантов заняло %v под блокировкой пула", elapsed)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 1 {
		t.Fatalf("в пуле %d узлов, ожидался 1", len(e.nodes))
	}
	if got := len(e.nodes[0].FPCandidates); got > 12 {
		t.Errorf("отпечатков %d, потолок 12", got)
	}
}

// HIGH-2: в список отпечатков не попадает то, что не похоже на имя отпечатка.
func TestL2Review_FingerprintValidation(t *testing.T) {
	n := &models.Node{TLS: &models.TLSConfig{Fingerprint: "Chrome"}}
	n.FPCandidates = []string{"firefox", "bad name", strings.Repeat("a", 25), "evil/../x", "Safari", "chrome", ""}
	n.NormalizeFingerprints()
	want := []string{"chrome", "firefox", "safari"}
	if strings.Join(n.FPCandidates, ",") != strings.Join(want, ",") {
		t.Errorf("FPCandidates = %v, ожидалось %v", n.FPCandidates, want)
	}
}

// MED-3: при схлопывании вариантов выживает запись, принадлежащая пользователю (ручная), а не первая в
// файле: иначе узел терял пометку «ручной» и выпадал из удержания кэша.
func TestL2Review_LoadNodesKeepsUserOwnedVariant(t *testing.T) {
	e, _ := newL12Engine(t)
	vs := l12Parse(t, l12Link("192.0.2.82", "chrome", "tcp"), l12Link("192.0.2.82", "firefox", "tcp"))
	for _, n := range vs {
		n.ID = parser.LegacyNodeID(n)
		n.FPCandidates = nil
	}
	vs[0].Source = "v2ray-aggregator"
	vs[1].Source = "manual"
	vs[1].VerifiedCount = 3
	vs[1].LastVerifiedAt = time.Now().Unix()
	writeLegacyCache(t, vs)

	if err := e.loadNodes(); err != nil {
		t.Fatal(err)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(e.nodes))
	}
	n := e.nodes[0]
	if !n.IsUserOwned() || n.Source != "manual" {
		t.Errorf("пометка «ручной» потеряна: source=%q", n.Source)
	}
	if n.TLS.Fingerprint != "firefox" || len(n.FPCandidates) != 2 || n.FPCandidates[0] != "firefox" {
		t.Errorf("основной отпечаток должен остаться тем, на котором узел подтверждался: fp=%q список=%v", n.TLS.Fingerprint, n.FPCandidates)
	}
}

// MED-3: при равенстве по принадлежности выживает подтверждённая запись.
func TestL2Review_LoadNodesKeepsProvenVariant(t *testing.T) {
	e, _ := newL12Engine(t)
	vs := l12Parse(t, l12Link("192.0.2.83", "chrome", "tcp"), l12Link("192.0.2.83", "ios", "tcp"))
	for _, n := range vs {
		n.ID = parser.LegacyNodeID(n)
		n.FPCandidates = nil
	}
	vs[1].VerifiedCount = 4
	vs[1].LastVerifiedAt = time.Now().Unix()
	writeLegacyCache(t, vs)
	if err := e.loadNodes(); err != nil {
		t.Fatal(err)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 1 || e.nodes[0].TLS.Fingerprint != "ios" {
		t.Fatalf("выжил не подтверждённый вариант: %+v", e.nodes[0].TLS)
	}
}

// MED-4/5: узел, который пользователь сознательно оставил в пуле, не убивается «повышением»
// надгробия одного из удалённых вариантов fp.
func TestL2Review_KeptNodeSurvivesLegacyTombstonesOfRemovedVariants(t *testing.T) {
	e, _ := newL12Engine(t)
	kept := l12Parse(t, l12Link("192.0.2.84", "chrome", "tcp"))[0]
	e.mu.Lock()
	e.nodes = []*models.Node{kept}
	e.mu.Unlock()
	// Надгробия шести удалённых вариантов, поставленные старой сборкой.
	for _, fp := range []string{"firefox", "safari", "ios", "android", "edge", "random"} {
		v := l12Parse(t, l12Link("192.0.2.84", fp, "tcp"))[0]
		e.tombs.add(parser.LegacyNodeID(v))
	}
	added := e.mergeFetchedNodes(l12Parse(t, l12Link("192.0.2.84", "firefox", "tcp"), l12Link("192.0.2.84", "safari", "tcp")), "Тест")
	if added != 0 {
		t.Fatalf("добавлено %d", added)
	}
	if e.tombs.has(kept.ID) {
		t.Error("надгробие повышено до ID узла, оставленного пользователем: после перезапуска он пропал бы насовсем")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 1 {
		t.Errorf("узел выпал из пула: %d", len(e.nodes))
	}
}

// MED-5: ручное добавление снимает и надгробия под ID по схеме до L2.
func TestL2Review_ManualAddClearsLegacyTombstones(t *testing.T) {
	e, _ := newL12Engine(t)
	n := l12Parse(t, l12Link("192.0.2.85", "chrome", "tcp"))[0]
	legacy := parser.LegacyNodeID(n)
	e.tombs.add(legacy)
	e.tombs.add(n.ID)
	e.clearNodeTombstones(n)
	if e.tombs.has(legacy) || e.tombs.has(n.ID) {
		t.Errorf("надгробия не сняты: старое=%v новое=%v", e.tombs.has(legacy), e.tombs.has(n.ID))
	}
}

// LOW-6: перебор старых ID не меняет узел (раньше временно подменял TLS.Fingerprint).
func TestL2Review_LegacyNodeIDsDoesNotMutateNode(t *testing.T) {
	n := l12Parse(t, l12Link("192.0.2.86", "chrome", "tcp"))[0]
	before := n.TLS.Fingerprint
	done := make(chan struct{})
	go func() { // параллельный читатель не должен видеть чужой fp
		defer close(done)
		for i := 0; i < 2000; i++ {
			if n.TLS.Fingerprint != before {
				t.Error("читатель увидел подменённый fp")
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		_ = parser.LegacyNodeIDs(n)
	}
	<-done
	if n.TLS.Fingerprint != before {
		t.Errorf("fp изменён: %q", n.TLS.Fingerprint)
	}
}

// L4: проб-инстансы проверки узлов тоже под паролем сессии (раньше - открытый прокси на предсказуемом порту).
func TestL4Review_ProbeBuilderRequiresSessionPassword(t *testing.T) {
	b := newProbeBuilder(20001)
	if !b.LocalAuthEnabled() {
		t.Fatal("проб-билдер без пароля сессии")
	}
	cfg, err := b.BuildSingle(&models.Node{
		Protocol: models.ProtoVLESS, Address: "192.0.2.90", Port: 443, UUID: "12345678-1234-1234-1234-123456789012",
	})
	if err != nil {
		t.Fatal(err)
	}
	withUsers := 0
	for _, in := range cfg.Inbounds {
		if in.Tag == "socks-in" || in.Tag == "http-in" {
			if len(in.Users) != 1 {
				t.Errorf("%s: users=%v", in.Tag, in.Users)
			} else {
				withUsers++
			}
		}
		if in.Tag == "tun-in" {
			t.Error("в проб-инстансе не должно быть TUN")
		}
	}
	if withUsers != 2 {
		t.Errorf("входов с паролем %d, ожидалось 2", withUsers)
	}
}

// L4: режим локальных входов привязан к режиму подключения на уровне движка (раньше проверялось
// только на уровне билдера).
func TestL4Review_EngineBuilderFollowsConnectionMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{{models.ModeProxy, false}, {models.ModeHybrid, false}, {models.ModeVPN, true}} {
		cfg := models.DefaultConfig()
		cfg.AutoConnect = false
		cfg.EnableKillSwitch = false
		cfg.ConnectionMode = tc.mode
		e := New(cfg)
		if got := e.builder.LocalAuthEnabled(); got != tc.want {
			t.Errorf("режим %q: пароль на локальных входах = %v, ожидалось %v", tc.mode, got, tc.want)
		}
	}
}
