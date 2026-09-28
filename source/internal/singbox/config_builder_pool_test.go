package singbox

// Тесты BuildPool (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0) — группа-СЕЛЕКТОР для горячего
// переключения узла на Windows без пересоздания процесса sing-box (см. RCA «5 почему» в ТЗ:
// на Windows нет SIGHUP, Reload() делает Stop()+Start(), что на реальной машине пользователя
// давало 20-68с задержки на каждое из ~12 переключений за сессию). BuildPool — тот же приём,
// что уже работает у BuildRace (config_builder_race_test.go), но тип selector, а не urltest:
// переключает Go-код явно (Process.SwitchOutbound), а не сам sing-box своей пробой.

import (
	"encoding/json"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Группа обязана быть outbound'ом типа selector с тегом proxy (тот же якорь route/kill
// switch, что у BuildRace/BuildSingle), Default выставлен на запрошенный activeTag, и
// InterruptExistConnections включён — иначе переключение оставляло бы «зомби»-соединения
// на старом узле (тот же класс проблемы, что у Задачи #11, но уровнем ниже, в самом
// sing-box, а не в TUN/gVisor).
func TestBuildPool_ProducesSelectorGroupTaggedProxy(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildPool(raceTestNodes(4), "pool-1")
	if err != nil {
		t.Fatalf("BuildPool: %v", err)
	}

	var group *Outbound
	members := 0
	for i := range cfg.Outbounds {
		o := &cfg.Outbounds[i]
		switch {
		case o.Tag == "proxy":
			group = o
		case len(o.Tag) > 5 && o.Tag[:5] == "pool-":
			members++
		}
	}
	if group == nil {
		t.Fatal("нет outbound с тегом proxy — маршрутизация и kill switch завязаны на него")
	}
	if group.Type != "selector" {
		t.Errorf("type = %q, ожидался selector", group.Type)
	}
	if len(group.Outbounds) != 4 {
		t.Errorf("в группе %d участников, ожидалось 4", len(group.Outbounds))
	}
	if members != 4 {
		t.Errorf("создано %d outbound'ов-кандидатов, ожидалось 4", members)
	}
	if group.Default != "pool-1" {
		t.Errorf("Default = %q, ожидался запрошенный activeTag pool-1", group.Default)
	}
	if !group.InterruptExistConnections {
		t.Error("InterruptExistConnections не включён — переключение оставит зомби-" +
			"соединения на старом узле висеть под тем же тегом proxy")
	}
	if cfg.Route.Final != "proxy" {
		t.Errorf("Route.Final = %q, ожидался proxy", cfg.Route.Final)
	}
}

func TestBuildPool_MemberTagsAreUniqueAndReferenced(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildPool(raceTestNodes(5), "pool-0")
	if err != nil {
		t.Fatalf("BuildPool: %v", err)
	}

	tags := map[string]bool{}
	for _, o := range cfg.Outbounds {
		if tags[o.Tag] {
			t.Errorf("тег %q встречается дважды", o.Tag)
		}
		tags[o.Tag] = true
	}
	for _, member := range cfg.Outbounds[0].Outbounds {
		if !tags[member] {
			t.Errorf("группа ссылается на несуществующий outbound %q", member)
		}
	}
	if !tags["direct"] {
		t.Error("direct-outbound потерян — bypass-правила ссылаются на него")
	}
}

func TestBuildPool_SerializesToValidJSON(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildPool(raceTestNodes(3), "pool-0")
	if err != nil {
		t.Fatalf("BuildPool: %v", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("конфиг не сериализуется: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("конфиг не разбирается обратно: %v", err)
	}
	if _, ok := back["outbounds"]; !ok {
		t.Error("в JSON нет outbounds")
	}
}

func TestBuildPool_RejectsTooFewNodes(t *testing.T) {
	b := NewBuilder(10808, false)
	if _, err := b.BuildPool(raceTestNodes(1), "pool-0"); err == nil {
		t.Error("ожидался отказ для одного узла")
	}
	if _, err := b.BuildPool(nil, ""); err == nil {
		t.Error("ожидался отказ для пустого списка")
	}
}

func TestBuildPool_RejectedWithShadowTLSOrCDN(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetShadowTLS(&ShadowTLSParams{Server: "1.2.3.4", Port: 443, Password: "x", SNI: "a.com"})
	if _, err := b.BuildPool(raceTestNodes(3), "pool-0"); err == nil {
		t.Error("ожидался отказ при включённом ShadowTLS")
	}

	b2 := NewBuilder(10808, false)
	b2.SetCDNFronting(&CDNParams{Server: "1.2.3.4", Port: 443, SNI: "a.com", WSPath: "/x"})
	if _, err := b2.BuildPool(raceTestNodes(3), "pool-0"); err == nil {
		t.Error("ожидался отказ при включённом CDN fronting")
	}
}

// Непригодный кандидат не должен рушить всю группу — его просто не берут (тот же приём,
// что у BuildRace), если только это не был запрошенный activeTag (следующий тест).
func TestBuildPool_SkipsUnbuildableCandidate(t *testing.T) {
	nodes := raceTestNodes(3)
	nodes[1].Protocol = models.ProtoWireGuard // nodeToOutbound по нему отказывает

	b := NewBuilder(10808, false)
	cfg, err := b.BuildPool(nodes, "pool-0")
	if err != nil {
		t.Fatalf("группа должна собраться из оставшихся кандидатов: %v", err)
	}
	if got := len(cfg.Outbounds[0].Outbounds); got != 2 {
		t.Errorf("в группе %d участников, ожидалось 2 (непригодный пропущен)", got)
	}
}

// Специфика BuildPool (которой нет у BuildRace: там нет понятия «активный»): если
// activeTag указывает на кандидата, который сам оказался непригоден (или индекс вне
// диапазона), конфиг был бы синтаксически валиден, но переключиться сразу после Start было
// бы не на что — это обязан ловить BuildPool, а не проявляться позже как отказ Clash API.
func TestBuildPool_RejectsWhenActiveTagNotBuildable(t *testing.T) {
	nodes := raceTestNodes(3)
	nodes[0].Protocol = models.ProtoWireGuard // pool-0 не соберётся

	b := NewBuilder(10808, false)
	if _, err := b.BuildPool(nodes, "pool-0"); err == nil {
		t.Error("ожидался отказ: activeTag ссылается на непригодного кандидата")
	}
}

func TestBuildPool_RejectsUnknownActiveTag(t *testing.T) {
	b := NewBuilder(10808, false)
	if _, err := b.BuildPool(raceTestNodes(3), "pool-99"); err == nil {
		t.Error("ожидался отказ: activeTag не существует среди кандидатов")
	}
}

// Тот же инвариант R-8, что и у BuildRace — переиспользует ту же карту SetRacePinnedIPs
// (семантика одна: «заранее резолвнутые адреса кандидатов пачки»).
func TestBuildPool_PinnedIPs_ReplacesDomainWithIP(t *testing.T) {
	nodes := raceTestNodes(3)
	nodes[0].Address = "node-a.example.com"

	b := NewBuilder(10808, false)
	b.SetRacePinnedIPs(map[string]string{"node-a.example.com": "203.0.113.9"})

	cfg, err := b.BuildPool(nodes, "pool-0")
	if err != nil {
		t.Fatalf("BuildPool: %v", err)
	}

	var found bool
	for _, o := range cfg.Outbounds {
		if o.Tag == "pool-0" {
			found = true
			if o.Server != "203.0.113.9" {
				t.Errorf("pool-0.Server = %q, ожидался закреплённый IP 203.0.113.9 "+
					"(домен не должен уходить в открытый DNS)", o.Server)
			}
		}
	}
	if !found {
		t.Fatal("pool-0 outbound не найден")
	}
}
