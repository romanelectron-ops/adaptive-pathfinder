package singbox

// Тесты «гонки узлов» (BuildRace) — механизма, решающего проблему из живого лога
// пользователя от 2026-08-20: выбранный по score «лучший» узел оказывался мёртвым и
// десятки секунд держал пользователя без интернета, пока watchdog искал замену.

import (
	"encoding/json"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func raceTestNodes(n int) []*models.Node {
	out := make([]*models.Node, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &models.Node{
			ID:       string(rune('a'+i)) + "-id",
			Name:     "node-" + string(rune('a'+i)),
			Protocol: models.ProtoShadowsocks,
			Address:  "198.51.100." + string(rune('1'+i)),
			Port:     8388 + i,
			Method:   "aes-256-gcm",
			Password: "pass",
		})
	}
	return out
}

// Группа обязана быть outbound'ом типа urltest с тегом proxy: на этот тег завязаны
// route-правила, kill switch и health-check — подмена должна быть прозрачной.
func TestBuildRace_ProducesURLTestGroupTaggedProxy(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildRace(raceTestNodes(4))
	if err != nil {
		t.Fatalf("BuildRace: %v", err)
	}

	var group *Outbound
	members := 0
	for i := range cfg.Outbounds {
		o := &cfg.Outbounds[i]
		switch {
		case o.Tag == "proxy":
			group = o
		case len(o.Tag) > 5 && o.Tag[:5] == "race-":
			members++
		}
	}
	if group == nil {
		t.Fatal("нет outbound с тегом proxy — маршрутизация и kill switch завязаны на него")
	}
	if group.Type != "urltest" {
		t.Errorf("type = %q, ожидался urltest", group.Type)
	}
	if len(group.Outbounds) != 4 {
		t.Errorf("в группе %d участников, ожидалось 4", len(group.Outbounds))
	}
	if members != 4 {
		t.Errorf("создано %d outbound'ов-кандидатов, ожидалось 4", members)
	}
	if group.URL != RaceProbeURL {
		t.Errorf("URL пробы = %q, ожидался %q", group.URL, RaceProbeURL)
	}
	if group.Tolerance <= 0 {
		t.Error("Tolerance не задан — группа будет дребезжать между равными узлами, " +
			"обрывая установленные соединения")
	}
	if cfg.Route.Final != "proxy" {
		t.Errorf("Route.Final = %q, ожидался proxy", cfg.Route.Final)
	}
}

// Каждый участник обязан быть самостоятельным рабочим outbound'ом с уникальным тегом:
// дубль тега молча ломает конфиг sing-box.
func TestBuildRace_MemberTagsAreUniqueAndReferenced(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildRace(raceTestNodes(5))
	if err != nil {
		t.Fatalf("BuildRace: %v", err)
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

// Конфиг обязан быть сериализуемым: sing-box получает именно JSON.
func TestBuildRace_SerializesToValidJSON(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildRace(raceTestNodes(3))
	if err != nil {
		t.Fatalf("BuildRace: %v", err)
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

// Гонка из одного узла бессмысленна — вызывающая сторона должна откатиться на BuildSingle.
func TestBuildRace_RejectsTooFewNodes(t *testing.T) {
	b := NewBuilder(10808, false)
	if _, err := b.BuildRace(raceTestNodes(1)); err == nil {
		t.Error("ожидался отказ для одного узла")
	}
	if _, err := b.BuildRace(nil); err == nil {
		t.Error("ожидался отказ для пустого списка")
	}
}

// ShadowTLS/CDN занимают теги outbound'ов своей обёрткой — совмещение молча сломало бы её.
func TestBuildRace_RejectedWithShadowTLSOrCDN(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetShadowTLS(&ShadowTLSParams{Server: "1.2.3.4", Port: 443, Password: "x", SNI: "a.com"})
	if _, err := b.BuildRace(raceTestNodes(3)); err == nil {
		t.Error("ожидался отказ при включённом ShadowTLS")
	}

	b2 := NewBuilder(10808, false)
	b2.SetCDNFronting(&CDNParams{Server: "1.2.3.4", Port: 443, SNI: "a.com", WSPath: "/x"})
	if _, err := b2.BuildRace(raceTestNodes(3)); err == nil {
		t.Error("ожидался отказ при включённом CDN fronting")
	}
}

// Непригодный кандидат не должен рушить всю группу — его просто не берут.
func TestBuildRace_SkipsUnbuildableCandidate(t *testing.T) {
	nodes := raceTestNodes(3)
	nodes[1].Protocol = models.ProtoWireGuard // nodeToOutbound по нему отказывает

	b := NewBuilder(10808, false)
	cfg, err := b.BuildRace(nodes)
	if err != nil {
		t.Fatalf("группа должна собраться из оставшихся кандидатов: %v", err)
	}
	if got := len(cfg.Outbounds[0].Outbounds); got != 2 {
		t.Errorf("в группе %d участников, ожидалось 2 (непригодный пропущен)", got)
	}
}

// Если непригодных кандидатов настолько много, что пригодным остаётся только один —
// гонка теряет смысл (нечего сравнивать), и BuildRace обязан явно отказать, а не
// молча собрать группу из одного участника (что для urltest эквивалентно BuildSingle,
// но без обычных для него гарантий closest-к-BuildSingle поведения).
func TestBuildRace_TooFewBuildableCandidates_Rejected(t *testing.T) {
	nodes := raceTestNodes(2)
	nodes[1].Protocol = models.ProtoWireGuard // единственный оставшийся пригодный — nodes[0]

	b := NewBuilder(10808, false)
	if _, err := b.BuildRace(nodes); err == nil {
		t.Error("ожидался отказ: после отсева пригодных кандидатов остался только 1")
	}
}

// ─── SetRacePinnedIPs ─────────────────────────────────────────────────────────
// R-8 для гонки (находка ревью 2026-08-24): без закрепления IP в конфиге остаются
// ДОМЕННЫЕ имена кандидатов, и sing-box резолвит их сам через открытый DNS без detour —
// это утечка всего списка VPN-узлов пользователя. SetRacePinnedIPs обязан подставлять
// заранее резолвнутый IP в Server каждого кандидата, чей Address присутствует в карте.

func TestBuildRace_PinnedIPs_ReplacesDomainWithIP(t *testing.T) {
	nodes := raceTestNodes(3)
	// raceTestNodes уже использует IP-адреса (198.51.100.x) — подменим первый узел на
	// доменное имя, чтобы pinServerIP(имел что подставлять.
	nodes[0].Address = "node-a.example.com"

	b := NewBuilder(10808, false)
	b.SetRacePinnedIPs(map[string]string{"node-a.example.com": "203.0.113.9"})

	cfg, err := b.BuildRace(nodes)
	if err != nil {
		t.Fatalf("BuildRace: %v", err)
	}

	var found bool
	for _, o := range cfg.Outbounds {
		if o.Tag == "race-0" {
			found = true
			if o.Server != "203.0.113.9" {
				t.Errorf("race-0.Server = %q, ожидался закреплённый IP 203.0.113.9 "+
					"(домен не должен уходить в открытый DNS)", o.Server)
			}
		}
	}
	if !found {
		t.Fatal("race-0 outbound не найден")
	}
}

// Значение карты может быть списком через запятую (типичный ответ резолвера с
// несколькими A-записями) — берётся первый адрес.
func TestBuildRace_PinnedIPs_CommaSeparatedTakesFirst(t *testing.T) {
	nodes := raceTestNodes(2)
	nodes[0].Address = "multi.example.com"

	b := NewBuilder(10808, false)
	b.SetRacePinnedIPs(map[string]string{"multi.example.com": "198.51.100.50,198.51.100.51"})

	cfg, err := b.BuildRace(nodes)
	if err != nil {
		t.Fatalf("BuildRace: %v", err)
	}
	for _, o := range cfg.Outbounds {
		if o.Tag == "race-0" && o.Server != "198.51.100.50" {
			t.Errorf("race-0.Server = %q, ожидался первый IP из списка 198.51.100.50", o.Server)
		}
	}
}

// Кандидат, для которого закрепления нет в карте, остаётся с исходным адресом
// (частичное закрепление — не повод ломать остальных участников гонки).
func TestBuildRace_PinnedIPs_UnmatchedNodeKeepsOriginalAddress(t *testing.T) {
	nodes := raceTestNodes(2)
	nodes[0].Address = "pinned.example.com"
	nodes[1].Address = "not-pinned.example.com"

	b := NewBuilder(10808, false)
	b.SetRacePinnedIPs(map[string]string{"pinned.example.com": "203.0.113.5"})

	cfg, err := b.BuildRace(nodes)
	if err != nil {
		t.Fatalf("BuildRace: %v", err)
	}
	for _, o := range cfg.Outbounds {
		if o.Tag == "race-1" && o.Server != "not-pinned.example.com" {
			t.Errorf("race-1.Server = %q, домен без закрепления не должен подменяться", o.Server)
		}
	}
}
