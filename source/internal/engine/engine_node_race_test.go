package engine

// Тесты «гонки узлов» на уровне движка: когда она применяется, кого берёт в группу и —
// главное — что Kill Switch разрешает адреса ВСЕХ участников, а не только точки входа.
// Последнее не косметика: разрешив один адрес, Kill Switch заблокировал бы остальных
// кандидатов, группа выродилась бы в один узел, и при мёртвой точке входа связи не было бы
// вовсе — то есть включённый Kill Switch делал бы гонку хуже обычного режима.

import (
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func raceNode(id, addr string, score float64) *models.Node {
	return &models.Node{
		ID:          id,
		Name:        "n-" + id,
		Protocol:    models.ProtoShadowsocks,
		Address:     addr,
		Port:        8388,
		Method:      "aes-256-gcm",
		Password:    "pass",
		Score:       score,
		Status:      models.StatusOK,
		Latency:     50,
		LastChecked: time.Now(),
	}
}

func engineWithRaceNodes(t *testing.T, n int) (*Engine, []*models.Node) {
	t.Helper()
	e := newTestEngine()
	e.cfg.NodeRaceEnabled = true
	nodes := make([]*models.Node, 0, n)
	for i := 0; i < n; i++ {
		nd := raceNode(
			string(rune('a'+i)),
			"198.51.100."+string(rune('1'+i)),
			1.0-float64(i)*0.01,
		)
		nodes = append(nodes, nd)
	}
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()
	return e, nodes
}

func TestRaceCandidates_IncludesInitiatorFirstAndFillsUp(t *testing.T) {
	e, nodes := engineWithRaceNodes(t, 10)

	got := e.raceCandidates(nodes[3], 5)
	if len(got) == 0 {
		t.Fatal("группа пуста")
	}
	if got[0].ID != nodes[3].ID {
		t.Errorf("первым идёт %q, ожидался инициатор %q — он победитель обычного отбора, "+
			"и если он рабочий, urltest обязан выбрать именно его", got[0].ID, nodes[3].ID)
	}
	if len(got) > 5 {
		t.Errorf("в группе %d участников, лимит был 5", len(got))
	}
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n.ID] {
			t.Errorf("узел %q попал в группу дважды — дубль тега сломал бы конфиг sing-box", n.ID)
		}
		seen[n.ID] = true
	}
}

// Узлы, только что доказанно подведшие, в гонку не берём: иначе серия переключений раз за
// разом тащила бы за собой один и тот же мёртвый набор.
func TestRaceCandidates_SkipsRecentlyFailed(t *testing.T) {
	e, nodes := engineWithRaceNodes(t, 6)
	e.markNodeFailed(nodes[1].ID)
	e.markNodeFailed(nodes[2].ID)

	for _, n := range e.raceCandidates(nodes[0], 6) {
		if n.ID == nodes[1].ID || n.ID == nodes[2].ID {
			t.Errorf("узел %q недавно подвёл, но попал в группу", n.ID)
		}
	}
}

// Ручной/закреплённый выбор узла обязан подключаться ИМЕННО к нему: гонка увела бы трафик
// на соседа, и это выглядело бы как «ручной выбор не работает».
func TestShouldRaceNodes_RespectsExplicitChoice(t *testing.T) {
	e, nodes := engineWithRaceNodes(t, 5)

	if !e.shouldRaceNodes(nodes[0]) {
		t.Fatal("при обычном автоподключении гонка должна быть разрешена")
	}

	e.PinNode(nodes[0].ID)
	if e.shouldRaceNodes(nodes[0]) {
		t.Error("узел закреплён пользователем — гонка не должна подменять его группой")
	}
	e.PinNode("")

	e.mu.Lock()
	e.manualConnectAt = time.Now()
	e.mu.Unlock()
	if e.shouldRaceNodes(nodes[0]) {
		t.Error("идёт sticky-окно после ручного выбора — гонка не должна перебивать выбор")
	}
}

func TestShouldRaceNodes_DisabledByConfig(t *testing.T) {
	e, nodes := engineWithRaceNodes(t, 5)
	e.cfg.NodeRaceEnabled = false
	if e.shouldRaceNodes(nodes[0]) {
		t.Error("тумблер выключен — гонки быть не должно")
	}
}

// Главный тест этой пачки: Kill Switch обязан разрешить адреса всех участников группы.
func TestKillSwitchAddressesFor_CoversWholeRaceGroup(t *testing.T) {
	e, nodes := engineWithRaceNodes(t, 4)
	group := e.raceCandidates(nodes[0], 4)
	e.setRaceNodes(group)

	addrs := e.killSwitchAddressesFor(nodes[0])
	if len(addrs) == 0 || addrs[0] != nodes[0].Address {
		t.Fatalf("первым обязан идти адрес точки входа, получено: %v", addrs)
	}
	for _, n := range group {
		found := false
		for _, a := range addrs {
			if a == n.Address {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("адрес участника гонки %q не попал в разрешения Kill Switch — "+
				"этот кандидат будет заблокирован собственным Kill Switch", n.Address)
		}
	}
}

// Разрешения не должны переживать группу: после перехода на одиночный узел Kill Switch
// обязан снова разрешать только его.
func TestKillSwitchAddressesFor_ResetWhenNotRacing(t *testing.T) {
	e, nodes := engineWithRaceNodes(t, 4)
	e.setRaceNodes(e.raceCandidates(nodes[0], 4))
	if got := len(e.killSwitchAddressesFor(nodes[0])); got < 2 {
		t.Fatalf("подготовка теста не сработала: в разрешениях %d адресов", got)
	}

	e.setRaceNodes(nil)
	addrs := e.killSwitchAddressesFor(nodes[0])
	if len(addrs) == 0 || addrs[0] != nodes[0].Address {
		t.Fatalf("первым обязан идти адрес узла %q, получено %v", nodes[0].Address, addrs)
	}
	// Проверяем ИМЕННО сброс группы: адресов других участников больше нет. Точное число
	// разрешений здесь не проверяем — в список правомерно попадают ещё и домены bypass с
	// прямым маршрутом, и они зависят от состояния bypass-правил, общего между тестами
	// пакета (bypass_list.json в каталоге данных, а не во временном каталоге теста).
	for _, other := range nodes[1:] {
		for _, a := range addrs {
			if a == other.Address {
				t.Errorf("адрес %q из прошлой группы остался в разрешениях после сброса", a)
			}
		}
	}
}

func TestKillSwitchAddressesFor_NilNode(t *testing.T) {
	e, _ := engineWithRaceNodes(t, 2)
	if got := e.killSwitchAddressesFor(nil); got != nil {
		t.Errorf("для nil-узла ожидался nil, получено %v", got)
	}
}
