package androidbridge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Общий контракт «проверенности» на границе Android-моста (2026-09-06, LOT-06).
//
// Что здесь закрепляется и почему именно это.
//
// Жалоба пользователя звучала как «пишет ВПН подключен, а зайти на сайт не могу», и держалось
// это враньё до конца сеанса. Корень со стороны моста был двойной:
//
//  1. models.ConnectionState.VerifyState объявлен с `omitempty` — при пустом значении ключ
//     ИСЧЕЗАЛ из JSON. Kotlin, для которого это единственный честный источник статуса, обязан
//     был бы догадываться; догадка на прошлой сборке была разбором ПОДСТРОКИ русского текста.
//     Поэтому мост обязан отдавать verify_state ВСЕГДА — это и проверяется ниже.
//
//  2. Список узлов резался до одного булева `proven`, из-за чего «трафик проходил минуту
//     назад» и «трафик проходил неделю назад» на телефоне выглядели одинаково. Значок
//     (models.Node.VerifyBadge) — МЕТОД, в JSON сам не попадает, его обязан вычислить мост.
//
// Осознанное ограничение тестов на список узлов: они проверяют СОСТАВ полей и допустимость
// значений, а не конкретный значок конкретного узла. Причина — AddNode запускает фоновую
// проверку узла (Engine.AddNodeFromLink → checker.CheckOne), которая пишет Status/LastChecked
// того же узла; ожидание конкретного значка было бы гонкой с этой горутиной и дало бы
// мигающий тест, а под `-race` — ещё и ложное обвинение.

// ─── verify_state: он обязан существовать даже когда движок его ещё не заполняет ──────────

// Пустой VerifyState — это НЕ «состояние неизвестно». Поле появилось 2026-09-06, и слой,
// который его наполняет, вливается отдельно; всё это время у моста уже есть Connected и
// Verified, из которых состояние выводится однозначно. Если бы мост отдавал пустую строку,
// экран показывал бы «Отключено» поверх живого туннеля — ровно то враньё, ради устранения
// которого поле и вводилось.
func TestEffectiveVerifyState_FallbackWhenEngineDoesNotFillIt(t *testing.T) {
	cases := []struct {
		name  string
		state *models.ConnectionState
		want  string
	}{
		{"nil-состояние", nil, models.VerifyIdle},
		{"пусто и не подключено", &models.ConnectionState{}, models.VerifyIdle},
		{
			"пусто, туннель поднят, подтверждения ещё нет",
			&models.ConnectionState{Connected: true},
			models.VerifyChecking,
		},
		{
			"пусто, но старый bool Verified уже true",
			&models.ConnectionState{Connected: true, Verified: true},
			models.VerifyVerified,
		},
		{
			"движок заполнил failed — трактовка моста не спорит с ним",
			&models.ConnectionState{Connected: true, VerifyState: models.VerifyFailed},
			models.VerifyFailed,
		},
		{
			"движок заполнил checking",
			&models.ConnectionState{Connected: true, VerifyState: models.VerifyChecking},
			models.VerifyChecking,
		},
		{
			"движок заполнил idle при поднятом Connected — приоритет у движка",
			&models.ConnectionState{Connected: true, VerifyState: models.VerifyIdle},
			models.VerifyIdle,
		},
	}
	for _, c := range cases {
		if got := effectiveVerifyState(c.state); got != c.want {
			t.Errorf("%s: effectiveVerifyState() = %q, ожидалось %q", c.name, got, c.want)
		}
	}
}

// isKnownVerifyState — множество допустимых значений контракта, целиком.
func isKnownVerifyState(s string) bool {
	switch s {
	case models.VerifyIdle, models.VerifyChecking, models.VerifyVerified, models.VerifyFailed:
		return true
	}
	return false
}

// isKnownBadge — те же шесть значков, что рисуют Web/Wails/Kotlin.
func isKnownBadge(s string) bool {
	switch s {
	case models.BadgeProvenFresh, models.BadgeProvenStale, models.BadgeProvenFailed,
		models.BadgeTCPAlive, models.BadgeDead, models.BadgeUnchecked:
		return true
	}
	return false
}

// Ветка «ядро не инициализировано» — тоже часть контракта: Kotlin читает этот JSON тем же
// кодом, что и обычный, и ключей в нём не должно недоставать.
func TestGetStateJSON_BeforeInit_CarriesVerifyContract(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — проверка неинформативна")
	}
	raw := GetStateJSON()
	if !strings.Contains(raw, `"error":"not initialized"`) {
		t.Fatalf("GetStateJSON() = %q, ожидалась ошибка not initialized", raw)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("GetStateJSON() не распарсился: %v (%q)", err, raw)
	}
	for _, key := range []string{"connected", "verified", "verify_state", "active_verified_latency_ms", "active_verify_badge"} {
		if _, ok := m[key]; !ok {
			t.Errorf("GetStateJSON() до инициализации не содержит ключа %q: %s", key, raw)
		}
	}
	var vs string
	if err := json.Unmarshal(m["verify_state"], &vs); err != nil || vs != models.VerifyIdle {
		t.Errorf("verify_state = %q (err=%v), ожидалось %q", vs, err, models.VerifyIdle)
	}
}

// Главная гарантия для Kotlin: ключ verify_state присутствует ВСЕГДА, несмотря на omitempty
// в самой модели, и при этом обычные поля состояния (connected/mode) никуда не делись —
// обёртка не должна была подменить собой встроенную структуру.
func TestGetStateJSON_AfterInit_VerifyStateAlwaysPresent(t *testing.T) {
	newBareTestEngine(t)

	raw := GetStateJSON()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("GetStateJSON() не распарсился: %v (%q)", err, raw)
	}
	// Регресс на обёртку: встроенные поля обязаны остаться на прежних местах.
	for _, key := range []string{"connected", "verified", "mode", "verify_state", "active_verify_badge"} {
		if _, ok := m[key]; !ok {
			t.Errorf("GetStateJSON() не содержит ключа %q: %s", key, raw)
		}
	}

	var vs string
	if err := json.Unmarshal(m["verify_state"], &vs); err != nil {
		t.Fatalf("verify_state не строка: %v", err)
	}
	if !isKnownVerifyState(vs) {
		t.Errorf("verify_state = %q — не из контракта idle|checking|verified|failed", vs)
	}
	// Свежий движок не подключён, значит честное состояние — «Отключено», а не «Подключено».
	var connected bool
	if err := json.Unmarshal(m["connected"], &connected); err != nil {
		t.Fatalf("connected не bool: %v", err)
	}
	if !connected && vs != models.VerifyIdle {
		t.Errorf("connected=false, но verify_state=%q — экран показал бы подключение, которого нет", vs)
	}

	var badge string
	if err := json.Unmarshal(m["active_verify_badge"], &badge); err != nil || !isKnownBadge(badge) {
		t.Errorf("active_verify_badge = %q (err=%v) — не из шести значков контракта", badge, err)
	}
}

// GetVerifyState — та же величина без разбора JSON на стороне Kotlin (D4: строковый разбор
// русского текста удалён, читается ровно это).
func TestGetVerifyState_ContractValues(t *testing.T) {
	if getEngine() == nil {
		if got := GetVerifyState(); got != models.VerifyIdle {
			t.Errorf("GetVerifyState() до инициализации = %q, ожидалось %q", got, models.VerifyIdle)
		}
	}
	newBareTestEngine(t)
	got := GetVerifyState()
	if !isKnownVerifyState(got) {
		t.Fatalf("GetVerifyState() = %q — не из контракта", got)
	}
	if got != models.VerifyIdle {
		t.Errorf("GetVerifyState() на неподключённом движке = %q, ожидалось %q", got, models.VerifyIdle)
	}
	// Тождество со старым bool обязано сохраниться: Verified == (verify_state == verified).
	if IsVerified() != (got == models.VerifyVerified) {
		t.Errorf("IsVerified()=%v расходится с verify_state=%q", IsVerified(), got)
	}
}

// D12: «подтверждённая через туннель» задержка — отдельная величина, и её отсутствие (0)
// нельзя путать с нулевой задержкой. Без активного узла ответ обязан быть 0, а не паника.
func TestGetActiveNodeVerifiedLatency_ZeroWithoutActiveNode(t *testing.T) {
	if getEngine() == nil {
		if got := GetActiveNodeVerifiedLatency(); got != 0 {
			t.Errorf("GetActiveNodeVerifiedLatency() до инициализации = %d, ожидалось 0", got)
		}
	}
	newBareTestEngine(t)
	if got := GetActiveNodeVerifiedLatency(); got != 0 {
		t.Errorf("GetActiveNodeVerifiedLatency() без активного узла = %d, ожидалось 0", got)
	}
	// Обе задержки обязаны существовать раздельно: TCP-величина у неподключённого движка
	// тоже 0, но это ДРУГОЙ ноль, и смешивать их в одном поле нельзя.
	if got := GetActiveNodeLatency(); got != 0 {
		t.Errorf("GetActiveNodeLatency() без активного узла = %d, ожидалось 0", got)
	}
}

// ─── Список узлов: значок вместо булевой галочки ──────────────────────────────────────────

// Состав полей элемента списка. `proven` намеренно проверяется на ПРИСУТСТВИЕ: его уже
// читают существующие сборки UI, и удаление поля сломало бы их молча.
func TestGetNodesJSON_CarriesVerifyBadgeAndFreshness(t *testing.T) {
	snapshotAndRestoreDataFile(t, "nodes_cache.json")
	snapshotAndRestoreDataFile(t, "config.json")
	newBareTestEngine(t)

	if got := AddNode("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.9:8388#BadgeNode"); got != "" {
		t.Fatalf("AddNode() = %q, ожидался успех", got)
	}

	raw := GetNodesJSON()
	var items []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		t.Fatalf("GetNodesJSON() не распарсился: %v (%q)", err, raw)
	}
	if len(items) == 0 {
		t.Fatalf("GetNodesJSON() пуст после AddNode: %q", raw)
	}

	for _, item := range items {
		for _, key := range []string{"proven", "verify_badge", "last_verified_at", "verified_count", "verified_latency_ms"} {
			if _, ok := item[key]; !ok {
				t.Fatalf("узел списка не содержит ключа %q: %v", key, item)
			}
		}
		var badge string
		if err := json.Unmarshal(item["verify_badge"], &badge); err != nil {
			t.Fatalf("verify_badge не строка: %v", err)
		}
		if !isKnownBadge(badge) {
			t.Errorf("verify_badge = %q — не из шести значков контракта", badge)
		}
		// «Подтверждён» и «есть отметка о подтверждении» обязаны быть согласованы: значок
		// proven_* без единого подтверждения означал бы, что телефон рисует зелёное там,
		// где трафик через узел никогда не проверялся.
		var provenCount int
		if err := json.Unmarshal(item["verified_count"], &provenCount); err != nil {
			t.Fatalf("verified_count не число: %v", err)
		}
		var lastVerified int64
		if err := json.Unmarshal(item["last_verified_at"], &lastVerified); err != nil {
			t.Fatalf("last_verified_at не число: %v", err)
		}
		if strings.HasPrefix(badge, "proven") && (provenCount == 0 || lastVerified == 0) {
			t.Errorf("значок %q при verified_count=%d/last_verified_at=%d — значок обещает трафик, которого не было",
				badge, provenCount, lastVerified)
		}
	}
}
