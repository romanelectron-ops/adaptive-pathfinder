// node_lifecycle_test.go — ТЗ v1.3 F1.2/F2: методы Node, отвечающие за жизненный цикл
// «подтверждён реальным трафиком / не проверен ни разу / последнее событие — сбой» и за
// устойчивые ссылки на узел (NodeRef). До этого файла ни один из них не был протестирован
// напрямую (только косвенно, через CalcScoreWeighted в internal/checker) — пробел найден при
// сверке internal/models/*.go с существующими *_test.go в рамках верификационного прогона.
package models

import (
	"testing"
	"time"
)

// ── IsProven ─────────────────────────────────────────────────────────────────

func TestIsProven_TrueWhenVerifiedAndNotBanned(t *testing.T) {
	n := &Node{VerifiedCount: 1, LastVerifiedAt: 1_700_000_000}
	if !n.IsProven() {
		t.Error("узел с VerifiedCount>0 и LastVerifiedAt>0 должен быть IsProven")
	}
}

func TestIsProven_FalseWhenNeverVerified(t *testing.T) {
	cases := []*Node{
		{},                                              // ни разу не проверялся
		{VerifiedCount: 0, LastVerifiedAt: 1_700_000_000}, // время есть, счётчика нет (не должно бывать, но не должно и падать)
		{VerifiedCount: 3, LastVerifiedAt: 0},             // счётчик есть, времени нет
	}
	for i, n := range cases {
		if n.IsProven() {
			t.Errorf("случай %d: узел без полного подтверждения не должен быть IsProven: %+v", i, *n)
		}
	}
}

// F3: ручной бан ДОЛЖЕН перевешивать любое количество прошлых подтверждений — иначе
// «забаненный навсегда» узел из комментария UserBanned продолжал бы выбираться как proven.
func TestIsProven_FalseWhenUserBanned(t *testing.T) {
	n := &Node{VerifiedCount: 10, LastVerifiedAt: 1_700_000_000, UserBanned: true}
	if n.IsProven() {
		t.Error("забаненный пользователем узел не должен быть IsProven независимо от истории подтверждений")
	}
}

// ── IsUnchecked ──────────────────────────────────────────────────────────────

func TestIsUnchecked_TrueForZeroValueNode(t *testing.T) {
	n := &Node{}
	if !n.IsUnchecked() {
		t.Error("совсем новый узел (нулевые значения) должен быть IsUnchecked")
	}
}

// Любой из четырёх признаков «его уже касалась проверка» снимает IsUnchecked — иначе узел с
// историей сбоев (LastFailedAt) или единственной TCP-пробой (Status/LastChecked) снова
// проходил бы через getRescanBatch как будто ни разу не тестировался.
func TestIsUnchecked_FalseIfAnySignalPresent(t *testing.T) {
	base := func() *Node { return &Node{} }

	withLastChecked := base()
	withLastChecked.LastChecked = time.Now()
	withStatus := base()
	withStatus.Status = StatusOK
	withVerified := base()
	withVerified.LastVerifiedAt = 1
	withFailed := base()
	withFailed.LastFailedAt = 1

	for name, n := range map[string]*Node{
		"LastChecked":    withLastChecked,
		"Status":         withStatus,
		"LastVerifiedAt": withVerified,
		"LastFailedAt":   withFailed,
	} {
		if n.IsUnchecked() {
			t.Errorf("%s: узел с этим признаком НЕ должен быть IsUnchecked", name)
		}
	}
}

// ── LastOutcomeIsFailure ─────────────────────────────────────────────────────

func TestLastOutcomeIsFailure_Cases(t *testing.T) {
	cases := []struct {
		name           string
		verifiedAt     int64
		failedAt       int64
		wantIsFailure  bool
	}{
		{"никогда не проверялся", 0, 0, false},
		{"только подтверждён", 1000, 0, false},
		{"только провален", 0, 1000, true},
		{"провал позже подтверждения", 1000, 2000, true},
		{"подтверждение позже провала — реабилитирован", 2000, 1000, false},
		{"провал и подтверждение в один момент — считаем провалом (>=)", 1000, 1000, true},
	}
	for _, c := range cases {
		n := &Node{LastVerifiedAt: c.verifiedAt, LastFailedAt: c.failedAt}
		if got := n.LastOutcomeIsFailure(); got != c.wantIsFailure {
			t.Errorf("%s: LastOutcomeIsFailure()=%v, want %v", c.name, got, c.wantIsFailure)
		}
	}
}

// ── ProvenFreshness ──────────────────────────────────────────────────────────

func TestProvenFreshness_NeverVerified_IsZero(t *testing.T) {
	n := &Node{}
	if got := n.ProvenFreshness(2_000_000_000); got != 0 {
		t.Errorf("никогда не подтверждённый узел: ProvenFreshness=%v, want 0", got)
	}
}

func TestProvenFreshness_LessThanOneHour_IsOne(t *testing.T) {
	now := int64(2_000_000_000)
	n := &Node{LastVerifiedAt: now - 60} // минуту назад
	if got := n.ProvenFreshness(now); got != 1.0 {
		t.Errorf("подтверждение <1ч назад: ProvenFreshness=%v, want 1.0", got)
	}
}

func TestProvenFreshness_FutureOrEqualTimestamp_IsOne(t *testing.T) {
	// nowUnix <= LastVerifiedAt (часы устройства скакнули назад, либо тот же тик) — не должно
	// давать отрицательный возраст/панику, трактуем как «только что».
	n := &Node{LastVerifiedAt: 2_000_000_000}
	if got := n.ProvenFreshness(2_000_000_000); got != 1.0 {
		t.Errorf("now == LastVerifiedAt: ProvenFreshness=%v, want 1.0", got)
	}
	if got := n.ProvenFreshness(1_999_999_000); got != 1.0 {
		t.Errorf("now < LastVerifiedAt (часы назад): ProvenFreshness=%v, want 1.0", got)
	}
}

func TestProvenFreshness_24Hours_IsHalf(t *testing.T) {
	now := int64(2_000_000_000)
	n := &Node{LastVerifiedAt: now - 24*3600}
	if got := n.ProvenFreshness(now); got != 0.5 {
		t.Errorf("24ч назад: ProvenFreshness=%v, want 0.5", got)
	}
}

// Регрессия 2026-09-05: граница РОВНО 7 суток (168ч). Документированный контракт функции
// обещает «≈0.1 при 7 сутках», но до фикса код применял пол 0.1 только при ageH СТРОГО < 168 —
// ровно на границе получалось 0.5^7 ≈ 0.0078, то есть на порядок МЕНЬШЕ, чем за час до этого
// (167ч давали пол 0.1). Свежесть не может обвалиться на границе резче, чем внутри интервала.
func TestProvenFreshness_SevenDayBoundary_FloorApplies(t *testing.T) {
	now := int64(2_000_000_000)
	n167 := &Node{LastVerifiedAt: now - 167*3600}
	n168 := &Node{LastVerifiedAt: now - 168*3600}
	n169 := &Node{LastVerifiedAt: now - 169*3600}

	got167 := n167.ProvenFreshness(now)
	got168 := n168.ProvenFreshness(now)
	got169 := n169.ProvenFreshness(now)

	if got167 != 0.1 {
		t.Errorf("167ч (< 7 сут): ProvenFreshness=%v, want 0.1 (пол)", got167)
	}
	if got168 != 0.1 {
		t.Errorf("168ч (ровно 7 сут, документированный контракт '≈0.1 при 7 сутках'): ProvenFreshness=%v, want 0.1", got168)
	}
	// Дальше пола уже нет (за пределами 7 суток продолжается затухание без ограничения снизу) —
	// но падение НЕ должно быть больше одного шага по сравнению с границей.
	if got169 >= got168 {
		t.Errorf("169ч должно быть строго свежее... то есть МЕНЬШЕ веса, чем 168ч: got169=%v got168=%v", got169, got168)
	}
}

// Монотонность: чем старше подтверждение, тем меньше (или равен) вес — свежесть никогда не
// растёт со временем.
func TestProvenFreshness_Monotonic(t *testing.T) {
	now := int64(2_000_000_000)
	prev := 2.0 // заведомо больше максимума 1.0
	for hours := 0; hours <= 240; hours += 6 {
		n := &Node{LastVerifiedAt: now - int64(hours)*3600}
		got := n.ProvenFreshness(now)
		if got > prev+1e-9 {
			t.Fatalf("возраст %dч: freshness=%v выросло относительно предыдущего шага %v", hours, got, prev)
		}
		if got < 0 || got > 1 {
			t.Fatalf("возраст %dч: freshness=%v вне [0,1]", hours, got)
		}
		prev = got
	}
}

// ── NodeRefOf / NodeRef.Matches ──────────────────────────────────────────────

func TestNodeRefOf_Nil(t *testing.T) {
	if got := NodeRefOf(nil); got != (NodeRef{}) {
		t.Errorf("NodeRefOf(nil) = %+v, want zero value", got)
	}
}

func TestNodeRefOf_CopiesIdentifyingFields(t *testing.T) {
	n := &Node{ID: "id1", Protocol: ProtoVLESS, Address: "1.2.3.4", Port: 443, Name: "test",
		UUID: "should-not-be-copied"} // NodeRef не хранит секреты, только для переразрешения
	ref := NodeRefOf(n)
	if ref.ID != "id1" || ref.Protocol != ProtoVLESS || ref.Address != "1.2.3.4" || ref.Port != 443 || ref.Name != "test" {
		t.Errorf("NodeRefOf: %+v", ref)
	}
}

func TestNodeRef_Matches_ByID(t *testing.T) {
	ref := NodeRef{ID: "abc", Address: "9.9.9.9", Port: 1} // адрес/порт заведомо не совпадут
	n := &Node{ID: "abc", Address: "1.2.3.4", Port: 443}
	if !ref.Matches(n) {
		t.Error("совпадение по ID должно матчиться независимо от адреса/порта")
	}
}

// F2: если ID устарел (миграция схемы ID сменила хеш, см. parser.generateID), узел
// переразрешается по protocol/address/port — иначе PinnedNode/Favorites молча слетали бы
// при любой смене алгоритма ID.
func TestNodeRef_Matches_FallbackToAddressPortProtocol(t *testing.T) {
	ref := NodeRef{ID: "old-stale-id", Protocol: ProtoVLESS, Address: "1.2.3.4", Port: 443}
	n := &Node{ID: "new-id-after-migration", Protocol: ProtoVLESS, Address: "1.2.3.4", Port: 443}
	if !ref.Matches(n) {
		t.Error("устаревший ID должен переразрешаться по protocol+address+port")
	}
}

func TestNodeRef_Matches_ProtocolMismatchRejected(t *testing.T) {
	ref := NodeRef{ID: "old-id", Protocol: ProtoVLESS, Address: "1.2.3.4", Port: 443}
	n := &Node{ID: "new-id", Protocol: ProtoTrojan, Address: "1.2.3.4", Port: 443}
	if ref.Matches(n) {
		t.Error("тот же адрес/порт, но другой протокол — НЕ тот же узел (агрегаторы держат vless и trojan на одном IP)")
	}
}

func TestNodeRef_Matches_EmptyProtocolIsWildcard(t *testing.T) {
	// Protocol в ref пуст (например, ссылка сохранена до появления этого поля) — не
	// накладываем требование на протокол, матчим только по адресу/порту.
	ref := NodeRef{Address: "1.2.3.4", Port: 443}
	n := &Node{ID: "x", Protocol: ProtoTrojan, Address: "1.2.3.4", Port: 443}
	if !ref.Matches(n) {
		t.Error("пустой Protocol в ref не должен блокировать совпадение по адресу/порту")
	}
}

func TestNodeRef_Matches_NilNode(t *testing.T) {
	ref := NodeRef{ID: "x"}
	if ref.Matches(nil) {
		t.Error("Matches(nil) должен быть false, не паникой")
	}
}

func TestNodeRef_Matches_NoOverlapAtAll(t *testing.T) {
	ref := NodeRef{ID: "a", Address: "1.1.1.1", Port: 1}
	n := &Node{ID: "b", Address: "2.2.2.2", Port: 2}
	if ref.Matches(n) {
		t.Error("ни ID, ни адрес/порт не совпадают — не должно матчиться")
	}
}
