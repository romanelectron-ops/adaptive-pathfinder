// engine_v13_f4_speed_test.go — ТЗ v1.3 F4 (просьба пользователя 2026-09-05: «не забудь
// проверить скорость поиска и подбора рабочего узла и подключения»): connectTopCandidates
// обязан пробовать не больше connectTopK кандидатов и не дольше connectBudget — до этого теста
// ни один тест это не проверял (grep connectTopK/connectBudget по *_test.go давал 0 совпадений).
// connectTopK/connectBudget были const; переведены в var тем же приёмом, что уже применён к
// scanBatchLimit/sweepBatchSize/nodesSaveDebounce/autoSweepDelay, специально ради этих тестов.
package engine

import (
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// badNode — узел, для которого connectNode гарантированно и МГНОВЕННО проваливается без
// единой сетевой операции: AmneziaWG — единственный протокол, который nodeToOutbound
// (internal/singbox/config_builder.go) отвергает безусловно, независимо от заполненных полей,
// ещё до создания реального sing-box инстанса или обращения к сети.
func badNode(id string, score float64) *models.Node {
	return &models.Node{ID: id, Name: id, Address: "10.0.0.9", Port: 51820,
		Protocol: models.ProtoAmneziaWG, Status: models.StatusOK, Score: score}
}

// F4 ND-6: connectTopCandidates не должен трогать кандидатов за пределами connectTopK, даже
// если их в списке заведомо больше — иначе «top-K» ничего не ограничивает на практике.
func TestConnectTopCandidates_RespectsTopKLimit(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	prevK := connectTopK
	connectTopK = 3
	t.Cleanup(func() { connectTopK = prevK })

	nodes := make([]*models.Node, 0, 8)
	for i := 0; i < 8; i++ {
		nodes = append(nodes, badNode(string(rune('a'+i)), 1.0-float64(i)*0.01))
	}

	if err := e.connectTopCandidates(nodes, "test"); err == nil {
		t.Fatal("все кандидаты нерабочие — ошибка ожидалась")
	}

	tried := 0
	for _, n := range nodes {
		if logs.has("Подключение к «" + n.Name + "» не удалось") {
			tried++
		}
	}
	if tried != connectTopK {
		t.Fatalf("должно быть испробовано ровно connectTopK=%d кандидатов, испробовано %d: %v",
			connectTopK, tried, logs.all())
	}
	for i := 0; i < connectTopK; i++ {
		if !logs.has("Подключение к «" + nodes[i].Name + "» не удалось") {
			t.Errorf("кандидат %s из первых %d должен был быть испробован: %v", nodes[i].Name, connectTopK, logs.all())
		}
	}
	for i := connectTopK; i < len(nodes); i++ {
		if logs.has("Подключение к «" + nodes[i].Name + "» не удалось") {
			t.Errorf("кандидат %s за пределами connectTopK не должен был пробоваться: %v", nodes[i].Name, logs.all())
		}
	}
}

// F4 ND-6: истёкший бюджет времени обязан оборвать перебор кандидатов НЕМЕДЛЕННО, до попытки
// подключения к следующему — иначе бюджет был бы декларативным и «ищет часами» (R2) осталось бы
// возможным даже после top-K фикса.
func TestConnectTopCandidates_BudgetDeadlineStopsLoop(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	prevBudget := connectBudget
	connectBudget = -1 * time.Second // дедлайн уже в прошлом до первой же проверки
	t.Cleanup(func() { connectBudget = prevBudget })

	nodes := []*models.Node{badNode("x", 1), badNode("y", 0.9)}
	err := e.connectTopCandidates(nodes, "test")
	if err == nil {
		t.Fatal("ошибка ожидалась — ни один кандидат не должен был пробоваться")
	}
	if err.Error() != "no connectable candidates" {
		t.Errorf("с немедленно истёкшим бюджетом ни один кандидат не пробуется — ожидалась исходная ошибка, получено: %v", err)
	}
	if !logs.has("на попытки подключения исчерпан") {
		t.Errorf("должен быть лог об исчерпании бюджета: %v", logs.all())
	}
	if logs.has("Подключение к") {
		t.Errorf("с истёкшим бюджетом connectNode не должен вызываться вообще: %v", logs.all())
	}
}

// Контрольный сценарий: рабочий бюджет (не истёкший) обязан по-прежнему позволять перебор —
// предыдущий тест не должен был случайно сломать нормальный путь.
func TestConnectTopCandidates_HealthyBudgetStillTriesCandidates(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	nodes := []*models.Node{badNode("p", 1), badNode("q", 0.9)}
	if err := e.connectTopCandidates(nodes, "test"); err == nil {
		t.Fatal("оба кандидата нерабочие — ошибка ожидалась")
	}
	if !logs.has("Подключение к «p» не удалось") || !logs.has("Подключение к «q» не удалось") {
		t.Errorf("с нормальным бюджетом оба кандидата должны были пробоваться: %v", logs.all())
	}
}
