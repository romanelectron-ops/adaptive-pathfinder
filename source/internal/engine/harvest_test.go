package engine

// harvest_test.go — L5-ENG (ТЗ v1.4 §5). Проверяет движковую обвязку харвестера БЕЗ сети:
// диспетчеризацию кандидатов в parser.Parse* (с провенансом и recover-обёрткой) и single-flight
// ручного прохода. Сетевой путь (FetchRawBodies → harvester.Run) покрыт тестами пакетов
// sources и harvester; здесь — именно то, что добавляет движок.

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/harvester"
)

// TestHarvestCandidatesToNodes_DispatchAndProvenance — валидная ссылка узла превращается в узел с
// проставленным источником; мусор считается parseFailed; ссылка-подписка не парсится (subURLs);
// base64-блоб разбирается в несколько узлов.
func TestHarvestCandidatesToNodes_DispatchAndProvenance(t *testing.T) {
	srcName := map[string]string{"s1": "ИсточникОдин", "s2": "ИсточникДва"}

	blob := base64.StdEncoding.EncodeToString([]byte(
		"trojan://pass@b1.example.com:443#Blob1\nss://chacha20-ietf-poly1305:sec@1.2.3.4:8388#Blob2\n"))

	cands := []harvester.Candidate{
		{Kind: harvester.KindNodeURI, Normalized: "trojan://pass@t.example.com:443#OK", SourceID: "s1", Scheme: "trojan"},
		// ParseLink отвергает vmess с битым base64 (parser_extra_test.go) → parseFailed.
		{Kind: harvester.KindNodeURI, Normalized: "vmess://not!valid!base64!!!", SourceID: "s1", Scheme: "vmess"},
		{Kind: harvester.KindSubscriptionURL, Normalized: "https://example.com/sub.txt", SourceID: "s2"},
		{Kind: harvester.KindConfigBlob, Normalized: blob, SourceID: "s2"},
	}

	nodes, parsed, parseFailed, subURLs := harvestCandidatesToNodes(cands, srcName)

	if subURLs != 1 {
		t.Errorf("subURLs = %d, ожидалось 1 (ссылка-подписка не качается движком — I-1/дизайн)", subURLs)
	}
	if parseFailed != 1 {
		t.Errorf("parseFailed = %d, ожидалось 1 (мусорная vless://)", parseFailed)
	}
	// 1 одиночный узел + 2 из блоба = 3.
	if parsed != 3 || len(nodes) != 3 {
		t.Fatalf("parsed=%d len(nodes)=%d, ожидалось 3 (1 одиночный + 2 из base64-блоба)", parsed, len(nodes))
	}

	// Провенанс: одиночный узел получил имя своего источника.
	var singled *string
	for _, n := range nodes {
		if n.Address == "t.example.com" {
			s := n.Source
			singled = &s
		}
	}
	if singled == nil {
		t.Fatal("одиночный узел t.example.com не найден среди распознанных")
	}
	if *singled != "ИсточникОдин" {
		t.Errorf("Source = %q, ожидалось \"ИсточникОдин\" (провенанс по SourceID)", *singled)
	}
}

// TestHarvestCandidatesToNodes_Empty — пустой вход не паникует и даёт нули.
func TestHarvestCandidatesToNodes_Empty(t *testing.T) {
	nodes, parsed, parseFailed, subURLs := harvestCandidatesToNodes(nil, nil)
	if len(nodes) != 0 || parsed != 0 || parseFailed != 0 || subURLs != 0 {
		t.Errorf("пустой вход дал ненулевой результат: nodes=%d parsed=%d failed=%d sub=%d",
			len(nodes), parsed, parseFailed, subURLs)
	}
}

// TestHarvestNow_SingleFlight — пока идёт один проход (harvestActive держится), повторный вызов
// отбивается ErrHarvestBusy ДО любой сетевой активности.
func TestHarvestNow_SingleFlight(t *testing.T) {
	e := newTestEngine()
	if !e.harvestActive.CompareAndSwap(false, true) {
		t.Fatal("harvestActive обязан быть свободен в начале теста")
	}
	defer e.harvestActive.Store(false)

	_, err := e.HarvestNow(context.Background())
	if err != ErrHarvestBusy {
		t.Fatalf("ожидалась ErrHarvestBusy при идущем проходе, получено: %v", err)
	}
}

// TestSafeParseLink_RecoversAndParses — обёртка возвращает узел на валидной ссылке и ошибку (не
// панику) на мусоре.
func TestSafeParseLink_RecoversAndParses(t *testing.T) {
	n, err := safeParseLink("trojan://pass@ok.example.com:443#OK")
	if err != nil || n == nil {
		t.Fatalf("валидная ссылка не разобралась: n=%v err=%v", n, err)
	}
	if _, err := safeParseLink("vmess://not!valid!base64!!!"); err == nil {
		t.Error("мусорная ссылка должна вернуть ошибку, а не nil")
	}
}
