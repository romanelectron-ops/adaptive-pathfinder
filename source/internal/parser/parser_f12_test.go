package parser

import "testing"

// B-12.1 — ParseCatalogContent: единая точка разбора контента провайдера каталога
// (F-12 / T-12). Подключает ранее изолированный ParseClashYAML и чинит nomore-walls=0.

const clashYAMLFixture = `
proxies:
  - name: MySS
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret123
`

// (1) Позитив: Clash YAML (формат nomore-walls .yml) → узлы > 0 (раньше было 0).
func TestParseCatalogContent_ClashYAML(t *testing.T) {
	nodes, err := ParseCatalogContent([]byte(clashYAMLFixture))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("Clash YAML must yield nodes (T-12: nomore-walls must be > 0)")
	}
}

// (4) Инвариант/стойкость: для не-YAML контента результат идентичен ParseSubscription
// (не регрессируем существующих провайдеров).
func TestParseCatalogContent_SubscriptionUnchanged(t *testing.T) {
	sub := []byte("ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#Node1\n")
	want, _ := ParseSubscription(sub)
	got, err := ParseCatalogContent(sub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("dispatcher changed subscription result: got %d want %d", len(got), len(want))
	}
}

// (4) Стойкость: непустой мусор без ключа proxies: → 0 узлов, без ошибки/паники.
func TestParseCatalogContent_GarbageNoCrash(t *testing.T) {
	got, err := ParseCatalogContent([]byte("just some random text\nno markers here\n"))
	if err != nil {
		t.Fatalf("garbage must not error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("garbage must yield 0 nodes, got %d", len(got))
	}
}

// looksLikeClashYAML: распознаёт ключ proxies:, не путает с link-списком.
func TestLooksLikeClashYAML(t *testing.T) {
	if !looksLikeClashYAML([]byte("proxies:\n  - name: x")) {
		t.Error("must detect proxies: marker")
	}
	if looksLikeClashYAML([]byte("vless://abc\nvmess://def\n")) {
		t.Error("must not flag a link list as Clash YAML")
	}
}
