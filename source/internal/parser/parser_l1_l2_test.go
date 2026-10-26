package parser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Лоты L1 и L2. Данные СИНТЕТИЧЕСКИЕ: адреса из документационных диапазонов RFC 5737, UUID и
// ключи выдуманные. Настоящие списки в тестах не используются.

const l12PBK = "SYNTHETICPUBLICKEYSYNTHETICPUBLICKEY000"

func vlessReality(host string, port int, fp, typ string) string {
	return fmt.Sprintf("vless://00000000-0000-4000-8000-0000000000aa@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.org&fp=%s&pbk=%s&sid=ab12&type=%s#n", host, port, fp, l12PBK, typ)
}

// L1: type=raw - это обычный TCP под новым именем; узел валиден и без транспорта.
func TestL1_RawTransportIsPlainTCP(t *testing.T) {
	for _, typ := range []string{"raw", "RAW", "tcp"} {
		n, err := ParseLink(vlessReality("192.0.2.1", 443, "chrome", typ))
		if err != nil {
			t.Fatalf("type=%s: %v", typ, err)
		}
		if n.Transport != nil {
			t.Errorf("type=%s: у обычного TCP не должно быть Transport, получено %+v", typ, n.Transport)
		}
		if err := models.ValidateNode(n); err != nil {
			t.Errorf("type=%s: узел должен быть валиден: %v", typ, err)
		}
	}
	// raw и tcp - ОДИН и тот же узел (один ID).
	a, _ := ParseLink(vlessReality("192.0.2.1", 443, "chrome", "raw"))
	b, _ := ParseLink(vlessReality("192.0.2.1", 443, "chrome", "tcp"))
	if a.ID != b.ID {
		t.Errorf("raw и tcp дали разные ID: %s / %s", a.ID, b.ID)
	}
}

func TestL1_RawAndH2InOtherProtocols(t *testing.T) {
	tr, err := ParseLink("trojan://synthetic-password@192.0.2.5:443?security=tls&sni=example.org&type=raw#t")
	if err != nil || tr.Transport != nil {
		t.Fatalf("trojan type=raw: node=%+v err=%v", tr, err)
	}
	h2, err := ParseLink(vlessReality("192.0.2.6", 443, "chrome", "h2"))
	if err != nil || h2.Transport == nil || h2.Transport.Type != "http" {
		t.Fatalf("h2 должен превращаться в http: node=%+v err=%v", h2, err)
	}
}

// L1: транспорты, которых нет в ядре, получают честную причину.
func TestL1_UnsupportedTransportsGetAReason(t *testing.T) {
	cases := map[string]string{"xhttp": "XHTTP", "splithttp": "XHTTP", "kcp": "mKCP", "mkcp": "mKCP"}
	for typ, label := range cases {
		n, err := ParseLink(vlessReality("192.0.2.7", 443, "chrome", typ))
		if err != nil {
			t.Fatalf("type=%s: парсер не должен падать: %v", typ, err)
		}
		if got := models.UnsupportedTransport(n); !strings.Contains(got, label) {
			t.Errorf("type=%s: UnsupportedTransport=%q, ожидалось содержащее %q", typ, got, label)
		}
		err = models.ValidateNode(n)
		if err == nil || !strings.Contains(err.Error(), "not supported by this build") {
			t.Errorf("type=%s: ValidateNode должен назвать причину, получено %v", typ, err)
		}
	}
	// Поддерживаемые транспорты не затронуты.
	for _, typ := range []string{"ws", "grpc", "http"} {
		n, _ := ParseLink(vlessReality("192.0.2.8", 443, "chrome", typ))
		if models.UnsupportedTransport(n) != "" {
			t.Errorf("type=%s ошибочно помечен неподдерживаемым", typ)
		}
	}
}

// L2: ID не зависит от fp, но по-прежнему различает серверы и ключи.
func TestL2_IdentityIgnoresFingerprintButNotKeysOrServers(t *testing.T) {
	var first string
	for _, fp := range []string{"chrome", "firefox", "safari", "ios", "android"} {
		n, err := ParseLink(vlessReality("192.0.2.9", 443, fp, "tcp"))
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = n.ID
		} else if n.ID != first {
			t.Errorf("fp=%s дал другой ID: %s вместо %s", fp, n.ID, first)
		}
	}
	other, _ := ParseLink(vlessReality("192.0.2.10", 443, "chrome", "tcp"))
	if other.ID == first {
		t.Error("разные серверы получили один ID")
	}
	rekeyed, _ := ParseLink(strings.Replace(vlessReality("192.0.2.9", 443, "chrome", "tcp"), l12PBK, "OTHERSYNTHETICKEYOTHERSYNTHETICKEY000", 1))
	if rekeyed.ID == first {
		t.Error("смена ключа Reality должна менять ID (иначе остаётся узел со старым нерабочим ключом)")
	}
}

// L2: ID TLS-узлов БЕЗ fp не меняются (формула побайтно совпадает со старой), меняются только
// у узлов, где fp был. LegacyNodeID воспроизводит старую схему.
func TestL2_IDsOfNodesWithoutFingerprintAreUnchanged(t *testing.T) {
	noFP, _ := ParseLink(strings.Replace(vlessReality("192.0.2.11", 443, "chrome", "tcp"), "&fp=chrome", "", 1))
	if noFP.TLS == nil || noFP.TLS.Fingerprint != "" {
		t.Fatalf("fp не должен быть задан: %+v", noFP.TLS)
	}
	if noFP.ID != LegacyNodeID(noFP) {
		t.Errorf("у узла без fp новый ID %s обязан совпасть со старым %s", noFP.ID, LegacyNodeID(noFP))
	}
	withFP, _ := ParseLink(vlessReality("192.0.2.11", 443, "chrome", "tcp"))
	if withFP.ID == LegacyNodeID(withFP) {
		t.Error("у узла с fp новый ID должен отличаться от старого")
	}
	// Старая схема различала варианты fp - именно из-за неё пул раздувался.
	other, _ := ParseLink(vlessReality("192.0.2.11", 443, "firefox", "tcp"))
	if LegacyNodeID(withFP) == LegacyNodeID(other) {
		t.Error("LegacyNodeID должен учитывать fp")
	}
	// Узлы без TLS: обе схемы совпадают.
	ss, _ := ParseLink("ss://YWVzLTI1Ni1nY206c3ludGhldGljLXBhc3N3b3Jk@192.0.2.12:8388#ss")
	if ss.ID != LegacyNodeID(ss) {
		t.Error("у узла без TLS ID не должен меняться")
	}
}

// Критерий приёмки L2: 55 строк (11 серверов x 5 fp) дают 11 узлов, у каждого 5 отпечатков.
func TestL2_FiftyFiveLinesCollapseToElevenNodes(t *testing.T) {
	fps := []string{"chrome", "firefox", "safari", "ios", "android"}
	var lines []string
	for s := 1; s <= 11; s++ {
		for _, fp := range fps {
			lines = append(lines, vlessReality(fmt.Sprintf("192.0.2.%d", s), 443, fp, "raw"))
		}
	}
	nodes, err := ParseSubscription([]byte(strings.Join(lines, "\n")))
	if err != nil || len(nodes) != 55 {
		t.Fatalf("разобрано %d строк, err=%v", len(nodes), err)
	}
	byID := map[string]*models.Node{}
	for _, n := range nodes {
		if kept := byID[n.ID]; kept != nil {
			kept.MergeFingerprints(n)
			continue
		}
		byID[n.ID] = n
	}
	if len(byID) != 11 {
		t.Fatalf("узлов %d, ожидалось 11", len(byID))
	}
	for _, n := range byID {
		if len(n.FPCandidates) != 5 {
			t.Errorf("узел %s: отпечатков %d, ожидалось 5: %v", n.Address, len(n.FPCandidates), n.FPCandidates)
		}
		if n.FPCandidates[0] != "chrome" {
			t.Errorf("первым должен идти собственный отпечаток узла: %v", n.FPCandidates)
		}
	}
}

// U-07: страна по флаг-эмодзи; имя («Egypt») раньше давало пустой ответ.
func TestU07_CountryFromFlagEmoji(t *testing.T) {
	cases := map[string]string{
		"🇪🇬 Egypt | [*CIDR]": "EG",
		"🇩🇪 Germany":         "DE",
		"Server 🇳🇱 fast":     "NL",
		"🇺🇸🇬🇧 mixed":         "US",
		// Не страны: флаги ЕС и ООН. Иначе «EU» вечно давало ложное «⚠ не совпадает» с фактическим выходом.
		"🇪🇺 Europe":  "",
		"🇺🇳 UN node": "",
	}
	for name, want := range cases {
		if got := (&models.Node{Name: name}).CatalogCountry(); got != want {
			t.Errorf("CatalogCountry(%q) = %q, ожидалось %q", name, got, want)
		}
	}
	// Прежнее поведение: без флага - пара заглавных букв, слова вроде RELAY/TOR не страны.
	if got := (&models.Node{Name: "US-West-1"}).CatalogCountry(); got != "US" {
		t.Errorf("пара букв без флага: %q", got)
	}
	if got := (&models.Node{Name: "RELAY node"}).CatalogCountry(); got != "" {
		t.Errorf("слово RELAY принято за страну: %q", got)
	}
}
