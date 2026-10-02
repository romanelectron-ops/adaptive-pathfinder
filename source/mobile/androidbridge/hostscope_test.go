package androidbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/relay"
)

// TestLinkHostWarning_Delegates — мост не должен подменять классификацию своей: он обязан
// отдавать ровно то, что решает netutil.LinkHostWarning (подробные таблицы — в
// internal/netutil/hostscope_test.go). Здесь проверяем только сам экспорт: приватный хост даёт
// непустое предупреждение с упоминанием LAN, публичный IP и имя хоста — пустую строку.
func TestLinkHostWarning_Delegates(t *testing.T) {
	if w := LinkHostWarning("10.0.0.37"); !strings.Contains(w, "LAN") {
		t.Errorf("для приватного 10.0.0.37 ожидалось предупреждение про LAN, получено %q", w)
	}
	if w := LinkHostWarning("127.0.0.1"); !strings.Contains(w, "loopback") {
		t.Errorf("для 127.0.0.1 ожидалось предупреждение про loopback, получено %q", w)
	}
	for _, host := range []string{"8.8.8.8", "example.com", ""} {
		if w := LinkHostWarning(host); w != "" {
			t.Errorf("для %q предупреждать не о чем, получено %q", host, w)
		}
	}
}

// Новые классы netutil (тест-диапазон 198.18/15, multicast, зарезервированный 240/4,
// «*.localhost») доходят через мост без изменений — мост ничего не перекрывает.
func TestLinkHostWarning_DelegatesNewClasses(t *testing.T) {
	for host, sub := range map[string]string{
		"198.18.0.1":      "198.18.0.0/15",
		"224.0.0.251":     "multicast",
		"240.0.0.1":       "240.0.0.0/4",
		"vpn.localhost":   "loopback",
		"localhost.":      "loopback",
		"100.64.0.1":      "Tailscale", // CGNAT-фраза допускает оверлейные сети
		"192.168.1.5":     "Tailscale", // LAN-фраза — тоже
		"fe80::1%wlan0":   "LAN",
		"::ffff:10.0.0.1": "LAN",
	} {
		if w := LinkHostWarning(host); !strings.Contains(w, sub) {
			t.Errorf("LinkHostWarning(%q) = %q, ожидалась подстрока %q", host, w, sub)
		}
	}
}

// fakeReachability — заглушка relay.Reachability: настоящий Detect бьёт в SSDP/STUN.
type fakeReachability struct {
	method relay.Method
	host   string
	port   int
	ok     bool
}

func (f *fakeReachability) Detect(context.Context, int) (relay.Method, error) { return f.method, nil }
func (f *fakeReachability) Explain(m relay.Method) string {
	return relay.NewReachability().Explain(m) // настоящий текст: проверяем его в составе JSON
}
func (f *fakeReachability) ExternalAddress() (string, int, bool) { return f.host, f.port, f.ok }

// method=5 (MethodUndetermined) — новый исход Detect: ни один путь не дал адреса. Контракт для
// Kotlin: has_address=false, external_host="", external_port=0, explanation непустой и не
// про «проброс порта на роутере». Числа 0..4 остались прежними.
func TestDetectReachabilityJSON_Undetermined_NoAddress(t *testing.T) {
	out := detectReachabilityWith(context.Background(), &fakeReachability{method: relay.MethodUndetermined}, 8443)

	var got struct {
		Method       int    `json:"method"`
		Explanation  string `json:"explanation"`
		ExternalHost string `json:"external_host"`
		ExternalPort int    `json:"external_port"`
		HasAddress   bool   `json:"has_address"`
		Error        string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("ответ %q не разбирается как JSON: %v", out, err)
	}
	if got.Error != "" {
		t.Fatalf("неожиданная ошибка в ответе: %q", got.Error)
	}
	if got.Method != 5 {
		t.Errorf("method = %d, ожидалось 5 (MethodUndetermined)", got.Method)
	}
	if got.HasAddress || got.ExternalHost != "" || got.ExternalPort != 0 {
		t.Errorf("has_address=%v external_host=%q external_port=%d, ожидалось false/\"\"/0", got.HasAddress, got.ExternalHost, got.ExternalPort)
	}
	if !strings.Contains(got.Explanation, "Не удалось определить внешний адрес") {
		t.Errorf("explanation = %q, ожидалась фраза про «не удалось определить внешний адрес»", got.Explanation)
	}
}

// Прежние исходы сериализуются как раньше: числа 1..4 и адрес при has_address=true.
func TestDetectReachabilityJSON_PreviousMethodsUnchanged(t *testing.T) {
	for _, c := range []struct {
		m    relay.Method
		want int
	}{
		{relay.MethodDirect, 1}, {relay.MethodUPnP, 2}, {relay.MethodManualPort, 3}, {relay.MethodRelay, 4},
	} {
		out := detectReachabilityWith(context.Background(),
			&fakeReachability{method: c.m, host: "203.0.113.42", port: 8443, ok: true}, 8443)
		var got map[string]interface{}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("ответ %q не разбирается: %v", out, err)
		}
		if int(got["method"].(float64)) != c.want {
			t.Errorf("method для %v = %v, ожидалось %d", c.m, got["method"], c.want)
		}
		if got["has_address"] != true || got["external_host"] != "203.0.113.42" {
			t.Errorf("для %v адрес потерян: %v", c.m, got)
		}
	}
}

// GetLocalIPCandidatesJSON на настоящей машине: link-local (169.254/16) и 0.0.0.0 не должны
// попадать в список на любой конфигурации; формат элементов прежний (ip, interface_name).
func TestGetLocalIPCandidatesJSON_NoLinkLocalNoUnspecified(t *testing.T) {
	var cands []map[string]string
	if err := json.Unmarshal([]byte(GetLocalIPCandidatesJSON()), &cands); err != nil {
		t.Fatalf("не парсится как массив объектов: %v", err)
	}
	for _, c := range cands {
		ip, ok := c["ip"]
		if !ok {
			t.Errorf("элемент %v без поля ip", c)
			continue
		}
		if _, ok := c["interface_name"]; !ok {
			t.Errorf("элемент %v без поля interface_name", c)
		}
		if strings.HasPrefix(ip, "169.254.") || ip == "0.0.0.0" {
			t.Errorf("в кандидатах адрес %s — link-local/unspecified не годятся в «Хост»", ip)
		}
	}
}
