package androidbridge

import (
	"strings"
	"testing"
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
