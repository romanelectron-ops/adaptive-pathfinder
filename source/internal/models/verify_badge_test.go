// verify_badge_test.go — общий контракт значков проверенности узла и состояний проверки
// канала (2026-09-06). Контракт написан оркестратором до раздачи лотов волны 2 именно потому,
// что его потребляют три независимых UI (Web, Wails, Android) — разойдись они в условиях,
// пользователь увидел бы в трёх местах три разных ответа про один и тот же узел.
package models

import (
	"testing"
	"time"
)

func TestVerifyBadge_AllStates(t *testing.T) {
	now := time.Now().Unix()
	hour := int64(3600)

	cases := []struct {
		name string
		node *Node
		want string
	}{
		{"nil-узел безопасен", nil, BadgeUnchecked},
		{"нулевой узел — не проверен", &Node{}, BadgeUnchecked},
		{
			"подтверждён час назад — свежий",
			&Node{Status: StatusOK, VerifiedCount: 1, LastVerifiedAt: now - hour},
			BadgeProvenFresh,
		},
		{
			"подтверждён 3 суток назад — давний",
			&Node{Status: StatusOK, VerifiedCount: 1, LastVerifiedAt: now - 72*hour},
			BadgeProvenStale,
		},
		{
			"подтверждался, но последний исход — сбой",
			&Node{Status: StatusOK, VerifiedCount: 1, LastVerifiedAt: now - hour, LastFailedAt: now - 60},
			BadgeProvenFailed,
		},
		{
			"TCP отвечает, трафик не проверялся",
			&Node{Status: StatusOK, LastChecked: time.Now()},
			BadgeTCPAlive,
		},
		{
			"медленный, но живой по TCP — тоже tcp_alive",
			&Node{Status: StatusSlow, LastChecked: time.Now()},
			BadgeTCPAlive,
		},
		{
			"проверялся и не отвечает — мёртв",
			&Node{Status: StatusBlocked, LastChecked: time.Now()},
			BadgeDead,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.node.VerifyBadge(now); got != c.want {
				t.Errorf("VerifyBadge() = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Ключевой смысловой инвариант, ради которого значок и вводится: узел, который прошёл только
// TCP-скан (а это подавляющее большинство пула — обычный обход Verified*-полей не пишет),
// обязан честно показываться как «трафик не проверялся», а НЕ как «трафика нет» и не как
// «проверен». Если этот тест когда-нибудь покраснеет — значок начал врать пользователю.
func TestVerifyBadge_TCPScanNeverClaimsProven(t *testing.T) {
	now := time.Now().Unix()
	// Ровно то, что оставляет после себя checker.CheckOne: статус, задержка, время проверки.
	// Verified*-полей нет — их обычный скан не пишет.
	scanned := &Node{Status: StatusOK, Latency: 42, LastChecked: time.Now()}

	if got := scanned.VerifyBadge(now); got != BadgeTCPAlive {
		t.Fatalf("узел после TCP-скана = %q, ожидалось %q", got, BadgeTCPAlive)
	}
	if scanned.IsProven() {
		t.Error("TCP-скан не должен делать узел proven")
	}
}

// Пользовательский бан не должен подменять собой значок трафика: это отдельный маркер, и
// забаненный узел, который раньше реально пропускал трафик, не превращается в «мёртвый».
func TestVerifyBadge_UserBanIsSeparateMarker(t *testing.T) {
	now := time.Now().Unix()
	banned := &Node{Status: StatusOK, VerifiedCount: 3, LastVerifiedAt: now - 3600, UserBanned: true}

	if got := banned.VerifyBadge(now); got != BadgeTCPAlive {
		t.Errorf("забаненный, но живой по TCP узел = %q, ожидалось %q (бан рисуется отдельно)", got, BadgeTCPAlive)
	}
}

// Граница «свежо/давно» проходит ровно по полураспаду ProvenFreshness (~24 ч). Проверяем обе
// стороны границы, чтобы будущая правка ProvenFreshness не сдвинула значок молча.
func TestVerifyBadge_FreshnessBoundary(t *testing.T) {
	now := time.Now().Unix()

	justUnder := &Node{Status: StatusOK, VerifiedCount: 1, LastVerifiedAt: now - 23*3600}
	if got := justUnder.VerifyBadge(now); got != BadgeProvenFresh {
		t.Errorf("23 часа = %q, ожидалось %q", got, BadgeProvenFresh)
	}

	wellOver := &Node{Status: StatusOK, VerifiedCount: 1, LastVerifiedAt: now - 49*3600}
	if got := wellOver.VerifyBadge(now); got != BadgeProvenStale {
		t.Errorf("49 часов = %q, ожидалось %q", got, BadgeProvenStale)
	}
}

func TestVerifyStateConstants_AreDistinct(t *testing.T) {
	all := []string{VerifyIdle, VerifyChecking, VerifyVerified, VerifyFailed}
	seen := make(map[string]bool, len(all))
	for _, v := range all {
		if v == "" {
			t.Error("пустая строка не может быть состоянием: omitempty съест её в JSON")
		}
		if seen[v] {
			t.Errorf("дубликат состояния %q — UI не сможет их различить", v)
		}
		seen[v] = true
	}
}
