package checker

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/localauth/localauthtest"
)

// Лот L4: клиент SOCKS5 работает и с открытым входом (режимы прокси/гибрид), и с входом, защищённым
// паролем сессии (режим VPN): метод выбирает сервер, клиент отвечает логином/паролем из localauth.

func TestL4_CheckerSOCKS5_OpenAndProtectedInbound(t *testing.T) {
	for _, requireAuth := range []bool{false, true} {
		srv := localauthtest.StartSOCKS5(t, requireAuth)
		conn, err := dialViaSOCKS5(context.Background(), srv.Addr, "example.org:80", 2*time.Second)
		if err != nil {
			t.Fatalf("requireAuth=%v: %v", requireAuth, err)
		}
		conn.Close()
		if got := srv.Connects(); len(got) != 1 || got[0] != "example.org:80" {
			t.Errorf("requireAuth=%v: CONNECT дошёл как %v", requireAuth, got)
		}
		if requireAuth && srv.AuthOK() != 1 {
			t.Errorf("пароль сессии не принят (ok=%d bad=%d)", srv.AuthOK(), srv.AuthBad())
		}
	}
}
