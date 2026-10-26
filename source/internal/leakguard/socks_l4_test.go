package leakguard

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/localauth/localauthtest"
)

// Лот L4: клиент SOCKS5 работает и с открытым входом (режимы прокси/гибрид), и с входом, защищённым
// паролем сессии (режим VPN): метод выбирает сервер, клиент отвечает логином/паролем из localauth.

func TestL4_LeakguardSOCKS5_OpenAndProtectedInbound(t *testing.T) {
	for _, requireAuth := range []bool{false, true} {
		srv := localauthtest.StartSOCKS5(t, requireAuth)
		conn, err := dialSOCKS5(context.Background(), srv.Addr, "198.51.100.5:53")
		if err != nil {
			t.Fatalf("requireAuth=%v: %v", requireAuth, err)
		}
		conn.Close()
		if got := srv.Connects(); len(got) != 1 || got[0] != "198.51.100.5:53" {
			t.Errorf("requireAuth=%v: CONNECT дошёл как %v", requireAuth, got)
		}
		if requireAuth && srv.AuthOK() != 1 {
			t.Errorf("пароль сессии не принят (ok=%d bad=%d)", srv.AuthOK(), srv.AuthBad())
		}
	}
}

// Сервер принял соединение и молчит: рукопожатие обязано оборваться по сроку контекста, а не висеть
// (Greet читает из соединения дважды и срок сам не ставит).
func TestL4_LeakguardSOCKS5_SilentServerHonoursContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // молчим до конца теста
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := dialSOCKS5(ctx, ln.Addr().String(), "198.51.100.5:53")
	if err == nil {
		conn.Close()
		t.Fatal("молчащий сервер принят за SOCKS5")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("рукопожатие висело %v при сроке контекста 300 мс", elapsed)
	}
}
