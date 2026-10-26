package localauth

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestCredentialsAreStableRandomAndDistinct(t *testing.T) {
	u1, p1 := Credentials()
	u2, p2 := Credentials()
	if u1 != u2 || p1 != p2 {
		t.Fatal("учётные данные должны быть стабильны в пределах процесса")
	}
	if len(p1) < 32 || len(ClashSecret()) < 32 {
		t.Errorf("пароль или секрет слишком короткие: %d / %d", len(p1), len(ClashSecret()))
	}
	if p1 == ClashSecret() {
		t.Error("пароль SOCKS и секрет Clash API должны быть разными")
	}
	if BearerHeader() != "Bearer "+ClashSecret() {
		t.Errorf("BearerHeader = %q", BearerHeader())
	}
}

// fakeServer имитирует сторону сервера SOCKS5: выбирает метод и (для 0x02) проверяет пароль.
func fakeServer(t *testing.T, chooseMethod byte, wantOK bool) (net.Conn, <-chan error) {
	t.Helper()
	c, s := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(3 * time.Second))
		hello := make([]byte, 4)
		if _, err := io.ReadFull(s, hello); err != nil {
			done <- err
			return
		}
		if hello[0] != 0x05 || hello[1] != 0x02 || hello[2] != 0x00 || hello[3] != 0x02 {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, _ = s.Write([]byte{0x05, chooseMethod})
		if chooseMethod != 0x02 {
			done <- nil
			return
		}
		head := make([]byte, 2)
		if _, err := io.ReadFull(s, head); err != nil {
			done <- err
			return
		}
		user := make([]byte, head[1])
		_, _ = io.ReadFull(s, user)
		plen := make([]byte, 1)
		_, _ = io.ReadFull(s, plen)
		pass := make([]byte, plen[0])
		_, _ = io.ReadFull(s, pass)
		u, p := Credentials()
		ok := string(user) == u && string(pass) == p
		if ok != wantOK {
			done <- io.ErrClosedPipe
			return
		}
		status := byte(0x00)
		if !ok {
			status = 0x01
		}
		_, _ = s.Write([]byte{0x01, status})
		done <- nil
	}()
	return c, done
}

func TestGreet_OpenServerNeedsNoPassword(t *testing.T) {
	c, done := fakeServer(t, 0x00, true)
	defer c.Close()
	if err := Greet(c); err != nil {
		t.Fatalf("Greet с открытым входом: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}

func TestGreet_ProtectedServerGetsSessionPassword(t *testing.T) {
	c, done := fakeServer(t, 0x02, true)
	defer c.Close()
	if err := Greet(c); err != nil {
		t.Fatalf("Greet с защищённым входом: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("сервер не получил верный пароль: %v", err)
	}
}

func TestGreet_UnsupportedMethodIsAnError(t *testing.T) {
	c, _ := fakeServer(t, 0xFF, true)
	defer c.Close()
	if err := Greet(c); err == nil {
		t.Fatal("метод 0xFF (нет приемлемых) должен давать ошибку")
	}
}
