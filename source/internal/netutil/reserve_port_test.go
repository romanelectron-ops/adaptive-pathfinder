package netutil

import (
	"fmt"
	"net"
	"testing"
)

// TestReserveFreePort_ReturnsUsablePort проверяет, что порт, выданный ReserveFreePort,
// реально свободен и пригоден для последующего Listen — это единственная причина
// существования функции (windowsServerRunner/AndroidServerRunner узнают номер порта
// заранее, до запуска sing-box, см. комментарий в reserve_port.go). У функции раньше не
// было ни одного теста в пакете.
func TestReserveFreePort_ReturnsUsablePort(t *testing.T) {
	port, err := ReserveFreePort()
	if err != nil {
		t.Fatalf("ReserveFreePort: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("ReserveFreePort returned out-of-range port %d", port)
	}

	// Порт должен быть немедленно занимаемым — окно гонки принято (см. комментарий в
	// исходнике), но в тесте (без параллельных потребителей) он обязан быть свободен.
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %d reserved by ReserveFreePort is not actually usable: %v", port, err)
	}
	_ = ln.Close()
}

// TestReserveFreePort_ReturnsDistinctPortsUsuallyDiffer — последовательные вызовы не
// обязаны каждый раз отдавать один и тот же порт: ОС не переиспользует немедленно только
// что закрытый порт, пока в системе есть другие свободные. Проверяем, что функция не
// залипает на константе (что было бы симптомом сломанного net.Listen("...:0")).
func TestReserveFreePort_ReturnsDistinctPortsUsuallyDiffer(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 5; i++ {
		port, err := ReserveFreePort()
		if err != nil {
			t.Fatalf("ReserveFreePort iteration %d: %v", i, err)
		}
		seen[port] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected ReserveFreePort to return varying ports across 5 calls, got only %d distinct value(s): %v", len(seen), seen)
	}
}
