package netutil

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestSplice_BidirectionalCopyAndClose проверяет основной контракт Splice: байты, отправленные
// с каждой из сторон пары соединений, доходят до другой стороны, и когда обе половины
// исчерпаны (EOF), Splice закрывает оба соединения и возвращается. Splice используется в
// internal/relay (Entry↔Stream и т.п.) и internal/singbox/admission_proxy.go — ни разу не
// было покрыто тестом в этом пакете, где оно фактически определено.
func TestSplice_BidirectionalCopyAndClose(t *testing.T) {
	aServer, aClient := net.Pipe()
	bServer, bClient := net.Pipe()

	done := make(chan struct{})
	go func() {
		Splice(aServer, bServer)
		close(done)
	}()

	// Клиент "A" пишет клиенту "B" через Splice(aServer, bServer): a→b копирует aServer.Read
	// в bServer.Write, то есть то, что пишет aClient, должно быть прочитано bClient.
	const msgAtoB = "hello from A"
	const msgBtoA = "hello from B"

	writeErrs := make(chan error, 2)
	go func() { _, err := aClient.Write([]byte(msgAtoB)); writeErrs <- err }()
	go func() { _, err := bClient.Write([]byte(msgBtoA)); writeErrs <- err }()

	bufFromA := make([]byte, len(msgBtoA))
	if _, err := io.ReadFull(aClient, bufFromA); err != nil {
		t.Fatalf("aClient did not receive B's message via Splice: %v", err)
	}
	if !bytes.Equal(bufFromA, []byte(msgBtoA)) {
		t.Errorf("aClient got %q, want %q", bufFromA, msgBtoA)
	}

	bufFromB := make([]byte, len(msgAtoB))
	if _, err := io.ReadFull(bClient, bufFromB); err != nil {
		t.Fatalf("bClient did not receive A's message via Splice: %v", err)
	}
	if !bytes.Equal(bufFromB, []byte(msgAtoB)) {
		t.Errorf("bClient got %q, want %q", bufFromB, msgAtoB)
	}

	for i := 0; i < 2; i++ {
		if err := <-writeErrs; err != nil {
			t.Errorf("write into pipe failed: %v", err)
		}
	}

	// Закрываем оба клиентских конца → обе копирующие горутины внутри Splice получат EOF/
	// ошибку записи и завершатся, Splice обязан закрыть aServer/bServer и вернуться.
	_ = aClient.Close()
	_ = bClient.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Splice did not return after both ends closed — bidirectional copy did not terminate")
	}

	// aServer/bServer должны быть закрыты Splice — повторная запись обязана вернуть ошибку.
	if _, err := aServer.Write([]byte("x")); err == nil {
		t.Error("Splice must close its connections when done, but aServer.Write succeeded")
	}
}
