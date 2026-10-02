package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// [ревью 1.1.10, C3/F4] ExitClient.handleNewStream писал в журнал КАЖДЫЙ отказ DialLocal, в том
// числе штатный отказ лимита устройств, да ещё текстом «цель недоступна» — в обход
// лимитированного по частоте лога AdmissionProxy. Тесты идут через настоящий relay и настоящий
// AdmissionProxy (лимит в одно устройство), чтобы проверить не заглушку, а реальный путь.

// logSink — потокобезопасный сборщик строк журнала (OnLog зовётся из нескольких горутин).
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) add(s string) {
	l.mu.Lock()
	l.lines = append(l.lines, s)
	l.mu.Unlock()
}

// without возвращает строки, не содержащие ни один из подстрок skip (обычно — штатную строку
// про регистрацию EXIT, не относящуюся к проверяемому пути).
func (l *logSink) without(skip ...string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
lines:
	for _, s := range l.lines {
		for _, k := range skip {
			if strings.Contains(s, k) {
				continue lines
			}
		}
		out = append(out, s)
	}
	return out
}

func (l *logSink) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// startLoggingExitClient поднимает ExitClient с заданным DialLocal (nil — прямой dial на
// localTarget) и ждёт, пока он зарегистрируется на relay.
func startLoggingExitClient(t *testing.T, relayAddr, fingerprint, localTarget string,
	dialLocal func(ctx context.Context, sourceIP string) (net.Conn, error), sink *logSink) (exitID string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	c := NewExitClient(relayAddr, exitID, token, localTarget, fingerprint)
	c.OnLog = sink.add
	c.DialLocal = dialLocal
	go c.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !c.IsConnected() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !c.IsConnected() {
		t.Fatal("ExitClient не зарегистрировался")
	}
	return exitID
}

// knockUntilClosed — «Вход» стучится в relay и ждёт, пока сторона «Выхода» закроет поток.
// Строка журнала ExitClient (если она есть) пишется ДО закрытия relayConn, поэтому к моменту,
// когда «Вход» увидел закрытие, всё, что ExitClient собирался записать, уже записано — спать
// вслепую не нужно.
func knockUntilClosed(t *testing.T, relayAddr, fingerprint, exitID string) {
	t.Helper()
	// Сроки — с большим запасом: при насыщении CPU на Windows (замечание ревью 2026-09-30) TLS-дозвон
	// к relay на loopback занимал секунды, и жёсткие 3–5 с давали ложные падения без связи с логикой.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	entry, err := dialRelayTLS(ctx, relayAddr, fingerprint, 15*time.Second)
	if err != nil {
		t.Fatalf("dial relay (entry): %v", err)
	}
	defer entry.Close()
	if err := writeLine(entry, cmdEntry+" "+exitID); err != nil {
		t.Fatalf("write ENTRY: %v", err)
	}
	resp, err := readLine(entry, 20*time.Second)
	if err != nil || resp != cmdOK {
		t.Fatalf("ENTRY: ответ %q, ошибка %v — поток до «Выхода» не установился", resp, err)
	}
	entry.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := entry.Read(buf); err == nil {
		t.Fatal("ожидалось закрытие потока «Выходом», но пришли данные")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("поток не закрыт «Выходом» за 5 с")
	}
}

// Отказ по лимиту устройств не пишется ExitClient'ом ни разу — ни прямой, ни обёрнутый
// через %w (DialLocal в проде может добавлять контекст). AdmissionProxy при этом свой отказ
// в журнал пишет (один раз за минуту на устройство).
func TestExitClient_AdmissionRejection_NotLoggedByExitClient(t *testing.T) {
	cases := []struct {
		name string
		wrap func(error) error
	}{
		{"прямой", func(err error) error { return err }},
		{"обёрнутый через %w", func(err error) error { return fmt.Errorf("DialLocal: %w", err) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
			echoAddr := echoListener(t)

			proxy := singbox.NewAdmissionProxy(nil, echoAddr, 1, 0)
			var proxyLog logSink
			proxy.OnLog = proxyLog.add
			// Единственное место занимает посторонний «Вход»; relay отдаст «Выходу» адрес
			// 127.0.0.1 — другое устройство, значит, отказ по лимиту гарантирован.
			holder, err := proxy.AdmitAndDial(context.Background(), "198.51.100.10")
			if err != nil {
				t.Fatalf("занять место: %v", err)
			}
			defer holder.Close()

			var clientLog logSink
			exitID := startLoggingExitClient(t, relayAddr, fingerprint, "127.0.0.1:1",
				func(ctx context.Context, sourceIP string) (net.Conn, error) {
					conn, err := proxy.AdmitAndDial(ctx, sourceIP)
					if err != nil {
						return nil, tc.wrap(err)
					}
					return conn, nil
				}, &clientLog)

			const knocks = 3
			for i := 0; i < knocks; i++ {
				knockUntilClosed(t, relayAddr, fingerprint, exitID)
			}

			if extra := clientLog.without("зарегистрирован"); len(extra) != 0 {
				t.Errorf("ExitClient записал в журнал %d строк(и) на отказы по лимиту, ожидалось 0: %q", len(extra), extra)
			}
			if n := proxyLog.count("Лимит устройств"); n != 1 {
				t.Errorf("AdmissionProxy записал %d строк об отказе за %d стуков подряд, ожидалась 1 (лимит частоты)", n, knocks)
			}
		})
	}
}

// Прочие ошибки логируются — но текстом про реальную причину, а не «локальная цель недоступна»
// с адресом-заглушкой LocalTarget, куда при DialLocal никто не звонил.
func TestExitClient_OtherDialErrors_LoggedWithRealCause(t *testing.T) {
	t.Run("сбой DialLocal", func(t *testing.T) {
		relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
		var clientLog logSink
		exitID := startLoggingExitClient(t, relayAddr, fingerprint, "127.0.0.1:1",
			func(ctx context.Context, sourceIP string) (net.Conn, error) {
				return nil, errors.New("внутренний порт не отвечает")
			}, &clientLog)
		knockUntilClosed(t, relayAddr, fingerprint, exitID)

		lines := clientLog.without("зарегистрирован")
		if len(lines) != 1 {
			t.Fatalf("ожидалась ровно одна строка журнала о сбое, получено %d: %q", len(lines), lines)
		}
		if !strings.Contains(lines[0], "внутренней целью") || !strings.Contains(lines[0], "внутренний порт не отвечает") {
			t.Errorf("строка %q не называет реальную причину сбоя", lines[0])
		}
		if strings.Contains(lines[0], "локальная цель") || strings.Contains(lines[0], "127.0.0.1:1") {
			t.Errorf("строка %q вводит в заблуждение: при DialLocal LocalTarget никто не набирал", lines[0])
		}
	})

	t.Run("прямой dial без DialLocal", func(t *testing.T) {
		relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
		var clientLog logSink
		// Порт 1 закрыт — dial отказывает; здесь LocalTarget и есть реальная цель.
		exitID := startLoggingExitClient(t, relayAddr, fingerprint, "127.0.0.1:1", nil, &clientLog)
		knockUntilClosed(t, relayAddr, fingerprint, exitID)

		lines := clientLog.without("зарегистрирован")
		if len(lines) != 1 || !strings.Contains(lines[0], "локальная цель 127.0.0.1:1 недоступна") {
			t.Errorf("прямой dial: ожидалась строка «локальная цель 127.0.0.1:1 недоступна…», получено %q", lines)
		}
	})
}
