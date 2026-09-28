package relay

// exit_register_race_test.go — P9 (аудит BLACKBOX_2026-09-07, находки A2/B3 #10) в
// RelayServer.handleExit:
//
//	(а) TOCTOU. Существование exit-id проверялось под RLock (`existing, known := s.exits[exitID]`),
//	    а финальная регистрация делалась ПОЗЖЕ, под отдельным Lock. Два одновременных EXIT с
//	    ОДНИМ И ТЕМ ЖЕ новым exit-id и РАЗНЫМИ токенами оба видели `known == false`, оба шли
//	    по TOFU-пути и оба регистрировались — побеждал тот, кто писал в карту последним. То
//	    есть ровно та дыра захвата exit-id, которую закрывали в exit_hijack_test.go, но в
//	    другом окне: не «пока владелец офлайн», а «пока владелец ещё регистрируется».
//	(б) Гонка данных. `existing.sess` читался вне какой-либо блокировки, тогда как
//	    disconnectExitSession пишет `b.sess = nil` под s.mu.Lock.
//
// Оба теста работают с handleExit напрямую через net.Pipe: нужны точные одновременные
// вызовы, чего TLS-дозвон через реальный listener не даёт.

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// raceTestServer — RelayServer без listener'а, с заведомо не мешающим rate-limiter'ом
// (проверяется отдельными тестами) и молчаливым логом.
func raceTestServer() *RelayServer {
	return NewRelayServer(nil, RelayServerConfig{
		NewExitRatePerMinute: 1 << 20,
		EntryRatePerMinute:   1 << 20,
		OnLog:                func(string) {},
	})
}

// (а) Конкурентные EXIT с ОДНИМ новым exit-id и разными токенами: ровно одна регистрация,
// остальные — честный отказ. Иначе TOFU-привязка достаётся не тому, кто пришёл первым, а
// тому, кто последним записал в карту.
func TestHandleExit_ConcurrentNewExitID_OnlyOneRegistration(t *testing.T) {
	const iterations = 300
	const competitors = 4

	for iter := 0; iter < iterations; iter++ {
		srv := raceTestServer()
		const exitID = "exit-contested"

		start := make(chan struct{})
		var okCount int32
		var wg sync.WaitGroup

		for i := 0; i < competitors; i++ {
			token := fmt.Sprintf("token-%d", i)
			cli, srvSide := net.Pipe()

			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				srv.handleExit(srvSide, "203.0.113.7", []string{cmdExit, exitID, token})
			}()
			go func() {
				defer wg.Done()
				line, err := readLine(cli, 3*time.Second)
				if err == nil && line == cmdOK {
					atomic.AddInt32(&okCount, 1)
				}
				cli.Close()
			}()
		}

		close(start)
		wg.Wait()

		if n := atomic.LoadInt32(&okCount); n != 1 {
			t.Fatalf("итерация %d: OK получили %d из %d претендентов на ОДИН новый exit-id — "+
				"проверка «известен ли id» и регистрация не в одной критической секции", iter, n, competitors)
		}
		// Победитель должен быть один и в самой карте — токен принадлежит ровно ему.
		srv.mu.RLock()
		b, ok := srv.exits[exitID]
		var token string
		if ok {
			token = b.token
		}
		srv.mu.RUnlock()
		if !ok {
			t.Fatalf("итерация %d: exit-id не зарегистрирован ни за кем", iter)
		}
		if !strings.HasPrefix(token, "token-") {
			t.Fatalf("итерация %d: в карте чужой токен %q", iter, token)
		}
	}
}

// (а-2) Тот же сценарий, но конкуренты — законный владелец (переподключение с ВЕРНЫМ токеном)
// и самозванец с чужим: самозванец обязан получить отказ при любом чередовании.
func TestHandleExit_ConcurrentReconnectAndImpostor(t *testing.T) {
	const iterations = 300

	for iter := 0; iter < iterations; iter++ {
		srv := raceTestServer()
		const exitID = "exit-owned"
		const realToken = "token-real"

		// Привязка уже существует, живой сессии нет (владелец в backoff).
		srv.exits[exitID] = &exitBinding{token: realToken, lastActive: time.Now()}

		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([]string, 2)

		for i, token := range []string{realToken, "token-impostor"} {
			cli, srvSide := net.Pipe()
			idx := i
			tok := token
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				srv.handleExit(srvSide, "203.0.113.8", []string{cmdExit, exitID, tok})
			}()
			go func() {
				defer wg.Done()
				line, err := readLine(cli, 3*time.Second)
				if err != nil {
					line = "<нет ответа: " + err.Error() + ">"
				}
				results[idx] = line
				cli.Close()
			}()
		}

		close(start)
		wg.Wait()

		if results[0] != cmdOK {
			t.Fatalf("итерация %d: законный владелец с верным токеном отвергнут: %q", iter, results[0])
		}
		if results[1] == cmdOK {
			t.Fatalf("итерация %d: самозванец с чужим токеном зарегистрирован", iter)
		}
		srv.mu.RLock()
		got := srv.exits[exitID].token
		srv.mu.RUnlock()
		if got != realToken {
			t.Fatalf("итерация %d: токен привязки подменён на %q", iter, got)
		}
	}
}

// (б) Переподключение владельца одновременно с разбором ОБРЫВА его прошлой сессии.
// handleExit читает existing.sess, disconnectExitSession пишет b.sess под локом — под -race
// это data race, а по сути — чтение указателя на сессию, который в этот момент меняют.
func TestHandleExit_ReconnectConcurrentWithDisconnect(t *testing.T) {
	const iterations = 300

	for iter := 0; iter < iterations; iter++ {
		srv := raceTestServer()
		const exitID = "exit-flapping"
		const token = "token-flap"

		oldCli, oldSrv := net.Pipe()
		old := &exitSession{exitID: exitID, token: token, conn: oldSrv, done: make(chan struct{})}
		srv.exits[exitID] = &exitBinding{token: token, lastActive: time.Now(), sess: old}

		newCli, newSrv := net.Pipe()

		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); srv.disconnectExitSession(exitID, old) }()
		go func() {
			defer wg.Done()
			srv.handleExit(newSrv, "203.0.113.9", []string{cmdExit, exitID, token})
		}()
		go func() {
			defer wg.Done()
			_, _ = readLine(newCli, 3*time.Second)
			newCli.Close()
		}()

		wg.Wait()
		oldCli.Close()

		// Чем бы ни кончилось чередование, привязка обязана остаться и указывать на НОВУЮ
		// сессию: разбор обрыва старой не имеет права обнулить только что подключившуюся.
		srv.mu.RLock()
		b, ok := srv.exits[exitID]
		var sess *exitSession
		if ok {
			sess = b.sess
		}
		srv.mu.RUnlock()
		if !ok {
			t.Fatalf("итерация %d: привязка исчезла", iter)
		}
		if sess == old {
			t.Fatalf("итерация %d: в привязке осталась ОТКЛЮЧЁННАЯ сессия", iter)
		}
	}
}
