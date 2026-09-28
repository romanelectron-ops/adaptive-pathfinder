package relay

import (
	"testing"
	"time"
)

// exit_hijack_test.go — P1 (аудит 2026-09-01, security-раздел, доп. находка): захват
// exit-id во время окна между разрывом control-канала и переподключением реального
// «Выхода» (сон устройства, смена сети — экспоненциальный backoff ~1→30с в ExitClient).
//
// Разбор случая из аудита: раньше TOFU-привязка (exit-id → token) удалялась из s.exits в
// момент разрыва TCP-соединения (runExitControl → бывший removeExit) — то есть ровно тогда,
// когда легитимный владелец физически не может её защитить. handleExit трактовал id как
// "виден впервые" и позволял атакующему зарегистрировать СВОЙ токен под чужим exit-id.
// Вернувшийся владелец получал "exit-id занят другим владельцем" НАВСЕГДА.

// Разрыв связи не должен открывать exit-id для захвата чужим токеном — TOFU-привязка обязана
// пережить отключение.
func TestRelayServer_ExitIDSurvivesDisconnect_CannotBeHijacked(t *testing.T) {
	addr, _, srv := startTestRelayServer(t, RelayServerConfig{})

	// Настоящий владелец регистрируется и затем «засыпает» — control-канал рвётся.
	conn1, resp1 := dialAndHandshake(t, addr, cmdExit+" exit-owner token-owner")
	if resp1 != cmdOK {
		t.Fatalf("первая регистрация: resp = %q, ожидался OK", resp1)
	}
	conn1.Close()

	// Даём серверу время заметить разрыв (runExitControl → disconnectExitSession).
	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.RLock()
		b, ok := srv.exits["exit-owner"]
		var offline bool
		if ok {
			offline = b.sess == nil
		}
		srv.mu.RUnlock()
		if ok && offline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("сервер не заметил разрыв control-канала за 2с")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Атакующий приходит СРАЗУ после разрыва, пока владелец ещё не переподключился —
	// ровно то окно, которое эксплуатировала находка аудита.
	connAttacker, respAttacker := dialAndHandshake(t, addr, cmdExit+" exit-owner token-attacker")
	defer connAttacker.Close()
	if respAttacker == cmdOK {
		t.Fatal("захват exit-id чужим токеном в окне отключения прошёл — привязка не пережила разрыв")
	}

	// Привязка обязана остаться настоящей — token НЕ подменился атакующей попыткой.
	srv.mu.RLock()
	b, ok := srv.exits["exit-owner"]
	srv.mu.RUnlock()
	if !ok {
		t.Fatal("TOFU-привязка exit-owner исчезла из карты после отключения — должна была остаться")
	}
	if b.token != "token-owner" {
		t.Errorf("token привязки = %q, ожидался token-owner (не должен был подмениться атакующим)", b.token)
	}

	// Настоящий владелец обязан суметь переподключиться СВОИМ токеном после неудачной
	// попытки захвата — это и есть разбираемый случай "владелец не регистрируется никогда".
	conn2, resp2 := dialAndHandshake(t, addr, cmdExit+" exit-owner token-owner")
	defer conn2.Close()
	if resp2 != cmdOK {
		t.Fatalf("переподключение настоящего владельца: resp = %q, ожидался OK", resp2)
	}
}

// ENTRY к TOFU-привязке, у которой сейчас нет живого соединения (владелец в процессе
// переподключения), обязан отвечать тем же "no such exit", что и для полностью неизвестного
// id — без этого зонд мог бы отличить "было, но офлайн" от "никогда не было".
func TestRelayServer_Entry_KnownButOfflineExit_SameErrorAsUnknown(t *testing.T) {
	addr, _, srv := startTestRelayServer(t, RelayServerConfig{})

	conn1, resp1 := dialAndHandshake(t, addr, cmdExit+" exit-sleepy token-x")
	if resp1 != cmdOK {
		t.Fatalf("регистрация: resp = %q, ожидался OK", resp1)
	}
	conn1.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.RLock()
		b, ok := srv.exits["exit-sleepy"]
		var offline bool
		if ok {
			offline = b.sess == nil
		}
		srv.mu.RUnlock()
		if ok && offline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("сервер не заметил разрыв control-канала за 2с")
		}
		time.Sleep(10 * time.Millisecond)
	}

	connKnownOffline, respKnownOffline := dialAndHandshake(t, addr, cmdEntry+" exit-sleepy")
	defer connKnownOffline.Close()
	connUnknown, respUnknown := dialAndHandshake(t, addr, cmdEntry+" never-registered")
	defer connUnknown.Close()

	if respKnownOffline != respUnknown {
		t.Errorf("ответ на известный-но-офлайн (%q) отличается от ответа на неизвестный (%q) — "+
			"зонд может отличить существующий id от несуществующего", respKnownOffline, respUnknown)
	}
	if respKnownOffline != "ERR no such exit" {
		t.Errorf("resp = %q, ожидался 'ERR no such exit'", respKnownOffline)
	}
}

// reserveExitSlot: при заполненном лимите вытесняется САМАЯ ДАВНО НЕАКТИВНАЯ офлайн-привязка;
// привязка с живой сессией — никогда, даже если она "старше" по lastActive.
func TestReserveExitSlot_EvictsOldestOfflineOnly(t *testing.T) {
	srv := NewRelayServer(nil, RelayServerConfig{MaxRegisteredExits: 2})

	srv.exits["old-offline"] = &exitBinding{token: "t1", lastActive: time.Now().Add(-time.Hour)}
	srv.exits["connected"] = &exitBinding{token: "t2", lastActive: time.Now().Add(-2 * time.Hour),
		sess: &exitSession{exitID: "connected"}} // "старше" по времени, но ПОДКЛЮЧЁН — не трогать

	if !srv.reserveExitSlot("new-id") {
		t.Fatal("reserveExitSlot вернул false — ожидалось вытеснение old-offline")
	}
	if _, stillThere := srv.exits["old-offline"]; stillThere {
		t.Error("old-offline должен был быть вытеснен (самая давняя офлайн-привязка)")
	}
	if _, stillThere := srv.exits["connected"]; !stillThere {
		t.Error("connected НЕ должен был быть вытеснен — у него живая сессия")
	}
}

// Все зарегистрированные exit-id сейчас подключены — реальная перегрузка, отказ обоснован
// (никого нельзя вытеснить, не оборвав активную сессию).
func TestReserveExitSlot_AllConnected_Rejects(t *testing.T) {
	srv := NewRelayServer(nil, RelayServerConfig{MaxRegisteredExits: 1})
	srv.exits["busy"] = &exitBinding{token: "t1", sess: &exitSession{exitID: "busy"}}

	if srv.reserveExitSlot("new-id") {
		t.Error("reserveExitSlot вернул true — все привязки подключены, вытеснять нечего")
	}
	if _, stillThere := srv.exits["busy"]; !stillThere {
		t.Error("busy не должен был быть тронут")
	}
}
