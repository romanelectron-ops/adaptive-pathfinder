package main

// V13-6-tray (ТЗ v1.4 §9.3 контракта, F6 «трей nil-guard»): проверено чтением gui/tray.go —
// nil-guard и паритет VerifyState (§2.1/§2.3 контракта) УЖЕ реализованы (комментарии кода,
// updateTrayState:106-109 и resolveTrayVerifyState:182-186, датируют это фиксом контракта
// VerifyState 2026-09-06, до начала этого лота): trayStatus/trayConnect/trayDisconnect нил-
// гвардятся одним условием (все три пишутся под общим мьютексом за один раз — частичного
// nil-состояния быть не может), state.ActiveNode нил-гвардится отдельно,
// resolveTrayVerifyState предпочитает честный state.VerifyState и деградирует на
// двух-булеву модель ТОЛЬКО если движок ещё не отдаёт это поле вовсе. tray.go этим лотом
// НЕ менялся (см. result.md — решение: зафиксировать регресс-тестом, не трогать рабочий
// код). Ниже — тест-замок на оба факта, чтобы будущая правка не сломала их молча.

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestUpdateTrayState_NilMenuItems_NoPanic — nil-guard: до первого тика onTrayReady()
// (заполняет trayStatus/trayConnect/trayDisconnect) любое число вызовов updateTrayState не
// должно паниковать — обычное состояние в первые миллисекунды после старта (см. комментарий
// updateTrayState в tray.go).
func TestUpdateTrayState_NilMenuItems_NoPanic(t *testing.T) {
	trayMu.Lock()
	trayStatus, trayConnect, trayDisconnect = nil, nil, nil
	trayMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("updateTrayState(nil-меню) запаниковал: %v", r)
		}
	}()

	updateTrayState(&models.ConnectionState{Connected: true, Verified: true})
	updateTrayState(&models.ConnectionState{})
	updateTrayState(&models.ConnectionState{ActiveNode: nil})
}

// TestResolveTrayVerifyState_PrefersHonestField — §2.1/§2.3 контракта: если движок уже
// заполнил VerifyState (LOT-04, 2026-09-06 — всегда так у текущего движка), трей обязан
// доверять именно ему, а не пересчитывать из Connected/Verified — та же таблица состояний,
// что и у orb во фронтенде (resolveVerifyState в index.html).
func TestResolveTrayVerifyState_PrefersHonestField(t *testing.T) {
	cases := []struct {
		name  string
		state *models.ConnectionState
		want  string
	}{
		{"честное verify_state побеждает противоречащие ему bool-поля",
			&models.ConnectionState{VerifyState: models.VerifyFailed, Connected: true, Verified: true},
			models.VerifyFailed},
		{"честное verified", &models.ConnectionState{VerifyState: models.VerifyVerified}, models.VerifyVerified},
		{"деградация: verify_state пуст, connected+verified", &models.ConnectionState{Connected: true, Verified: true}, models.VerifyVerified},
		{"деградация: verify_state пуст, только connected", &models.ConnectionState{Connected: true}, models.VerifyChecking},
		{"деградация: ничего нет — idle", &models.ConnectionState{}, models.VerifyIdle},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveTrayVerifyState(c.state); got != c.want {
				t.Errorf("resolveTrayVerifyState() = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// TestUpdateTrayState_ActiveNodeNil_NoPanic — отдельный nil-guard: ActiveNode тоже может
// быть nil (узел ещё не выбран/подключение только начинается) независимо от того, заполнены
// ли пункты меню трея.
func TestUpdateTrayState_ActiveNodeNil_NoPanic(t *testing.T) {
	trayMu.Lock()
	trayStatus = nil // держим пункты меню nil, чтобы updateTrayState вышла рано и тест
	trayMu.Unlock()  // проверял именно ActiveNode-путь без побочных вызовов systray.Set*
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("updateTrayState с ActiveNode==nil запаниковал: %v", r)
		}
	}()
	updateTrayState(&models.ConnectionState{Connected: true, ActiveNode: nil})
}
