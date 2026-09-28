package fallback

import (
	"context"
	"testing"
	"time"
)

// Контракт «сторож судит о здоровье туннеля, а не о его отсутствии» (дефект D-A25).
//
// Вход:      предикат ShouldCheck.
// Тело:      Watchdog.check.
// Выход:     проверка выполняется либо пропускается целиком.
// Fail-safe: предикат не задан → проверяем (прежнее поведение).
// Инвариант: пока подключения нет, счётчик отказов не растёт и OnDead не вызывается.
//
// Что ловится. Сторож ходит ЧЕРЕЗ SOCKS самого APF. До подключения этого SOCKS не
// существует, поэтому каждая проверка обязана провалиться — не потому, что туннель болен,
// а потому, что туннеля нет. На телефоне к первому нажатию «Подключить» уже накапливалось
// `Watchdog: DEAD (266 failures)`, а автомат доходил до `all levels exhausted, attempt #33`:
// первое подключение начиналось в состоянии «всё перепробовано и всё мертво».
//
// Для Э-6 (100 циклов Connect/Disconnect) это смертельно: поведение на сотом цикле
// определялось бы накопленным мусором, а не самим циклом.

// newTestWatchdog — сторож, чья проверка гарантированно провалится: SOCKS на порту 1
// никто не слушает. Так отделяется «проверка не выполнялась» от «проверка прошла».
func newTestWatchdog(t *testing.T) *Watchdog {
	t.Helper()
	cfg := DefaultWatchdogConfig("127.0.0.1:1")
	cfg.CheckTimeout = 200 * time.Millisecond
	return NewWatchdog(cfg, func(string) {})
}

func TestWatchdog_SkipsChecksWhileDisconnected(t *testing.T) {
	w := newTestWatchdog(t)
	dead := false
	w.OnDead = func() { dead = true }
	w.ShouldCheck = func() bool { return false }

	for i := 0; i < 5; i++ {
		w.check(context.Background())
	}

	st := w.GetStatus()
	if st.TotalChecks != 0 {
		t.Errorf("выполнено %d проверок при отсутствии подключения — должно быть 0", st.TotalChecks)
	}
	if st.FailCount != 0 || st.TotalFails != 0 {
		t.Errorf("накоплены отказы без подключения: FailCount=%d TotalFails=%d",
			st.FailCount, st.TotalFails)
	}
	if st.State != WatchdogIdle {
		t.Errorf("состояние %q вместо %q", st.State, WatchdogIdle)
	}
	// OnDead вызывается через go, поэтому даём ему шанс проявиться.
	time.Sleep(50 * time.Millisecond)
	if dead {
		t.Error("OnDead вызван без подключения — движок начал бы аварийное переключение впустую")
	}
}

// Главное для Э-6: отказы, набранные до отключения, не доживают до следующего подключения.
func TestWatchdog_ForgetsFailuresAfterDisconnect(t *testing.T) {
	w := newTestWatchdog(t)
	connected := true
	w.ShouldCheck = func() bool { return connected }

	w.check(context.Background()) // подключены, проверка провалится
	if w.GetStatus().FailCount == 0 {
		t.Fatal("проверка при подключении не дала отказа — тест выродился")
	}

	connected = false
	w.check(context.Background()) // отключились

	st := w.GetStatus()
	if st.FailCount != 0 {
		t.Errorf("FailCount = %d: чужая история дожила до следующего подключения", st.FailCount)
	}
	if st.LastError != "" {
		t.Errorf("LastError = %q: сохранилась ошибка от прошлого сеанса", st.LastError)
	}
}

// Обратная сторона: при подключении сторож обязан работать как прежде — иначе правка
// молча выключила бы защиту вместо того, чтобы её уточнить.
func TestWatchdog_ChecksWhileConnected(t *testing.T) {
	w := newTestWatchdog(t)
	w.ShouldCheck = func() bool { return true }

	w.check(context.Background())

	st := w.GetStatus()
	if st.TotalChecks != 1 {
		t.Errorf("выполнено %d проверок при активном подключении — ожидалась 1", st.TotalChecks)
	}
	if st.FailCount != 1 {
		t.Errorf("FailCount = %d: отказ недостижимого SOCKS не засчитан", st.FailCount)
	}
}

// Предикат не задан — поведение прежнее. Правка не должна менять тех, кто её не просил.
func TestWatchdog_NilPredicateKeepsOldBehaviour(t *testing.T) {
	w := newTestWatchdog(t)
	w.ShouldCheck = nil

	w.check(context.Background())

	if w.GetStatus().TotalChecks != 1 {
		t.Error("без предиката проверка не выполнилась — прежнее поведение нарушено")
	}
}
