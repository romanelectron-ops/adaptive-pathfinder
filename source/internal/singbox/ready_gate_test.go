package singbox

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Контракт «успех означает работающий туннель» (дефект D-A31).
//
// Вход:      запущенный процесс sing-box и порт из его конфигурации.
// Тело:      Process.awaitReady.
// Выход:     nil только при принятом соединении; иначе ошибка с указанием причины.
// Fail-safe: смерть процесса и истечение срока обе дают отказ (D-2, fail-closed).
// Инвариант: не существует прогона, где Start вернул nil, а порт закрыт.
//
// Что ловится. Раньше Start спал две секунды и возвращал nil безусловно. Отвергнутая
// конфигурация убивает sing-box за десятки миллисекунд, и движок всё равно объявлял
// «Connected! SOCKS5→127.0.0.1:10808» — состояние «подключено» при отсутствии туннеля.

func TestAwaitReady_SucceedsWhenPortAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("подготовка слушателя: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	p := &Process{readyPort: port, exitCh: make(chan struct{})}
	if err := p.awaitReady(context.Background()); err != nil {
		t.Fatalf("порт принимает соединения, а awaitReady отказал: %v", err)
	}
}

func TestAwaitReady_FailsWhenProcessDied(t *testing.T) {
	exited := make(chan struct{})
	close(exited) // процесс уже завершился — ровно случай отвергнутой конфигурации

	// Порт заведомо закрыт: 1 — привилегированный, слушателя там нет.
	p := &Process{readyPort: 1, running: true, exitCh: exited}
	err := p.awaitReady(context.Background())
	if err == nil {
		t.Fatal("процесс мёртв, а awaitReady вернул успех — это и есть ложное «Connected»")
	}
	if !strings.Contains(err.Error(), "завершился") {
		t.Errorf("сообщение не называет причину: %v", err)
	}
	if p.running {
		t.Error("после провала старта процесс числится запущенным")
	}
}

func TestAwaitReady_FailsOnTimeout(t *testing.T) {
	restoreProbe, restoreSleep, restoreTimeout := readyProbeFn, startSleepFn, ReadyTimeout
	defer func() {
		readyProbeFn, startSleepFn, ReadyTimeout = restoreProbe, restoreSleep, restoreTimeout
	}()

	// Порт не открывается никогда, а сон обнулён, чтобы тест не ждал реального срока.
	readyProbeFn = func(int) error { return errors.New("connection refused") }
	startSleepFn = func(time.Duration) {}
	ReadyTimeout = 10 * time.Millisecond

	p := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{})}
	err := p.awaitReady(context.Background())
	if err == nil {
		t.Fatal("порт так и не открылся, а awaitReady вернул успех")
	}
	if !strings.Contains(err.Error(), "10808") {
		t.Errorf("в сообщении нет номера порта, по которому судили о готовности: %v", err)
	}
	if p.running {
		t.Error("после провала старта процесс числится запущенным")
	}
}

// Отмена контекста — тоже отказ, а не тихое продолжение.
func TestAwaitReady_FailsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{})}
	if err := p.awaitReady(ctx); err == nil {
		t.Fatal("контекст отменён, а awaitReady вернул успех")
	}
}

// Совместимость: там, где признака готовности нет (чистый TUN без входящих портов),
// поведение прежнее — пауза и успех. Иначе правка сломала бы десктопный VPN-режим.
func TestAwaitReady_NoPortKeepsOldBehaviour(t *testing.T) {
	restore := startSleepFn
	defer func() { startSleepFn = restore }()
	slept := time.Duration(0)
	startSleepFn = func(d time.Duration) { slept += d }

	p := &Process{readyPort: 0}
	if err := p.awaitReady(context.Background()); err != nil {
		t.Fatalf("без признака готовности ожидался прежний успех, получено: %v", err)
	}
	if slept != 2*time.Second {
		t.Errorf("прежняя пауза изменилась: %v", slept)
	}
}

// readinessPort — какой именно порт считается признаком.
func TestReadinessPort(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want int
	}{
		{"nil", nil, 0},
		{"без входящих", &Config{}, 0},
		{"socks предпочтительнее http", &Config{Inbounds: []Inbound{
			{Type: "http", ListenPort: 10809},
			{Type: "socks", ListenPort: 10808},
		}}, 10808},
		{"без socks — первый доступный", &Config{Inbounds: []Inbound{
			{Type: "tun"},
			{Type: "http", ListenPort: 10809},
		}}, 10809},
		{"чистый TUN — признака нет", &Config{Inbounds: []Inbound{{Type: "tun"}}}, 0},
	}
	for _, c := range cases {
		if got := readinessPort(c.cfg); got != c.want {
			t.Errorf("%s: readinessPort = %d, ожидалось %d", c.name, got, c.want)
		}
	}
}

// WriteConfig обязан запомнить порт: без этого проверка готовности молча выключится и
// все тесты выше будут проверять функцию, которую никто не вызывает с реальными данными.
func TestWriteConfig_RemembersReadinessPort(t *testing.T) {
	p := NewProcess(t.TempDir(), t.TempDir())
	if err := p.WriteConfig(NewBuilder(10808, false).BuildTor()); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if p.readyPort != 10808 {
		t.Errorf("readyPort = %d, ожидался 10808 (порт socks-входа из конфигурации)", p.readyPort)
	}
}
