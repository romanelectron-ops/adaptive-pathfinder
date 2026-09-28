package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// withStubs подменяет сетевые швы на детерминированные заглушки на время теста и
// восстанавливает их по завершении — тот же приём, что и cfTraceURL в internal/checker.
func withStubs(t *testing.T, ips []singbox.LocalIPCandidate,
	upnp func(ctx context.Context, internalIP string, port int) (string, error),
	stun func(ctx context.Context) (net.IP, int, error)) {
	t.Helper()
	origIPs, origUPnP, origStun := localIPCandidatesFn, upnpAddPortMappingFn, stunDetectFn
	localIPCandidatesFn = func() []singbox.LocalIPCandidate { return ips }
	upnpAddPortMappingFn = upnp
	stunDetectFn = stun
	t.Cleanup(func() {
		localIPCandidatesFn, upnpAddPortMappingFn, stunDetectFn = origIPs, origUPnP, origStun
	})
}

func alwaysFailUPnP(context.Context, string, int) (string, error) {
	return "", errors.New("upnp: недоступен")
}

func alwaysFailStun(context.Context) (net.IP, int, error) {
	return nil, 0, errors.New("stun: недоступен")
}

// Путь 1: локальный адрес уже публичный (не приватный диапазон) — Detect не должен идти
// дальше в UPnP/STUN вовсе (это проверяется тем, что заглушки-провалы там не помешали бы
// тесту пройти, но реальная причина успеха — именно короткое замыкание на MethodDirect).
func TestDetect_AlreadyPublicIP_ReturnsMethodDirect(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "203.0.113.7", InterfaceName: "eth0"}},
		alwaysFailUPnP, alwaysFailStun)

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil", err)
	}
	if m != MethodDirect {
		t.Errorf("Detect() method = %v, ожидался MethodDirect", m)
	}
	host, port, ok := r.ExternalAddress()
	if !ok || host != "203.0.113.7" || port != 8443 {
		t.Errorf("ExternalAddress() = (%q, %d, %v), ожидалось (203.0.113.7, 8443, true)", host, port, ok)
	}
}

// Путь 2: локальный адрес приватный, UPnP успешен — MethodUPnP, внешний IP из ответа UPnP.
func TestDetect_PrivateIP_UPnPSucceeds_ReturnsMethodUPnP(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			if internalIP != "192.168.1.50" || port != 8443 {
				t.Errorf("upnpAddPortMapping вызван с (%q, %d), ожидалось (192.168.1.50, 8443)", internalIP, port)
			}
			return "198.51.100.9", nil
		}, alwaysFailStun)

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil", err)
	}
	if m != MethodUPnP {
		t.Errorf("Detect() method = %v, ожидался MethodUPnP", m)
	}
	host, port, ok := r.ExternalAddress()
	if !ok || host != "198.51.100.9" || port != 8443 {
		t.Errorf("ExternalAddress() = (%q, %d, %v), ожидалось (198.51.100.9, 8443, true)", host, port, ok)
	}
}

// Путь 3: UPnP недоступен, STUN отвечает — MethodManualPort (не MethodDirect: порт не
// подтверждён, только вероятный внешний IP).
//
// Аудит 2026-09-01 (раздел D): раньше тест ТРЕБОВАЛ, чтобы ExternalAddress() вернул порт из
// ответа STUN (55123 — эфемерный UDP-порт зондирующего сокета) вместо порта, который
// реально запросил вызывающий (28443 — порт службы «Выход»). Закреплял дефект: мастер
// настройки показал бы пользователю инструкцию пробросить порт 55123, следуя которой
// ничего не заработало бы — служба слушает 28443, а 55123 не имеет отношения ни к чему
// после закрытия зондирующего UDP-сокета. Порт STUN-ответа больше НЕ используется вовсе
// (см. stunPortIgnored ниже — заглушка возвращает заведомо другое значение, чтобы тест
// провалился, если код снова начнёт его читать).
func TestDetect_UPnPFails_StunSucceeds_ReturnsMethodManualPort(t *testing.T) {
	const requestedPort = 28443
	const stunEphemeralPort = 55123 // намеренно ДРУГОЕ значение — не должно попасть в результат
	withStubs(t, []singbox.LocalIPCandidate{{IP: "10.0.0.5", InterfaceName: "wlan0"}},
		alwaysFailUPnP,
		func(ctx context.Context) (net.IP, int, error) {
			return net.ParseIP("203.0.113.42"), stunEphemeralPort, nil
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), requestedPort)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil", err)
	}
	if m != MethodManualPort {
		t.Errorf("Detect() method = %v, ожидался MethodManualPort", m)
	}
	host, port, ok := r.ExternalAddress()
	if !ok || host != "203.0.113.42" || port != requestedPort {
		t.Errorf("ExternalAddress() = (%q, %d, %v), ожидалось (203.0.113.42, %d, true) — "+
			"порт обязан быть запрошенным портом службы, а НЕ эфемерным UDP-портом из "+
			"ответа STUN", host, port, ok, requestedPort)
	}
}

// Все пути провалились — Detect не паникует, не выдумывает адрес, возвращает
// MethodManualPort без ошибки (обычная сеть без UPnP, STUN недоступен именно отсюда — не
// исключительная ситуация) и ExternalAddress().ok остаётся false.
func TestDetect_AllPathsFail_ReturnsManualPortNoAddress(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "10.0.0.5", InterfaceName: "wlan0"}},
		alwaysFailUPnP, alwaysFailStun)

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil (не исключительная ситуация)", err)
	}
	if m != MethodManualPort {
		t.Errorf("Detect() method = %v, ожидался MethodManualPort", m)
	}
	if _, _, ok := r.ExternalAddress(); ok {
		t.Error("ExternalAddress() ok = true, ожидался false — ни один путь не дал результата")
	}
}

// CGNAT-диапазон (100.64.0.0/10, RFC 6598) не должен приниматься за публичный IP — живой
// случай 2026-08-28, реальное устройство оператора связи с адресом 10.139.239.x... то есть
// именно 100.x диапазон нужен отдельно от классических RFC 1918 — регрессия на этот случай.
func TestDetect_CGNATAddress_NotTreatedAsPublic(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "100.85.30.12", InterfaceName: "ccmni1"}},
		alwaysFailUPnP, alwaysFailStun)

	r := NewReachability()
	m, _ := r.Detect(context.Background(), 8443)
	if m == MethodDirect {
		t.Error("Detect() = MethodDirect для CGNAT-адреса (100.64.0.0/10) — должен считаться приватным")
	}
}

// [консилиум, HIGH, находка №13, TZ_RELAY_HARDENING_2026-08-29.md кластер F] Сердце фикса:
// STUN сам по себе не различает NAT-типы, но если наблюдаемый ЧЕРЕЗ STUN "внешний" адрес сам
// приватный/CGNAT — это самодостаточный признак двойного NAT (домашний роутер, а за ним ещё
// один слой NAT у оператора). Проброс порта на домашнем роутере физически не поможет — Detect
// обязан вернуть MethodRelay, а не невыполнимый совет MethodManualPort.
func TestDetect_StunObservesCGNATAddress_ReturnsMethodRelay(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		alwaysFailUPnP,
		func(ctx context.Context) (net.IP, int, error) {
			return net.ParseIP("100.85.30.12"), 55123, nil // CGNAT, RFC 6598
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil", err)
	}
	if m != MethodRelay {
		t.Errorf("Detect() method = %v, ожидался MethodRelay (STUN увидел CGNAT-адрес — двойной NAT)", m)
	}
}

// Тот же путь STUN, но с настоящим публичным адресом — обычный NAT, совет "пробросьте порт"
// остаётся выполнимым, поведение до фикса №13 не должно было сломаться.
func TestDetect_StunObservesPublicAddress_ReturnsMethodManualPort(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		alwaysFailUPnP,
		func(ctx context.Context) (net.IP, int, error) {
			return net.ParseIP("203.0.113.42"), 55123, nil
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil", err)
	}
	if m != MethodManualPort {
		t.Errorf("Detect() method = %v, ожидался MethodManualPort (STUN увидел публичный адрес — обычный NAT)", m)
	}
}

// Explain — единственная часть без сетевых операций (чистая функция без побочных эффектов).
// Проверяем, что каждый Method даёт непустую фразу и что MethodRelay явно упоминает
// необходимость посредника — это тот случай, который вводит пользователя в заблуждение
// сильнее всего, если текст ошибётся.
func TestReachability_Explain(t *testing.T) {
	r := NewReachability()

	cases := []struct {
		method Method
		substr string
	}{
		{MethodDirect, "видно"},
		{MethodUPnP, "автоматически"},
		{MethodManualPort, "проброс"},
		{MethodRelay, "посредник"},
		{MethodUnknown, "не проверено"},
	}
	for _, c := range cases {
		got := r.Explain(c.method)
		if got == "" {
			t.Errorf("Explain(%v) вернул пустую строку", c.method)
		}
		if !strings.Contains(got, c.substr) {
			t.Errorf("Explain(%v) = %q, ожидалась подстрока %q", c.method, got, c.substr)
		}
	}
}

// Регрессия (консилиум 2026-08-10, medium): невалидное значение Method (вне 5 объявленных
// констант) раньше молча получало ТУ ЖЕ фразу, что и легитимный MethodUnknown ("Пока не
// проверено") — неотличимо для того, кто читает лог/UI. Явный случай программной ошибки
// обязан быть узнаваем и не совпадать текстом с нормальным "ещё не проверено".
func TestReachability_Explain_UnknownValueDiffersFromMethodUnknown(t *testing.T) {
	r := NewReachability()

	legit := r.Explain(MethodUnknown)
	bogus := r.Explain(Method(99))

	if bogus == legit {
		t.Fatalf("Explain(Method(99)) = %q совпадает с Explain(MethodUnknown) — "+
			"невалидное значение неотличимо от легитимного «не проверено»", bogus)
	}
	if bogus == "" {
		t.Error("Explain(Method(99)) вернул пустую строку")
	}
}
