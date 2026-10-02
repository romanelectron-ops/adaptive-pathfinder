package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
// MethodUndetermined без ошибки (обычная сеть без UPnP, STUN недоступен именно отсюда — не
// исключительная ситуация) и ExternalAddress().ok остаётся false.
//
// Живой инцидент 2026-09-29: раньше здесь возвращался MethodManualPort — «нужен проброс порта
// на роутере» без адреса, хотя у ноутбука, сидевшего на раздаче с телефона, роутера нет вовсе
// (CGNAT оператора) и совет невыполним. Тест раньше закреплял именно это.
func TestDetect_AllPathsFail_ReturnsUndeterminedNoAddress(t *testing.T) {
	withStubs(t, []singbox.LocalIPCandidate{{IP: "10.0.0.5", InterfaceName: "wlan0"}},
		alwaysFailUPnP, alwaysFailStun)

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v, ожидался nil (не исключительная ситуация)", err)
	}
	if m != MethodUndetermined {
		t.Errorf("Detect() method = %v, ожидался MethodUndetermined (совет «пробросьте порт» без адреса и без роутера вводит в заблуждение)", m)
	}
	if _, _, ok := r.ExternalAddress(); ok {
		t.Error("ExternalAddress() ok = true, ожидался false — ни один путь не дал результата")
	}
}

// withTimeouts сжимает сроки Detect до миллисекунд на время теста (иначе тесты «висящего»
// пути ждали бы реальные секунды) и восстанавливает по завершении.
func withTimeouts(t *testing.T, detect, upnp, stun time.Duration) {
	t.Helper()
	origDetect, origUPnP, origSTUN := detectTimeout, upnpTimeout, stunTimeout
	detectTimeout, upnpTimeout, stunTimeout = detect, upnp, stun
	t.Cleanup(func() { detectTimeout, upnpTimeout, stunTimeout = origDetect, origUPnP, origSTUN })
}

// Значения Method 0..4 — числа, которых ждут UI (index.html) и Android (MainActivity.kt);
// новый исход добавлен в конец и не сдвинул прежние.
func TestMethodValues_StableForUIAndAndroid(t *testing.T) {
	want := map[Method]int{
		MethodUnknown: 0, MethodDirect: 1, MethodUPnP: 2, MethodManualPort: 3, MethodRelay: 4,
		MethodUndetermined: 5,
	}
	for m, v := range want {
		if int(m) != v {
			t.Errorf("Method = %d, ожидалось %d — числа сверяют UI и Android", int(m), v)
		}
	}
}

// Ревью 2026-09-30: если система выходит в сеть через ВИРТУАЛЬНЫЙ адаптер (внешний виртуальный
// коммутатор Hyper-V, «vEthernet (External)»), его адрес — и есть адрес устройства в сети. Detect
// обязан пробовать UPnP на нём: раньше фильтр по имени адаптера отбрасывал такой адрес, на хосте
// не оставалось ни одного «пригодного», UPnP не пробовался вовсе. Адрес виртуального адаптера,
// который НЕ является маршрутом по умолчанию, по-прежнему отбрасывается (тесты выше).
func TestDetect_DefaultRouteOnVirtualAdapter_StillUsesUPnP(t *testing.T) {
	var gotInternal atomic.Value
	withStubs(t, []singbox.LocalIPCandidate{
		{IP: "192.168.1.5", InterfaceName: "vEthernet (External)", IsDefaultRoute: true},
		{IP: "198.51.100.1", InterfaceName: "vEthernet (Default Switch)"},
	},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			gotInternal.Store(internalIP)
			return "203.0.113.9", nil
		}, alwaysFailStun)

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if m != MethodUPnP {
		t.Fatalf("Detect() = %v, ожидался MethodUPnP (UPnP на адресе маршрута по умолчанию)", m)
	}
	if got, _ := gotInternal.Load().(string); got != "192.168.1.5" {
		t.Errorf("UPnP вызван с внутренним адресом %q, ожидался 192.168.1.5 (адрес маршрута по умолчанию)", got)
	}
}

// UPnP и STUN стартуют одновременно, а не друг за другом. Детерминированно, без опоры на
// тайминги: UPnP-заглушка ждёт сигнала «STUN уже стартовал» и лишь при его отсутствии до
// своего срока сдаётся. Раньше (последовательный Detect) STUN запускался только ПОСЛЕ
// завершения UPnP, сигнал приходил бы слишком поздно, и заглушка видела бы только срок.
func TestDetect_UPnPAndSTUN_StartInParallel(t *testing.T) {
	// Срок UPnP-заглушки — с запасом: под сильной загрузкой машины (100% CPU) горутина STUN может
	// стартовать позже секунды, и тест падал бы ложно (замечание ревью 2026-09-30).
	withTimeouts(t, 8*time.Second, 5*time.Second, 5*time.Second)
	stunStarted := make(chan struct{})
	var upnpSawStunStart atomic.Bool

	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			select {
			case <-stunStarted:
				upnpSawStunStart.Store(true)
				return "", errors.New("upnp: нет IGD")
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
		func(ctx context.Context) (net.IP, int, error) {
			close(stunStarted)
			return net.ParseIP("203.0.113.42"), 55123, nil
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if !upnpSawStunStart.Load() {
		t.Error("STUN не стартовал, пока UPnP ждал — пути идут последовательно, а не параллельно")
	}
	if m != MethodManualPort {
		t.Errorf("Detect() method = %v, ожидался MethodManualPort (STUN увидел публичный адрес)", m)
	}
	if host, _, ok := r.ExternalAddress(); !ok || host != "203.0.113.42" {
		t.Errorf("ExternalAddress() = (%q, %v), ожидалось (203.0.113.42, true)", host, ok)
	}
}

// Сроки независимы: UPnP «висит» до собственного срока, но это не отнимает время у STUN —
// он отвечает УЖЕ ПОСЛЕ того, как срок UPnP истёк, и его контекст всё ещё жив. Раньше оба
// делили один бюджет: зависший SSDP-поиск съедал его целиком (живой инцидент 2026-09-29,
// медленная раздача с телефона), STUN получал уже истёкший ctx, а Detect молча возвращал
// MethodManualPort без адреса.
func TestDetect_UPnPHangDoesNotStarveSTUN(t *testing.T) {
	withTimeouts(t, 3*time.Second, 100*time.Millisecond, 2*time.Second)
	var upnpDeadlineHit atomic.Bool
	var stunCtxAliveAtReply atomic.Bool

	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			<-ctx.Done() // «висит» до собственного срока
			upnpDeadlineHit.Store(true)
			return "", ctx.Err()
		},
		func(ctx context.Context) (net.IP, int, error) {
			// Отвечаем заведомо после срока UPnP (100 мс), но в рамках своего (2 с).
			select {
			case <-time.After(400 * time.Millisecond):
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
			stunCtxAliveAtReply.Store(ctx.Err() == nil)
			return net.ParseIP("203.0.113.42"), 55123, nil
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if !upnpDeadlineHit.Load() {
		t.Error("UPnP-заглушка не дожила до своего срока — тест не проверяет то, что должен")
	}
	if !stunCtxAliveAtReply.Load() {
		t.Error("контекст STUN оказался истёкшим к моменту ответа — срок UPnP отнял время у STUN")
	}
	if m != MethodManualPort {
		t.Errorf("Detect() method = %v, ожидался MethodManualPort (STUN успел после срока UPnP)", m)
	}
	if host, port, ok := r.ExternalAddress(); !ok || host != "203.0.113.42" || port != 8443 {
		t.Errorf("ExternalAddress() = (%q, %d, %v), ожидалось (203.0.113.42, 8443, true)", host, port, ok)
	}
}

// Приоритет: UPnP важнее STUN, даже если STUN ответил раньше (порт реально открыт, а не «вероятный
// адрес»). Detect обязан дождаться UPnP в пределах его срока и не хватать первый готовый ответ.
func TestDetect_UPnPPreferredOverFasterSTUN(t *testing.T) {
	withTimeouts(t, 3*time.Second, 2*time.Second, 2*time.Second)
	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			select {
			case <-time.After(150 * time.Millisecond): // медленнее STUN
			case <-ctx.Done():
				return "", ctx.Err()
			}
			return "198.51.100.9", nil
		},
		func(ctx context.Context) (net.IP, int, error) {
			return net.ParseIP("203.0.113.42"), 55123, nil // мгновенно
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if m != MethodUPnP {
		t.Errorf("Detect() method = %v, ожидался MethodUPnP (приоритет над более быстрым STUN)", m)
	}
	if host, _, ok := r.ExternalAddress(); !ok || host != "198.51.100.9" {
		t.Errorf("ExternalAddress() = (%q, %v), ожидалось (198.51.100.9, true) — адрес UPnP, не STUN", host, ok)
	}
}

// Общий потолок: если обе функции вообще не смотрят на свой ctx (зависли в системном вызове),
// Detect всё равно возвращается — по срокам, а не по их завершению — и честно говорит
// «не определено».
func TestDetect_HungProbesIgnoringContext_ReturnUndeterminedWithinCeiling(t *testing.T) {
	withTimeouts(t, 400*time.Millisecond, 150*time.Millisecond, 150*time.Millisecond)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // отпустить горутины после теста, не оставлять висеть

	withStubs(t, []singbox.LocalIPCandidate{{IP: "192.168.1.50", InterfaceName: "wlan0"}},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			<-release
			return "", errors.New("upnp: отпущен")
		},
		func(ctx context.Context) (net.IP, int, error) {
			<-release
			return nil, 0, errors.New("stun: отпущен")
		})

	r := NewReachability()
	start := time.Now()
	m, err := r.Detect(context.Background(), 8443)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if m != MethodUndetermined {
		t.Errorf("Detect() method = %v, ожидался MethodUndetermined", m)
	}
	if elapsed > 3*time.Second {
		t.Errorf("Detect() занял %v — не уложился в сроки (заглушки игнорируют ctx, ждать их нельзя)", elapsed)
	}
	if _, _, ok := r.ExternalAddress(); ok {
		t.Error("ExternalAddress() ok = true, ожидался false")
	}
}

// Внутренний адрес для UPnP — первый настоящий: виртуальный коммутатор Hyper-V (живой инцидент
// 2026-09-29, адрес вида 172.x.x.1) и link-local (169.254/16) пропускаются, даже если стоят в списке
// впереди. LocalIPCandidates уже упорядочивает список, но Detect на порядок не полагается.
func TestDetect_InternalIPForUPnP_SkipsVirtualAndLinkLocal(t *testing.T) {
	withTimeouts(t, 2*time.Second, time.Second, time.Second)
	got := make(chan string, 1)
	withStubs(t, []singbox.LocalIPCandidate{
		{IP: "172.31.250.1", InterfaceName: "vEthernet (Default Switch)"},
		{IP: "169.254.5.5", InterfaceName: "Ethernet 9"},
		{IP: "192.168.1.50", InterfaceName: "Wi-Fi"},
	},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			got <- internalIP
			return "198.51.100.9", nil
		}, alwaysFailStun)

	r := NewReachability()
	if m, err := r.Detect(context.Background(), 8443); err != nil || m != MethodUPnP {
		t.Fatalf("Detect() = (%v, %v), ожидалось (MethodUPnP, nil)", m, err)
	}
	if internalIP := <-got; internalIP != "192.168.1.50" {
		t.Errorf("UPnP вызван с внутренним адресом %q, ожидался 192.168.1.50 (Wi-Fi), не виртуальный/link-local", internalIP)
	}
}

// Остались ТОЛЬКО виртуальный и link-local адреса — UPnP не запускается вовсе (пробрасывать
// порт не на что), STUN работает как обычно.
func TestDetect_OnlyVirtualCandidates_SkipsUPnPButStillUsesSTUN(t *testing.T) {
	withTimeouts(t, 2*time.Second, time.Second, time.Second)
	var upnpCalled atomic.Bool
	withStubs(t, []singbox.LocalIPCandidate{
		{IP: "172.31.250.1", InterfaceName: "vEthernet (Default Switch)"},
		{IP: "169.254.5.5", InterfaceName: "Ethernet 9"},
	},
		func(ctx context.Context, internalIP string, port int) (string, error) {
			upnpCalled.Store(true)
			return "198.51.100.9", nil
		},
		func(ctx context.Context) (net.IP, int, error) {
			return net.ParseIP("203.0.113.42"), 55123, nil
		})

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if upnpCalled.Load() {
		t.Error("UPnP вызван с виртуальным/link-local адресом — роутеру предложили пробросить порт на адрес не из его сети")
	}
	if m != MethodManualPort {
		t.Errorf("Detect() method = %v, ожидался MethodManualPort (STUN видит публичный адрес)", m)
	}
}

// «Не приватный» ≠ «публичный»: link-local (169.254/16, «DHCP не ответил») и публичный адрес
// на виртуальном адаптере (VPN/гипервизор) раньше давали ложный MethodDirect — «устройство видно
// снаружи напрямую», после чего ссылка с таким хостом не работала нигде.
func TestDetect_LinkLocalOrVirtualPublicAddress_NotDirect(t *testing.T) {
	withTimeouts(t, 2*time.Second, time.Second, time.Second)
	withStubs(t, []singbox.LocalIPCandidate{
		{IP: "169.254.10.1", InterfaceName: "Ethernet"},
		{IP: "203.0.113.7", InterfaceName: "VMware Network Adapter VMnet8"},
	}, alwaysFailUPnP, alwaysFailStun)

	r := NewReachability()
	m, err := r.Detect(context.Background(), 8443)
	if err != nil {
		t.Fatalf("Detect() err = %v", err)
	}
	if m == MethodDirect {
		t.Error("Detect() = MethodDirect для link-local/виртуального адреса — ложное «видно снаружи»")
	}
	if m != MethodUndetermined {
		t.Errorf("Detect() method = %v, ожидался MethodUndetermined", m)
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
		{MethodUndetermined, "Не удалось определить внешний адрес"},
		// оба сценария «не определено» названы прямо: раздача с телефона/CGNAT — нужен посредник,
		// домашний роутер — проброс вручную
		{MethodUndetermined, "CGNAT"},
		{MethodUndetermined, "relay-посредник"},
		{MethodUndetermined, "пробросьте порт вручную"},
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

// Регрессия (консилиум 2026-08-10, medium): невалидное значение Method (вне 6 объявленных
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
