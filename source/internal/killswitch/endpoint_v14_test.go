package killswitch

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// S-11 (TZ v1.4, лот L1-KS, TB-1) — «Отравленный DNS расширяет allow-список Kill Switch».
//
// До фикса classifyIPs (endpoint.go) не ограничивал ни количество, ни классы адресов: ЛЮБОЙ
// ответ DNS-резолвера (в т.ч. подсунутый атакующим, контролирующим DNS на пути) целиком
// попадал в allow-список Kill Switch. Комбинация с default-block-outbound делает allow-список
// фактическим «списком того, что Kill Switch не блокирует» — чем он шире и чем больше в нём
// адресов из приватных/служебных диапазонов (которые атакующий может подставить, если жертва
// резолвит домен через DNS-сервер в контролируемой атакующим сети), тем слабее защита.
//
// Фикс (данный лот): classifyIPs (1) отбрасывает loopback/RFC1918/CGNAT(100.64/10)/
// link-local/multicast/явный bogon, логируя каждый отброшенный адрес; (2) ограничивает ИТОГ
// (v4+v6 вместе) N=4 адресами из одного ответа.
//
// ВАЖНО (зафиксировано в result.md): фильтр НЕ включает IANA-документационные диапазоны
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) — они массово используются как
// стенд-ин «валидного публичного адреса» в СУЩЕСТВУЮЩИХ тестах пакетов killswitch/engine
// (endpoint_test.go, killswitch_uac_windows_test.go, wfp_plan_test.go, engine_r8_test.go),
// трогать которые запрещено правилами владения лота. Табличный тест ниже проверяет только
// диапазоны, явно перечисленные в ТЗ (loopback/RFC1918/CGNAT/link-local/multicast/bogon).

// captureClassifyLog — подменяет classifyDropLogf на время теста и возвращает функцию отмены
// + указатель на собранные сообщения (thread-safe: classifyIPs не параллелится, но тест обязан
// это не предполагать).
func captureClassifyLog(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var msgs []string
	orig := classifyDropLogf
	classifyDropLogf = func(format string, args ...interface{}) {
		mu.Lock()
		msgs = append(msgs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { classifyDropLogf = orig })
	return &msgs
}

// (1) Табличный тест классов адресов (S-11 / PLAN_LOTS acceptance #2).
func TestClassifyIPs_TableOfDisallowedClasses(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		allowed bool
	}{
		// loopback
		{"loopback v4", "127.0.0.1", false},
		{"loopback v6", "::1", false},
		// RFC1918 private
		{"rfc1918 10/8", "10.1.2.3", false},
		{"rfc1918 172.16/12", "172.16.5.6", false},
		{"rfc1918 192.168/16", "192.168.1.1", false},
		{"ULA v6 fc00::/7", "fc00::1", false},
		// CGNAT 100.64.0.0/10
		{"cgnat low", "100.64.0.1", false},
		{"cgnat mid", "100.100.100.1", false},
		{"cgnat high", "100.127.255.254", false},
		// link-local
		{"link-local v4", "169.254.1.1", false},
		{"link-local v6", "fe80::1", false},
		// multicast
		{"multicast v4", "224.0.0.1", false},
		{"multicast v6", "ff02::1", false},
		// bogon (узкий набор, не пересекающийся с TEST-NET/doc-диапазонами)
		{"this-network 0/8", "0.0.0.5", false},
		{"reserved 240/4", "240.1.2.3", false},
		{"limited broadcast", "255.255.255.255", false},
		{"unspecified v4", "0.0.0.0", false},
		{"unspecified v6", "::", false},
		// валидные публичные — обязаны пройти
		{"public v4 8.8.8.8", "8.8.8.8", true},
		{"public v4 1.1.1.1", "1.1.1.1", true},
		{"public v6", "2606:4700:4700::1111", true},
		// НЕ бросать документационные/TEST-NET диапазоны (см. комментарий выше файла)
		{"doc TEST-NET-2 (должен пройти по допущению)", "198.51.100.9", true},
		{"doc v6 2001:db8 (должен пройти по допущению)", "2001:db8::1", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := net.ParseIP(c.ip)
			if ip == nil {
				t.Fatalf("тест некорректен: %q не парсится как IP", c.ip)
			}
			v4, v6 := classifyIPs([]net.IP{ip})
			got := len(v4) > 0 || len(v6) > 0
			if got != c.allowed {
				t.Errorf("classifyIPs(%s): got allowed=%v, want %v (v4=%v v6=%v)", c.ip, got, c.allowed, v4, v6)
			}
		})
	}
}

// (2) «10 адресов в DNS-ответе -> 4 в allow-списке» (PLAN_LOTS acceptance #3).
func TestClassifyIPs_CapsAtFourFromOneResponse(t *testing.T) {
	msgs := captureClassifyLog(t)

	// 10 РАЗНЫХ валидных публичных адресов — реальные well-known DNS-резолверы, ни один не
	// попадает ни в один отбрасываемый класс.
	raw := []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
		"149.112.112.112", "208.67.222.222", "208.67.220.220", "4.2.2.2", "64.6.64.6",
	}
	ips := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		ips = append(ips, net.ParseIP(s))
	}

	v4, v6 := classifyIPs(ips)
	total := len(v4) + len(v6)
	if total != 4 {
		t.Fatalf("classifyIPs(10 адресов): итог = %d, want 4 (v4=%v v6=%v)", total, v4, v6)
	}
	// Первые 4 в порядке резолва (реализация обязана сохранять порядок, не выбирать случайно).
	want := raw[:4]
	got := append(append([]string{}, v4...), v6...)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("classifyIPs(10 адресов) = %v, want первые 4 в порядке резолва %v", got, want)
	}

	if len(*msgs) == 0 {
		t.Error("превышение лимита N=4 обязано логироваться (S-11: «лог по каждому отброшенному»)")
	}
}

// (2b) Через полный путь NormalizeEndpointIPs (резолв домена) — не только напрямую classifyIPs.
func TestNormalizeEndpointIPs_CapsAtFourFromDNSResponse(t *testing.T) {
	raw := []net.IP{
		net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4"), net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1"),
		net.ParseIP("9.9.9.9"), net.ParseIP("149.112.112.112"), net.ParseIP("208.67.222.222"),
		net.ParseIP("208.67.220.220"), net.ParseIP("4.2.2.2"), net.ParseIP("64.6.64.6"),
	}
	withLookup(func(string) ([]net.IP, error) { return raw, nil }, func() {
		v4, v6, err := NormalizeEndpointIPs("poisoned.example")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got := len(v4) + len(v6); got != 4 {
			t.Fatalf("итог = %d, want 4 (v4=%v v6=%v)", got, v4, v6)
		}
	})
}

// (3) Смешанный ответ: DNS-«отравление» приватным/CGNAT/link-local адресом среди валидных —
// вредный адрес НЕ должен попасть в allow-список, валидные — должны, лимит всё ещё соблюдён.
func TestNormalizeEndpointIPs_DropsPoisonedPrivateAndCGNAT(t *testing.T) {
	captureClassifyLog(t)
	poisoned := []net.IP{
		net.ParseIP("8.8.8.8"),      // валидный
		net.ParseIP("192.168.1.1"),  // атака: приватный
		net.ParseIP("100.64.0.1"),   // атака: CGNAT
		net.ParseIP("169.254.1.1"),  // атака: link-local
		net.ParseIP("1.1.1.1"),      // валидный
	}
	withLookup(func(string) ([]net.IP, error) { return poisoned, nil }, func() {
		v4, _, err := NormalizeEndpointIPs("poisoned2.example")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		for _, ip := range v4 {
			if ip == "192.168.1.1" || ip == "100.64.0.1" || ip == "169.254.1.1" {
				t.Errorf("отравленный адрес %s попал в allow-список", ip)
			}
		}
		want := []string{"8.8.8.8", "1.1.1.1"}
		if strings.Join(v4, ",") != strings.Join(want, ",") {
			t.Errorf("v4 = %v, want %v", v4, want)
		}
	})
}
