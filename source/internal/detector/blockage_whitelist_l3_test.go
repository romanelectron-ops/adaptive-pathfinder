package detector

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// Лот L3: распознавание «белых списков» мобильного интернета. Все пробы — заглушки, настоящая
// сеть не трогается.

// stubNet возвращает tcpDialer, который «открывает» только перечисленные адреса.
func stubNet(open ...string) func(ctx context.Context, addr string) bool {
	set := make(map[string]bool, len(open))
	for _, a := range open {
		set[a] = true
	}
	return func(ctx context.Context, addr string) bool { return set[addr] }
}

func diag(t *testing.T, d *BlockageDetector) BlockageType {
	t.Helper()
	bt, err := d.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	return bt
}

// Критерий приёмки L3, часть 1: «RU открыт, 1.1.1.1:443 закрыт» → BlockageWhitelist.
func TestL3_Diagnose_ForeignClosedDomesticOpen_IsWhitelist(t *testing.T) {
	d := New()
	d.tcpDialer = stubNet("ya.ru:443", "gosuslugi.ru:443", "vk.com:443")
	if got := diag(t, d); got != BlockageWhitelist {
		t.Fatalf("Diagnose = %s, ожидалось whitelist", got)
	}
}

// Критерий приёмки L3, часть 2: «всё закрыто» → по-прежнему Complete.
func TestL3_Diagnose_EverythingClosed_StillComplete(t *testing.T) {
	d := New()
	d.tcpDialer = stubNet() // ничего не открывается
	if got := diag(t, d); got != BlockageComplete {
		t.Fatalf("Diagnose = %s, ожидалось complete", got)
	}
}

// Наборы разрешённых сервисов у операторов разные: достаточно любого одного российского.
func TestL3_Diagnose_AnySingleDomesticIsEnough(t *testing.T) {
	for _, only := range whitelistDomesticProbes {
		d := New()
		d.tcpDialer = stubNet(only)
		if got := diag(t, d); got != BlockageWhitelist {
			t.Errorf("открыт только %s: Diagnose = %s, ожидалось whitelist", only, got)
		}
	}
}

// Если открыт ХОТЯ БЫ ОДИН зарубежный адрес из проверяемых — это не белые списки и не «полная
// блокировка»: сеть жива. «По IP» объявляется, только когда закрыты ДВА независимых адреса
// (1.1.1.1 и 8.8.8.8); один закрытый адрес блокировкой по IP не считается.
func TestL3_Diagnose_AnyForeignOpen_IsNotWhitelistNotComplete(t *testing.T) {
	for _, foreign := range whitelistForeignProbes {
		d := New()
		d.tcpDialer = stubNet(foreign, "ya.ru:443", "gosuslugi.ru:443", "vk.com:443")
		d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
		want := BlockageIP // 1.1.1.1 и 8.8.8.8 закрыты
		if foreign == googleProbe {
			want = BlockageNone // закрыт один 1.1.1.1
		}
		if got := diag(t, d); got != want {
			t.Errorf("зарубежный %s открыт, 1.1.1.1 закрыт: Diagnose = %s, ожидалось %s", foreign, got, want)
		}
	}
}

// Закрыт только 1.1.1.1, остальное работает: ни белые списки, ни «полная блокировка», ни «по IP»
// (один адрес не доказывает блокировку, а «по IP» подменяет веса выбора на всю сессию).
func TestL3_Diagnose_OnlyCloudflareClosed_IsNone(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return addr != cloudflareProbe }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	if got := diag(t, d); got != BlockageNone {
		t.Fatalf("закрытый одиночный 1.1.1.1 дал %s; ожидалось none", got)
	}
}

// Все пробы делят ОДНО окно d.timeout: когда молчит всё, диагностика укладывается в него, а не в
// d.timeout + отдельные 3 с (прежняя схема).
func TestL3_Diagnose_AllSilent_StaysInOneWindow(t *testing.T) {
	d := New()
	d.timeout = 400 * time.Millisecond
	old := extraProbesGrace
	extraProbesGrace = 50 * time.Millisecond
	defer func() { extraProbesGrace = old }()
	d.tcpDialer = func(ctx context.Context, addr string) bool {
		<-ctx.Done() // молчит, пока не кончится окно
		return false
	}
	start := time.Now()
	got := diag(t, d)
	if elapsed := time.Since(start); elapsed > 1200*time.Millisecond {
		t.Errorf("диагностика заняла %v при окне %v - пробы идут в отдельных окнах", elapsed, d.timeout)
	}
	if got != BlockageComplete {
		t.Errorf("молчит всё: Diagnose = %s, ожидалось complete", got)
	}
}

// 1.1.1.1 молчит (не закрыт, а не отвечает): остальные пробы стартуют после паузы, не дожидаясь его
// таймаута, и открытый 8.8.8.8 даёт «сеть жива».
func TestL3_Diagnose_SilentCloudflare_ExtraProbesStartAfterGrace(t *testing.T) {
	d := New()
	d.timeout = 2 * time.Second
	old := extraProbesGrace
	extraProbesGrace = 30 * time.Millisecond
	defer func() { extraProbesGrace = old }()
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	d.tcpDialer = func(ctx context.Context, addr string) bool {
		switch addr {
		case cloudflareProbe:
			<-ctx.Done()
			return false
		case googleProbe:
			return true
		}
		return false
	}
	start := time.Now()
	got := diag(t, d)
	if got == BlockageWhitelist || got == BlockageComplete {
		t.Errorf("при открытом 8.8.8.8 получено %s", got)
	}
	// 1.1.1.1 держит окно до конца (2 с): ответ нельзя вернуть раньше его результата.
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond || elapsed > 3500*time.Millisecond {
		t.Errorf("время %v вне ожидаемого окна ~2 с", elapsed)
	}
}

// Под `go test` реальный DNS-запрос за российскими именами не уходит (netguard): раньше резолв
// шёл мимо него.
func TestL3_CanTCPConnectPublic_NoRealLookupUnderTest(t *testing.T) {
	d := New()
	if d.canTCPConnectPublic(context.Background(), "ya.ru:443") {
		t.Fatal("под go test путь с реальным резолвом обязан возвращать false")
	}
}

// Путь «имя - публичные адреса - подключение»: частные/CGNAT отброшены, IPv4 раньше IPv6, не более
// двух адресов.
func TestL3_CanTCPConnectPublic_FilterAndOrder(t *testing.T) {
	d := New()
	d.lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("10.0.0.1")},        // частный - заглушка провайдера
			{IP: net.ParseIP("2a02:6b8::2:242")}, // публичный IPv6 - в конец
			{IP: net.ParseIP("100.64.0.9")},      // CGNAT
			{IP: net.ParseIP("93.184.216.34")},
			{IP: net.ParseIP("8.8.4.4")},
		}, nil
	}
	var tried []string
	d.ipDialer = func(ctx context.Context, addr string) bool { tried = append(tried, addr); return false }
	if d.canTCPConnectPublic(context.Background(), "ya.ru:443") {
		t.Fatal("все подключения неудачны, а проба вернула true")
	}
	want := []string{"93.184.216.34:443", "8.8.4.4:443"}
	if strings.Join(tried, ",") != strings.Join(want, ",") {
		t.Errorf("пробовались %v, ожидалось %v (IPv4 раньше IPv6, частные и CGNAT отброшены, не больше двух)", tried, want)
	}
	// Открывается второй адрес - проба успешна.
	d.ipDialer = func(ctx context.Context, addr string) bool { return addr == "8.8.4.4:443" }
	if !d.canTCPConnectPublic(context.Background(), "ya.ru:443") {
		t.Error("второй публичный адрес открыт, а проба вернула false")
	}
	// Только частные адреса (заглушка) - никаких подключений.
	d.lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.1")}}, nil
	}
	called := false
	d.ipDialer = func(ctx context.Context, addr string) bool { called = true; return true }
	if d.canTCPConnectPublic(context.Background(), "ya.ru:443") || called {
		t.Error("заглушка с частным адресом принята за настоящий сервис")
	}
}

// Прежние пути не затронуты: при открытом 1.1.1.1 лишних проб нет и ответ прежний.
func TestL3_Diagnose_ForeignOpen_NoExtraProbes(t *testing.T) {
	d := New()
	var asked []string
	d.tcpDialer = func(ctx context.Context, addr string) bool { asked = append(asked, addr); return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return false }
	if got := diag(t, d); got != BlockageDNS {
		t.Fatalf("Diagnose = %s, ожидалось dns (путь, не связанный с белыми списками)", got)
	}
	if len(asked) != 1 || asked[0] != "1.1.1.1:443" {
		t.Errorf("при открытом 1.1.1.1 проверки белых списков не нужны, а пробы были: %v", asked)
	}
}

// На белых списках зарубежный адрес молчит до таймаута: пробы обязаны идти параллельно, иначе
// диагностика растянется на (число проб × таймаут).
func TestL3_Diagnose_ProbesRunInParallel(t *testing.T) {
	d := New()
	const delay = 300 * time.Millisecond
	d.tcpDialer = func(ctx context.Context, addr string) bool {
		time.Sleep(delay)
		return strings.HasSuffix(addr, "ya.ru:443")
	}
	start := time.Now()
	got := diag(t, d)
	elapsed := time.Since(start)
	if got != BlockageWhitelist {
		t.Fatalf("Diagnose = %s, ожидалось whitelist", got)
	}
	// Последовательно было бы 1 + 5 проб = 6 × delay (1,8 с); параллельно — 2 × delay (0,6 с).
	if elapsed > 1200*time.Millisecond {
		t.Errorf("диагностика заняла %v — пробы белых списков идут не параллельно", elapsed)
	}
}

// Отменённый контекст — по-прежнему Complete (прежний контракт, проверяется и в detector_extra_test).
func TestL3_Diagnose_CancelledContext_StillComplete(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bt, err := d.Diagnose(ctx)
	if err != nil || bt != BlockageComplete {
		t.Fatalf("Diagnose(cancelled) = %s, %v; ожидалось complete", bt, err)
	}
}

func TestL3_Strategy_WhitelistHasNoTor(t *testing.T) {
	s := SelectStrategy(BlockageWhitelist)
	if strings.Contains(strings.ToLower(s.Primary+" "+s.Fallback), "tor") {
		t.Errorf("стратегия белых списков обещает Tor: %+v", s)
	}
	if !s.UseReality || s.UseChain || s.UseCDN {
		t.Errorf("ожидался Reality без цепочки и CDN: %+v", s)
	}
	if s.Primary == "" || s.Fallback == "" || s.Reason == "" {
		t.Errorf("пустые поля стратегии: %+v", s)
	}
	if strings.Contains(strings.ToLower(s.Reason), "snowflake") {
		t.Errorf("причина обещает Snowflake: %q", s.Reason)
	}
}

func TestL3_TypeValuesAndName(t *testing.T) {
	if BlockageWhitelist.String() != "whitelist" {
		t.Errorf("String() = %q", BlockageWhitelist.String())
	}
	// Прежние номера не сдвинуты: новый тип стоит последним.
	if int(BlockageComplete) != 5 || int(BlockageWhitelist) != 6 {
		t.Errorf("номера типов сдвинулись: complete=%d whitelist=%d", BlockageComplete, BlockageWhitelist)
	}
}

func TestL3_Report_WhitelistIsHonest(t *testing.T) {
	d := New()
	r := d.buildReport(BlockageWhitelist, SelectStrategy(BlockageWhitelist))
	for _, want := range []string{"белые списки", "российские", "Определено по косвенным признакам"} {
		if !strings.Contains(r, want) {
			t.Errorf("в отчёте нет %q:\n%s", want, r)
		}
	}
	if strings.Contains(r, "последний шанс") {
		t.Errorf("отчёт белых списков советует Tor как последний шанс:\n%s", r)
	}
}

func TestL3_DiagnoseAndRecommend_Whitelist(t *testing.T) {
	d := New()
	d.tcpDialer = stubNet("ya.ru:443")
	bt, strategy, report := d.DiagnoseAndRecommend(context.Background())
	if bt != BlockageWhitelist || strategy.Primary != "vless+reality" || report == "" {
		t.Fatalf("bt=%s strategy=%+v report=%q", bt, strategy, report)
	}
}

// Как только открылась любая зарубежная цель, остальные пробы обрываются: ответ «не белые списки»
// уже известен, ждать таймаута остальных незачем.
func TestL3_Diagnose_ForeignOpenCancelsRemainingProbes(t *testing.T) {
	d := New()
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	d.tcpDialer = func(ctx context.Context, addr string) bool {
		switch addr {
		case "1.1.1.1:443":
			return false
		case "8.8.8.8:443":
			return true
		}
		select { // остальные «молчат», пока их не отменят
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Second):
			return false
		}
	}
	start := time.Now()
	got := diag(t, d)
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("диагностика ждала молчащие пробы %v вместо досрочного выхода", elapsed)
	}
	if got == BlockageWhitelist || got == BlockageComplete {
		t.Errorf("открытый 8.8.8.8 принят за %s", got)
	}
}

// Набор зарубежных целей не сводится к публичным DNS-резолверам (их режут разом, оставляя
// остальной интернет) и включает IPv6 (в IPv6-only сети IPv4-литералы закрыты).
func TestL3_ForeignProbeSetIsNotJustDNSResolvers(t *testing.T) {
	var hasSite, hasV6 bool
	for _, a := range whitelistForeignProbes {
		if strings.HasPrefix(a, "[") {
			hasV6 = true
		}
		if host, _, err := net.SplitHostPort(a); err == nil && net.ParseIP(host) == nil {
			hasSite = true
		}
	}
	if !hasSite || !hasV6 {
		t.Errorf("в зарубежных пробах нет обычного сайта (%v) или IPv6 (%v): %v", hasSite, hasV6, whitelistForeignProbes)
	}
}

// Заглушки провайдеров и captive-порталы отдают на любое имя частный/CGNAT/локальный адрес.
func TestL3_IsPublicIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.4.4", true}, {"93.184.216.34", true}, {"2a02:6b8::2:242", true},
		{"10.1.2.3", false}, {"172.16.0.9", false}, {"192.168.1.1", false},
		{"127.0.0.1", false}, {"::1", false}, {"169.254.1.1", false}, {"0.0.0.0", false},
		{"100.64.0.1", false}, {"100.127.255.254", false}, {"100.128.0.1", true}, {"100.63.255.255", true},
		{"224.0.0.1", false}, {"fe80::1", false}, {"fd00::1", false},
	}
	for _, c := range cases {
		if got := isPublicIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isPublicIP(%s) = %v, ожидалось %v", c.ip, got, c.want)
		}
	}
	if isPublicIP(nil) {
		t.Error("isPublicIP(nil) = true")
	}
}
