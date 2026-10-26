package singbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/localauth"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Лот L4 (U-05): локальные socks-in/http-in и Clash API не должны быть открыты любому
// приложению на устройстве. Пароль сессии - только когда трафик пользователя идёт через TUN
// (режим VPN); в режимах «прокси» и «гибрид» вход остаётся открытым для браузера и приложений.
// Секрет Clash API - всегда. sing-box не запускается: проверяется собранный конфиг.

func l4Node() *models.Node {
	return &models.Node{
		Protocol: models.ProtoVLESS, Address: "192.0.2.1", Port: 443,
		UUID: "12345678-1234-1234-1234-123456789012",
	}
}

func inboundByTag(t *testing.T, cfg *Config, tag string) Inbound {
	t.Helper()
	for _, in := range cfg.Inbounds {
		if in.Tag == tag {
			return in
		}
	}
	t.Fatalf("в конфиге нет входа %s", tag)
	return Inbound{}
}

func TestL4_VPNMode_LocalInboundsRequireSessionPassword(t *testing.T) {
	b := NewBuilder(10808, true) // TUN без гибрида = режим VPN
	cfg, err := b.BuildSingle(l4Node())
	if err != nil {
		t.Fatal(err)
	}
	u, p := localauth.Credentials()
	for _, tag := range []string{"socks-in", "http-in"} {
		in := inboundByTag(t, cfg, tag)
		if len(in.Users) != 1 || in.Users[0].Username != u || in.Users[0].Password != p {
			t.Errorf("%s: users=%+v, ожидался один пользователь с учётными данными сессии", tag, in.Users)
		}
	}
	if tun := inboundByTag(t, cfg, "tun-in"); len(tun.Users) != 0 {
		t.Errorf("у tun-входа не должно быть users: %+v", tun.Users)
	}
}

func TestL4_ProxyAndHybridModes_InboundsStayOpen(t *testing.T) {
	proxy := NewBuilder(10808, false)
	hybrid := NewBuilder(10808, true)
	hybrid.SetHybrid(true)
	for name, b := range map[string]*Builder{"proxy": proxy, "hybrid": hybrid} {
		if b.LocalAuthEnabled() {
			t.Errorf("%s: LocalAuthEnabled должен быть false", name)
		}
		cfg, err := b.BuildSingle(l4Node())
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range []string{"socks-in", "http-in"} {
			if in := inboundByTag(t, cfg, tag); len(in.Users) != 0 {
				t.Errorf("%s/%s: вход обязан остаться открытым (браузер и приложения не знают пароля сессии), users=%+v", name, tag, in.Users)
			}
		}
	}
}

func TestL4_ClashAPISecretIsAlwaysSet(t *testing.T) {
	for name, b := range map[string]*Builder{"proxy": NewBuilder(10808, false), "vpn": NewBuilder(10808, true)} {
		cfg, err := b.BuildSingle(l4Node())
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Experimental == nil || cfg.Experimental.ClashAPI == nil {
			t.Fatalf("%s: clash_api не объявлен", name)
		}
		if got := cfg.Experimental.ClashAPI.Secret; got == "" || got != localauth.ClashSecret() {
			t.Errorf("%s: secret=%q, ожидался секрет сессии", name, got)
		}
	}
}

// В JSON "users" и "secret" попадают только когда заданы (прежние конфигурации не меняются).
func TestL4_JSONShape(t *testing.T) {
	open, _ := NewBuilder(10808, false).BuildSingle(l4Node())
	raw, _ := json.Marshal(open.Inbounds)
	if strings.Contains(string(raw), `"users"`) {
		t.Errorf("в открытом режиме в JSON входов не должно быть users: %s", raw)
	}
	vpn, _ := NewBuilder(10808, true).BuildSingle(l4Node())
	raw, _ = json.Marshal(vpn.Inbounds)
	if !strings.Contains(string(raw), `"users"`) {
		t.Errorf("в режиме VPN в JSON входов нет users: %s", raw)
	}
}

// Менеджер трафика и переключатель узла обязаны присылать секрет: сервер без него отвечает 401.
func newSecretClashServer(t *testing.T, seen *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+localauth.ClashSecret() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxies/"):
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/connections":
			_, _ = w.Write([]byte(`{"downloadTotal":10,"uploadTotal":20,"connections":[{"id":"a"}]}`))
		case r.URL.Path == "/traffic":
			_, _ = w.Write([]byte(`{"up":1,"down":2}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestL4_SwitchOutboundSendsClashSecret(t *testing.T) {
	var seen []string
	srv := newSecretClashServer(t, &seen)
	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := switchOutboundFn(addr, "select", "node-1", 2*time.Second); err != nil {
		t.Fatalf("переключение с секретом: %v (запросы: %v)", err, seen)
	}
}

func TestL4_TrafficMonitorSendsClashSecret(t *testing.T) {
	var seen []string
	srv := newSecretClashServer(t, &seen)
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	tm := NewTrafficMonitor(port)
	got := make(chan TrafficStats, 1)
	tm.OnStats = func(s TrafficStats) {
		select {
		case got <- s:
		default:
		}
	}
	tm.poll()
	select {
	case s := <-got:
		if s.UpBytes != 20 || s.DownBytes != 10 {
			t.Errorf("статистика разобрана неверно: %+v", s)
		}
	default:
		t.Fatalf("менеджер трафика не получил ответ (сервер вернул 401?). Запросы: %v", seen)
	}
}

// Сервер без секрета (серверная роль, старый конфиг) заголовок просто игнорирует.
func TestL4_ClashClientsWorkAgainstServerWithoutSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"downloadTotal":1,"uploadTotal":2,"connections":[]}`))
	}))
	defer srv.Close()
	if err := switchOutboundFn(strings.TrimPrefix(srv.URL, "http://"), "select", "n", time.Second); err != nil {
		t.Fatalf("сервер без секрета: %v", err)
	}
}

// Проб-инстансы проверки узлов (SOCKS-only, не TUN) получают пароль сессии принудительно.
func TestL4_ForceLocalAuthProtectsProbeInstance(t *testing.T) {
	b := NewBuilder(10808, false)
	if b.LocalAuthEnabled() {
		t.Fatal("без принуждения режим прокси остаётся открытым")
	}
	b.SetForceLocalAuth(true)
	if !b.LocalAuthEnabled() {
		t.Fatal("принудительный пароль не включился")
	}
	cfg, err := b.BuildSingle(l4Node())
	if err != nil {
		t.Fatal(err)
	}
	u, p := localauth.Credentials()
	for _, tag := range []string{"socks-in", "http-in"} {
		in := inboundByTag(t, cfg, tag)
		if len(in.Users) != 1 || in.Users[0].Username != u || in.Users[0].Password != p {
			t.Errorf("%s: users=%+v", tag, in.Users)
		}
	}
	for _, in := range cfg.Inbounds {
		if in.Tag == "tun-in" {
			t.Error("в проб-инстансе появился TUN")
		}
	}
}

// Менеджер трафика работает и против сервера без секрета (серверная роль, старый конфиг): заголовок
// Authorization такой сервер просто игнорирует.
func TestL4_TrafficMonitorWorksAgainstServerWithoutSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"downloadTotal":7,"uploadTotal":9,"connections":[]}`))
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	tm := NewTrafficMonitor(port)
	got := make(chan TrafficStats, 1)
	tm.OnStats = func(s TrafficStats) {
		select {
		case got <- s:
		default:
		}
	}
	tm.poll()
	select {
	case s := <-got:
		if s.UpBytes != 9 || s.DownBytes != 7 {
			t.Errorf("статистика разобрана неверно: %+v", s)
		}
	default:
		t.Fatal("менеджер трафика не получил ответ сервера без секрета")
	}
}
