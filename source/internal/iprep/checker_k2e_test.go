// checker_k2e_test.go — К2-E П15 (свод C, трек 1 №15; B1 #4).
//
// Три дефекта одной функции проверки репутации IP:
//  1. запрос шёл по http:// — адрес проверяемого узла и ответ о нём видны любому наблюдателю
//     на пути, включая провайдера, от которого пользователь и прячется;
//  2. User-Agent называл продукт и версию («APF/1.x») — уникальная подпись VPN-клиента в
//     каждом запросе к публичному API;
//  3. json.Decode читал тело БЕЗ ограничения размера — ответ произвольной длины от чужого
//     сервера превращался в неограниченное потребление памяти.
package iprep

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestK2E_IPAPI_DefaultURL_IsHTTPS — адрес по умолчанию не http://.
func TestK2E_IPAPI_DefaultURL_IsHTTPS(t *testing.T) {
	if strings.HasPrefix(ipAPIBaseURL, "http://") {
		t.Fatalf("ip-api опрашивается по незашифрованному каналу: %q", ipAPIBaseURL)
	}
	if !strings.HasPrefix(ipAPIBaseURL, "https://") {
		t.Fatalf("ожидался https://, получено %q", ipAPIBaseURL)
	}
	if strings.HasPrefix(proxyCheckBaseURL, "http://") {
		t.Fatalf("proxycheck опрашивается по незашифрованному каналу: %q", proxyCheckBaseURL)
	}
	t.Logf("OK: %s / %s", ipAPIBaseURL, proxyCheckBaseURL)
}

// TestK2E_UserAgent_DoesNotIdentifyAPF — заголовок не выдаёт продукт и версию.
func TestK2E_UserAgent_DoesNotIdentifyAPF(t *testing.T) {
	var gotUA atomic.Value
	gotUA.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.Header.Get("User-Agent"))
		w.Write([]byte(`{"status":"success","proxy":false,"hosting":false,"isp":"ISP","query":"1.2.3.4"}`))
	}))
	defer srv.Close()

	origIP, origPC := ipAPIBaseURL, proxyCheckBaseURL
	ipAPIBaseURL = srv.URL
	proxyCheckBaseURL = srv.URL
	defer func() { ipAPIBaseURL, proxyCheckBaseURL = origIP, origPC }()

	c := NewChecker(nil)
	if _, err := c.CheckIP(context.Background(), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	ua := gotUA.Load().(string)
	low := strings.ToLower(ua)
	if strings.Contains(low, "apf") || strings.Contains(low, "pathfinder") {
		t.Fatalf("User-Agent выдаёт продукт: %q", ua)
	}
	t.Logf("OK: User-Agent = %q", ua)
}

// hugeBodyHandler отдаёт валидный JSON, за которым следует очень длинный «хвост».
// Без LimitReader Decode прочитает столько, сколько отдаст сервер.
func hugeBodyHandler(prefix string, tailMB int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(prefix))
		chunk := make([]byte, 1024*1024)
		for i := range chunk {
			chunk[i] = ' '
		}
		for i := 0; i < tailMB; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}
}

// TestK2E_IPAPI_BodyLimited — гигантский ответ ip-api обрезается лимитом, а не съедает память.
func TestK2E_IPAPI_BodyLimited(t *testing.T) {
	srv := httptest.NewServer(hugeBodyHandler(
		`{"status":"success","proxy":false,"hosting":true,"isp":"Huge","query":"9.9.9.9"}`, 24))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	c := NewChecker(nil)
	info, err := c.checkIPAPI(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("валидный JSON в начале ответа должен разбираться: %v", err)
	}
	if info.ISP != "Huge" {
		t.Errorf("разбор испорчен обрезкой: %+v", info)
	}
	if got := bodyLimitBytes; got <= 0 {
		t.Fatalf("лимит размера тела не задан: %d", got)
	}
	t.Logf("OK: ответ ограничен %d байтами, разбор корректен", bodyLimitBytes)
}

// TestK2E_ProxyCheck_BodyLimited — то же для proxycheck.io.
func TestK2E_ProxyCheck_BodyLimited(t *testing.T) {
	srv := httptest.NewServer(hugeBodyHandler(
		`{"status":"ok","9.9.9.9":{"proxy":"no","vpn":"no","type":"Residential","isp":"Huge"}}`, 24))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := NewChecker(nil)
	info, err := c.checkProxyCheck(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("валидный JSON в начале ответа должен разбираться: %v", err)
	}
	if info.ISP != "Huge" {
		t.Errorf("разбор испорчен обрезкой: %+v", info)
	}
	t.Log("OK: ответ proxycheck ограничен по размеру")
}

// TestK2E_BodyLimit_CutsOversizedJSON — тело, ПРЕВЫШАЮЩЕЕ лимит уже в самом JSON, приводит к
// честной ошибке разбора, а не к чтению гигабайтов.
func TestK2E_BodyLimit_CutsOversizedJSON(t *testing.T) {
	big := strings.Repeat("a", bodyLimitBytes+4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","isp":"` + big + `","query":"8.8.8.8"}`))
	}))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	if _, err := NewChecker(nil).checkIPAPI(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("ответ длиннее лимита должен давать ошибку разбора, а не молча проходить")
	} else {
		t.Logf("OK: %v", err)
	}
}
