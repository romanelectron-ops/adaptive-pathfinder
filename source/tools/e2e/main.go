// E2E-харнесс пользовательского слоя APF (Часть A4 методики).
// Запуск: go run ./tools/e2e   (поднимает web.Server на :18091 и дёргает эндпоинты по HTTP)
package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/web"
)

const base = "http://127.0.0.1:18091"

func call(method, path, body string) (int, string) {
	var r *http.Response
	var err error
	if method == "GET" {
		r, err = http.Get(base + path)
	} else {
		r, err = http.Post(base+path, "application/json", strings.NewReader(body))
	}
	if err != nil {
		return 0, "ERR " + err.Error()
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

var pass, fail int

func check(name string, cond bool, detail string) {
	if cond {
		pass++
		fmt.Printf("  PASS %s\n", name)
	} else {
		fail++
		fmt.Printf("  FAIL %s — %s\n", name, detail)
	}
}

func main() {
	cfg := models.DefaultConfig()
	eng := engine.New(cfg)
	srv := web.New(eng, 18091)
	go func() { _ = srv.Start() }()
	time.Sleep(700 * time.Millisecond)

	fmt.Println("### A. GET-эндпоинты (статусы/панели) ###")
	for _, p := range []string{
		"/", "/api/state", "/api/nodes", "/api/stats", "/api/logs", "/api/config",
		"/api/leakguard/status", "/api/leakguard/browser-instructions", "/api/dpi/status",
		"/api/catalog/status", "/api/adblock/status", "/api/antiblock/status",
		"/api/antiblock/bypass-list", "/api/fallback/status", "/api/watchdog/status",
		"/api/session/status", "/api/diagnostics", "/api/singbox",
	} {
		code, body := call("GET", p, "")
		check(p, code >= 200 && code < 500, fmt.Sprintf("code=%d %.60s", code, body))
	}

	fmt.Println("\n### B. Сценарий add-node → pin → state → unpin ###")
	code, _ := call("POST", "/api/add-node", `{"link":"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&pbk=abc#N1"}`)
	check("add-node", code == 200, fmt.Sprintf("code=%d", code))
	var id string
	if n := eng.GetNodes(); len(n) > 0 {
		id = n[0].ID
	}
	check("узел в пуле", id != "", "нет узла")
	code, st := call("GET", "/api/state", "")
	_ = st
	code, _ = call("POST", "/api/pin", `{"node_id":"`+id+`","pinned":true}`)
	check("pin", code == 200 && eng.IsPinned(), fmt.Sprintf("code=%d pinned=%v", code, eng.IsPinned()))
	code, _ = call("POST", "/api/pin", `{"node_id":"`+id+`","pinned":false}`)
	check("unpin", code == 200 && !eng.IsPinned(), fmt.Sprintf("code=%d", code))

	fmt.Println("\n### C. Негатив/границы ###")
	code, body := call("POST", "/api/connect-node", `{"node_id":"__nope__"}`)
	check("connect несуществующего → 4xx", code >= 400, fmt.Sprintf("code=%d %s", code, body))
	code, _ = call("POST", "/api/add-node", `{not json`)
	check("битый JSON → 4xx", code >= 400, fmt.Sprintf("code=%d", code))
	code, _ = call("GET", "/api/nonexistent", "")
	check("неизвестный путь → 404", code == 404, fmt.Sprintf("code=%d", code))
	code, _ = call("GET", "/api/connect-node", "")
	check("GET на POST → 405", code == 405, fmt.Sprintf("code=%d", code))

	fmt.Printf("\n==== E2E ИТОГ: PASS=%d FAIL=%d ====\n", pass, fail)
	if fail > 0 {
		fmt.Println("ЕСТЬ ПРОВАЛЫ")
	} else {
		fmt.Println("ВСЕ СЦЕНАРИИ ПРОЙДЕНЫ")
	}
}
