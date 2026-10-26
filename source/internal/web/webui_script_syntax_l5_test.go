package web

import (
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Лот L5. Web UI — это сотни строк JavaScript внутри Go-строки; ошибка синтаксиса в любой из
// них молча ломает ВСЮ страницу (ни одна вкладка не оживает), а Go-компилятор её не видит.
// Тест достаёт каждый встроенный <script> из отдаваемой страницы и просит node только
// разобрать его (--check), ничего не выполняя. Нет node — тест пропускается (на хосте без
// node проверка недоступна, это не отказ).
func TestWebUI_InlineScriptsCompile(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node не найден в PATH — синтаксис встроенного JS не проверяется")
	}
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.apiUI(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("GET / = %d", w.Code)
	}

	scripts := regexp.MustCompile(`(?is)<script(\s[^>]*)?>(.*?)</script>`).FindAllStringSubmatch(w.Body.String(), -1)
	if len(scripts) == 0 {
		t.Fatal("в странице нет встроенных скриптов — проверять нечего")
	}
	dir := t.TempDir()
	checked := 0
	for i, m := range scripts {
		if strings.Contains(strings.ToLower(m[1]), "src=") || strings.TrimSpace(m[2]) == "" {
			continue // внешний скрипт или пустой тег
		}
		file := filepath.Join(dir, fmt.Sprintf("script%d.js", i))
		if err := os.WriteFile(file, []byte(m[2]), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(node, "--check", file).CombinedOutput(); err != nil {
			t.Errorf("встроенный скрипт №%d не разбирается node:\n%s", i, strings.TrimSpace(string(out)))
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("ни один встроенный скрипт не проверен")
	}
}
