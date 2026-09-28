package harvester

// Инварианты I-1…I-5 из §5 ТЗ v1.4 — проверяются кодом, а не обещаниями в промпте.
// Часть проверок структурная: они читают исходники самого пакета и падают, если в него
// когда-нибудь принесут сеть или запись в пул узлов.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func productionFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("исходники пакета не найдены")
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0) // без комментариев: смысл имеют идентификаторы
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = f
	}
	return out
}

// I-1. Харвестер не имеет сетевого клиента: в пакете нет импорта net/http вне тестов.
// Проверка сделана белым списком, а не чёрным: любой новый импорт придётся объяснить здесь,
// и «сеть просочилась через незнакомую библиотеку» стало невозможно.
func TestI1_NoNetworkImports(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "context": true, "encoding/base64": true, "encoding/json": true,
		"errors": true, "fmt": true, "html": true, "math": true, "net/url": true,
		"os": true, "regexp": true, "sort": true, "strconv": true, "strings": true,
		"sync": true, "time": true, "unicode": true, "unicode/utf8": true,
		"github.com/apf/adaptive-pathfinder/internal/models": true,
	}
	// net/url — чистый разбор строк, соединений не открывает; os — чтение /proc/meminfo.
	for name, f := range productionFiles(t) {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !allowed[path] {
				t.Errorf("I-1: %s импортирует %q — вне белого списка пакета", name, path)
			}
			if path == "net" || strings.HasPrefix(path, "net/http") {
				t.Errorf("I-1 нарушен: %s импортирует %q", name, path)
			}
		}
	}
}

// I-1, вторая половина: диалер не передаётся. В настройках пакета нет ни одного поля,
// через которое можно было бы внести соединение.
func TestI1_NoDialerInOptions(t *testing.T) {
	rt := reflect.TypeOf(Options{})
	for i := 0; i < rt.NumField(); i++ {
		ft := rt.Field(i).Type.String()
		for _, bad := range []string{"net.", "http.", "Dial", "Conn", "Client"} {
			if strings.Contains(ft, bad) {
				t.Errorf("I-1: поле %s имеет тип %s — похоже на сетевую точку входа",
					rt.Field(i).Name, ft)
			}
		}
	}
	rt = reflect.TypeOf(RunInput{})
	for i := 0; i < rt.NumField(); i++ {
		if strings.Contains(rt.Field(i).Type.String(), "net.") {
			t.Errorf("I-1: RunInput.%s несёт сетевой тип", rt.Field(i).Name)
		}
	}
}

// I-3 и I-4. В пакете нет ни одного упоминания точек, которыми узел попадает в пул или
// получает статус «рабочий». Сканируются идентификаторы AST, а не текст файла: писать про
// эти механизмы в комментариях можно и нужно, вызывать — нельзя.
func TestI3_I4_NoPoolWritesNoVerifyState(t *testing.T) {
	forbidden := map[string]string{
		"mergeFetchedNodes":   "I-3: запись в пул",
		"saveNodes":           "I-3: запись в пул",
		"RestoreRemovedNodes": "I-3: управление пулом",
		"recordNodeVerified":  "I-4: статус «рабочий»",
		"VerifyState":         "I-4: статус «рабочий»",
		"VerifyVerified":      "I-4: статус «рабочий»",
		"LastVerifiedAt":      "I-4: статус «рабочий»",
		"VerifiedCount":       "I-4: статус «рабочий»",
		"BlacklistedUntil":    "I-3: судьба узла — дело движка (AI-7)",
	}
	for name, f := range productionFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if why, bad := forbidden[id.Name]; bad {
				t.Errorf("%s: идентификатор %q — %s", name, id.Name, why)
			}
			return true
		})
	}
}

// I-3, вторая половина: у харвестера физически нет метода, которым можно было бы что-то
// сохранить или объявить рабочим. Контракт — ровно два метода.
func TestI3_HarvesterInterfaceIsMinimal(t *testing.T) {
	it := reflect.TypeOf((*Harvester)(nil)).Elem()
	if it.NumMethod() != 2 {
		t.Fatalf("контракт Harvester обязан состоять из Run и Available, методов %d", it.NumMethod())
	}
	names := map[string]bool{}
	for i := 0; i < it.NumMethod(); i++ {
		names[it.Method(i).Name] = true
	}
	if !names["Run"] || !names["Available"] {
		t.Fatalf("ожидались Run и Available, получено %v", names)
	}

	// И у самой реализации нет ничего похожего на «сохранить/подтвердить/забанить».
	rt := reflect.TypeOf(New(Options{}))
	for i := 0; i < rt.NumMethod(); i++ {
		n := strings.ToLower(rt.Method(i).Name)
		for _, bad := range []string{"verif", "merge", "save", "add", "remove", "ban", "blacklist", "store"} {
			if strings.Contains(n, bad) {
				t.Errorf("I-3/I-4: у харвестера есть метод %s — он не имеет права так уметь",
					rt.Method(i).Name)
			}
		}
	}
}

// I-2. Свойство проверяется на всех сохранённых образцах разом: каждый Raw обязан лежать
// в теле дословно.
func TestI2_EveryCandidateIsLiteralSubstring(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		extractSample(t, e.Name()) // проверка I-2 встроена в помощник
	}
}
