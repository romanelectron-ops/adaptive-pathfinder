// Command genksrules — генератор списков имён правил Kill Switch (B-0403 · R-7, C-13).
//
// Запуск: `go generate ./internal/killswitch` (рабочий каталог — каталог пакета killswitch).
//
// Что делает:
//  1. пишет `internal/killswitch/ks_rules.json` — машиночитаемый экспорт списка;
//  2. находит в дереве репозитория ВСЕ .bat-скрипты аварийного восстановления и переписывает в них
//     блок `for %%R in ( ... ) do (` списком имён из Go.
//
// Скрипты не ищутся по фиксированному перечню: критерий — наличие блока, все элементы которого
// начинаются с префикса правил APF. Новый скрипт с таким блоком подхватится сам, а забытый старый
// не останется с устаревшим списком.
//
// Переписывание побайтовое: трогаются ТОЛЬКО строки внутри блока, остальные байты (кодировка,
// CRLF, псевдографика в рамках) сохраняются как есть.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
)

const (
	blockOpen  = "for %%R in ("
	blockClose = ") do ("
)

// skipDirs — каталоги, куда генератору ходить незачем (и где .bat могут быть чужими).
var skipDirs = map[string]bool{
	"vendor": true, ".git": true, "node_modules": true, "dist": true,
}

func main() {
	var repoFlag, jsonFlag string
	flag.StringVar(&repoFlag, "repo", "", "корень репозитория (по умолчанию — поиск вверх от текущего каталога)")
	flag.StringVar(&jsonFlag, "json", "ks_rules.json", "куда писать машиночитаемый экспорт")
	flag.Parse()

	names := killswitch.WindowsRuleNames()
	if len(names) == 0 {
		fatalf("список правил пуст — генерировать нечего")
	}

	if err := writeJSON(jsonFlag, names); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("genksrules: записан %s (%d правил)\n", jsonFlag, len(names))

	root := repoFlag
	if root == "" {
		var err error
		if root, err = findRepoRoot(); err != nil {
			fatalf("%v", err)
		}
	}

	changed, seen, err := rewriteScripts(root, names)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("genksrules: скриптов с блоком правил найдено %d, обновлено %d (корень %s)\n",
		seen, changed, root)
	if seen == 0 {
		// Не ошибка (модуль могли распространить отдельно), но сказать об этом надо: молчаливое
		// «0 файлов» неотличимо от «генератор не нашёл то, что должен был».
		fmt.Println("genksrules: ВНИМАНИЕ — ни одного .bat со списком правил не найдено")
	}
}

func writeJSON(path string, names []string) error {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("  \"_comment\": \"СГЕНЕРИРОВАНО `go generate ./internal/killswitch` — вручную не править. " +
		"Единственный источник истины: windowsRuleSuffixes в internal/killswitch/killswitch.go.\",\n")
	fmt.Fprintf(&b, "  %q: %q,\n", "rule_prefix", killswitch.RulePrefix())
	fmt.Fprintf(&b, "  %q: %q,\n", "tun_subnet", killswitch.TunSubnet())
	b.WriteString("  \"rules\": [\n")
	for i, n := range names {
		sep := ","
		if i == len(names)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "    %q%s\n", n, sep)
	}
	b.WriteString("  ]\n}\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	return nil
}

// findRepoRoot ищет корень репозитория.
//
// Останавливаться на ПЕРВОМ предке, где нашлись скрипты, нельзя: копии списка лежат и внутри
// модуля (source/scripts), и в корне репозитория — генератор обновил бы внутреннюю и оставил
// внешние. Берётся САМЫЙ ВНЕШНИЙ предок с каталогом APF; при его отсутствии — корень модуля.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	best, moduleRoot := "", ""
	for i := 0; i < 12; i++ {
		if st, err := os.Stat(filepath.Join(dir, "APF")); err == nil && st.IsDir() {
			best = dir
		}
		if moduleRoot == "" {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				moduleRoot = dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if best != "" {
		return best, nil
	}
	if moduleRoot != "" {
		return moduleRoot, nil
	}
	return "", fmt.Errorf("не найден корень репозитория (нет ни каталога APF, ни go.mod выше %s)", dir)
}

func rewriteScripts(root string, names []string) (changed, seen int, err error) {
	err = walkBat(root, func(path string, data []byte) error {
		lines := strings.Split(string(data), "\n")
		start, end, ok := findBlock(lines)
		if !ok {
			return nil
		}
		seen++

		eol := ""
		if strings.HasSuffix(lines[start], "\r") {
			eol = "\r"
		}
		block := make([]string, 0, len(names))
		for _, n := range names {
			block = append(block, "    \""+n+"\""+eol)
		}
		out := append([]string{}, lines[:start+1]...)
		out = append(out, block...)
		out = append(out, lines[end:]...)

		updated := strings.Join(out, "\n")
		if updated == string(data) {
			return nil
		}
		if werr := os.WriteFile(path, []byte(updated), 0o644); werr != nil {
			return fmt.Errorf("запись %s: %w", path, werr)
		}
		changed++
		fmt.Printf("genksrules: обновлён %s\n", path)
		return nil
	})
	return changed, seen, err
}

func walkBat(root string, fn func(path string, data []byte) error) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // недоступный каталог — не повод падать
		}
		if d.IsDir() {
			if skipDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".bat") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		return fn(path, data)
	})
}

// findBlock возвращает индексы строки `for %%R in (` и строки `) do (` — при условии, что ВСЕ
// строки между ними являются именами правил APF. Иначе (ok=false) файл не наш и не трогается.
func findBlock(lines []string) (start, end int, ok bool) {
	for i, l := range lines {
		if strings.TrimSpace(l) != blockOpen {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if strings.HasPrefix(t, blockClose) {
				if j == i+1 {
					break // пустой блок — не наш
				}
				return i, j, true
			}
			if !isRuleLine(t) {
				break // посторонняя строка — блок не наш, не переписываем
			}
		}
	}
	return 0, 0, false
}

func isRuleLine(t string) bool {
	return strings.HasPrefix(t, `"`+killswitch.RulePrefix()) && strings.HasSuffix(t, `"`)
}

func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "genksrules: "+format+"\n", a...)
	os.Exit(1)
}
