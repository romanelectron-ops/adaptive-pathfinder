package killswitch

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ─── B-0403 · R-7 (C-13) · страж синхронизации Go ↔ скрипты ─────────────────
//
// Разбор здесь СОЗНАТЕЛЬНО реализован иначе, чем в генераторе (регулярное выражение по всему
// файлу вместо разбора блока `for %%R in (`). Страж, использующий код генератора, не способен
// поймать ошибку генератора — он повторил бы её симметрично.

var ruleNameRe = regexp.MustCompile(`APF-KillSwitch-[a-zA-Z0-9_-]+`)

// rulePrefixRe — P1-10 (аудит 2026-09-01). Отбор скриптов по ПРЕФИКСУ, а не по полному имени
// правила.
//
// Прежний отбор (`ruleNameRe.Match`) требовал литерального `APF-KillSwitch-<суффикс>`, поэтому
// два скрипта из семи были для стража НЕВИДИМЫ: `tools/apf_emergency_restore.bat` собирает имя
// как `APF-KillSwitch-%%R` (символ `%` не входит в класс регулярки), а
// `tools/apf_safety_lib.ps1` — как `"$($script:APF_RULE)$s"`. Ровно эти два и разошлись с
// Go-списком (не удаляли `-allow-vpn6`), а страж проверял только те пять файлов, которые
// генератор способен переписать — то есть ровно те, что не могли разойтись.
//
// Корреляция была идеальная 5/5 и 2/2: синхронность держалась исключительно на автоматике.
// Поэтому теперь файл, который УДАЛЯЕТ правила и упоминает префикс, но не даёт извлечь
// полный список литеральных имён, — это провал, а не пропуск.
var rulePrefixRe = regexp.MustCompile(`APF-KillSwitch`)

// deleteConstructRe отличает скрипт ВОССТАНОВЛЕНИЯ (удаляет правила) от файла, который просто
// упоминает префикс — например apf_admin_setup.ps1 считает правила через Select-String и
// разойтись с Go-списком физически не может.
var deleteConstructRe = regexp.MustCompile(`(?i)(firewall\s+delete\s+rule|Remove-NetFirewallRule)`)

// policyRestoreRe — скрипт восстановления обязан вернуть политику брандмауэра в
// allowoutbound. Удалить все правила и оставить blockoutbound — это оставить пользователя без
// интернета; прежний страж такой скрипт пропускал как корректный.
var policyRestoreRe = regexp.MustCompile(`(?i)firewallpolicy\s+blockinbound,allowoutbound`)

// goRuleSet — множество имён правил по Go-константам.
func goRuleSet() map[string]bool {
	set := make(map[string]bool, len(windowsRuleSuffixes))
	for _, n := range WindowsRuleNames() {
		set[n] = true
	}
	return set
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// repoRoot ищет корень репозитория.
//
// Наивное «первый предок, у которого нашлись скрипты» здесь НЕ работает: скрипты лежат и внутри
// модуля (source/scripts), и в корне репозитория, и рядом с ним — поиск остановился бы на самом
// внутреннем и молча не проверил бы остальные пять копий. Поэтому берётся САМЫЙ ВНЕШНИЙ предок,
// содержащий каталог APF (устойчивый признак этого репозитория), а при его отсутствии —
// корень модуля (каталог с go.mod).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	best, moduleRoot := "", ""
	for i := 0; i < 12; i++ {
		if st, err := os.Stat(filepath.Join(dir, "APF")); err == nil && st.IsDir() {
			best = dir // не выходим: выше может быть ещё один уровень с тем же признаком
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
		return best
	}
	return moduleRoot
}

// collectScripts возвращает пути .bat/.ps1, в которых упомянуто хотя бы одно ПОЛНОЕ имя правила.
func collectScripts(root string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch strings.ToLower(d.Name()) {
			case "vendor", ".git", "node_modules":
				return filepath.SkipDir
			// apf-stand — [TZ_TAILS_HARDENING_2026-08-31.md] кэши сборки (Go-модули,
			// Gradle) и файлы Hyper-V-стенда переехали ВНУТРЬ папки проекта (по правилу
			// проекта — временные/кэш-файлы не должны разбегаться по диску), из-за чего
			// repoRoot теперь climb'ит достаточно высоко, чтобы этот каталог попал в обход.
			// Десятки тысяч файлов gomodcache/gradle-home превращали обход в 10+ минут
			// (замер: TestEmergencyScriptsMatchGoRuleList таймаутил на 10м) — ни один .bat/
			// .ps1 восстановления в принципе не может лежать внутри кэша сборки, тот же
			// довод, что уже применён к vendor/node_modules.
			case "apf-stand":
				return filepath.SkipDir
			// vpn_proxy_analysis — распакованные архивы СТАРЫХ версий проекта целиком
			// (<old-workspace>, APF_Source). Их скрипты соответствуют набору правил
			// своей версии и расходятся с текущим Go-списком по определению, навсегда.
			//
			// Держать их в охвате — значит держать этот тест вечно красным, а вечно красный
			// страж перестают читать, и настоящий рассинхрон живого скрипта проходит
			// незамеченным. Это ровно та цена, которую тест призван предотвращать.
			//
			// Отдельно от исключения: сам факт наличия на диске старых копий, которые
			// пользователь в панике может запустить, зафиксирован в отчёте аудита
			// (CODE_REVIEW_2026-09-01) как вопрос к владельцу — удалять архивы или нет,
			// решается вне кода.
			case "vpn_proxy_analysis":
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".bat" && ext != ".ps1" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		// P1-10: берём по ПРЕФИКСУ + признаку удаления правил, а не по литеральному полному
		// имени — иначе скрипты, собирающие имя из переменной, выпадают из проверки молча.
		if rulePrefixRe.Match(data) && deleteConstructRe.Match(data) {
			found = append(found, path)
		}
		return nil
	})
	sort.Strings(found)
	return found
}

// Главный инвариант R-7: скрипт аварийного восстановления удаляет РОВНО тот набор правил,
// который APF способен создать. Недостача = правило переживает сброс и продолжает блокировать
// трафик (и ломает TG-1); излишек = имя, которого в Go уже нет (мусор, скрывающий рассинхрон).
func TestEmergencyScriptsMatchGoRuleList(t *testing.T) {
	root := repoRoot(t)
	if root == "" {
		t.Skip("скрипты восстановления не найдены — модуль распространён отдельно от репозитория")
	}
	scripts := collectScripts(root)
	// P1-10: t.Fatal, а не t.Skip. Пустой набор означает, что отбор сломался (изменился формат
	// имён, съехал repoRoot) — а молчаливый зелёный при неработающем страже неотличим от
	// успеха и ровно так же оставляет рассинхрон незамеченным.
	if len(scripts) == 0 {
		t.Fatalf("не найдено ни одного скрипта восстановления под %s — отбор сломан "+
			"(страж, который ничего не проверяет, хуже отсутствующего)", root)
	}
	t.Logf("проверяется скриптов: %d (корень %s)", len(scripts), root)

	want := goRuleSet()
	for _, path := range scripts {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("чтение %s: %v", path, err)
			}
			got := map[string]bool{}
			for _, m := range ruleNameRe.FindAllString(string(data), -1) {
				got[m] = true
			}

			// P1-10: скрипт восстановления обязан вернуть политику брандмауэра.
			// Удалить все правила и оставить blockoutbound — оставить пользователя без
			// интернета; прежний страж такой скрипт считал корректным.
			if !policyRestoreRe.Match(data) {
				t.Errorf("%s удаляет правила, но НЕ возвращает политику "+
					"`firewallpolicy blockinbound,allowoutbound` — после него исходящий "+
					"трафик останется заблокированным", path)
			}

			var missing, extra []string
			for n := range want {
				if !got[n] {
					missing = append(missing, n)
				}
			}
			for n := range got {
				if !want[n] {
					extra = append(extra, n)
				}
			}
			sort.Strings(missing)
			sort.Strings(extra)

			if len(missing) > 0 {
				t.Errorf("%s НЕ удаляет правила %v — они переживут аварийный сброс и продолжат "+
					"блокировать трафик пользователя (нарушение TG-1). Перегенерируйте: "+
					"go generate ./internal/killswitch", path, missing)
			}
			if len(extra) > 0 {
				t.Errorf("%s удаляет несуществующие правила %v — имена разошлись с Go. "+
					"Перегенерируйте: go generate ./internal/killswitch", path, extra)
			}
		})
	}
}

// ks_rules.json встроен в бинарь и обязан совпадать с Go-константами: иначе внешняя оснастка,
// читающая его, получит устаревший список.
func TestKSRulesJSONMatchesGoConstants(t *testing.T) {
	exp, err := LoadRuleExport()
	if err != nil {
		t.Fatalf("ks_rules.json не разбирается: %v", err)
	}
	if exp.Prefix != RulePrefix() {
		t.Errorf("rule_prefix = %q, want %q", exp.Prefix, RulePrefix())
	}
	if exp.TunSubnet != TunSubnet() {
		t.Errorf("tun_subnet = %q, want %q", exp.TunSubnet, TunSubnet())
	}

	want := WindowsRuleNames()
	if len(exp.Rules) != len(want) {
		t.Fatalf("в ks_rules.json %d правил, в Go %d: %v vs %v", len(exp.Rules), len(want), exp.Rules, want)
	}
	// Порядок тоже значим: он определяет порядок удаления в скриптах.
	for i := range want {
		if exp.Rules[i] != want[i] {
			t.Errorf("правило[%d] = %q, want %q (перегенерируйте: go generate ./internal/killswitch)",
				i, exp.Rules[i], want[i])
		}
	}
}

// Набор для очистки обязан покрывать всё, что умеет создать набор для применения.
// Иначе созданное правило переживёт Disable — это и есть механика остаточных правил.
func TestCleanupCoversEverythingApplyCanCreate(t *testing.T) {
	created := map[string]bool{}
	for _, cmd := range ksApplyCommands([]string{"1.2.3.4"}, []string{"2001:db8::1"}) {
		for _, arg := range cmd {
			if strings.HasPrefix(arg, "name=") {
				created[strings.TrimPrefix(arg, "name=")] = true
			}
		}
	}
	if len(created) == 0 {
		t.Fatal("ksApplyCommands не создаёт ни одного именованного правила")
	}

	cleaned := map[string]bool{}
	for _, cmd := range ksCleanupCommands() {
		for _, arg := range cmd {
			if strings.HasPrefix(arg, "name=") {
				cleaned[strings.TrimPrefix(arg, "name=")] = true
			}
		}
	}
	for n := range created {
		if !cleaned[n] {
			t.Errorf("правило %q создаётся, но не удаляется набором очистки: %v", n, sortedKeys(cleaned))
		}
	}
}

// Legacy-имена обязаны оставаться в списке очистки: их могли создать прежние версии APF, и
// удалить их некому, кроме нас.
func TestLegacyRuleNamesStillCleaned(t *testing.T) {
	legacy := []string{"-block-tcp", "-block-udp", "-block-out", "-allow-local", "-allow-dns"}
	set := goRuleSet()
	for _, s := range legacy {
		if !set[ksRuleName+s] {
			t.Errorf("legacy-правило %q выпало из очистки — на машинах со старой версией оно "+
				"останется навсегда", ksRuleName+s)
		}
	}
}
