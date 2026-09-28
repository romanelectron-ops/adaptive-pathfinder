package main

// U-15 (ТЗ v1.4, §9.3 UI_CONTRACT_v1.4.md, D3 §6.1): «5 невызываемых биндингов» —
// gui/frontend/wailsjs/go/main/App.js экспортировал функции, которые
// gui/frontend/src/index.html никогда не вызывал (ConnectByID, SaveConfig, SetKillSwitch,
// ResetNodeStats, GetRemovedNodeIDs). Этот файл держит два инварианта живыми навсегда:
//
//  1. Каждый вызов App.X(...) во фронте обязан существовать среди экспортов App.js —
//     иначе onclick/await в реальном окне бьёт в пустоту рантайм-ошибкой, которую
//     «go build»/«npm run build» не ловят (JS не типизирован).
//  2. Каждый экспорт App.js обязан быть либо вызван из index.html, либо явно занесён в
//     intentionallyUnwiredBindings ниже с записанной причиной — «подключить или удалить,
//     решение записать» (U-15в).
//
// Тест-до (снято в начале этого лота, до правок): TestBindings_NoUndocumentedUnwiredExports
// падал на 5 функциях — ConnectByID, GetRemovedNodeIDs, ResetNodeStats, SaveConfig,
// SetKillSwitch (SetTrafficPadding в exported-множестве тоже присутствовал, но уже был
// осознанно отключён от UI лотом K2-D — задокументирован в intentionallyUnwiredBindings
// с самого начала, отдельной находкой этого лота не был). Решение по каждому — см.
// result.md лота L2-D: ConnectByID/SaveConfig/SetKillSwitch — удалены (дублировали уже
// используемые безопасные пути ConnectOnce+PinNode / PatchConfig, а SaveConfig/SetKillSwitch
// в старом виде могли рассинхронизировать a.cfg с a.engine.cfg — тот же класс бага, что уже
// был найден и исправлён у остального toggle-кода); ResetNodeStats/GetRemovedNodeIDs —
// подключены (кнопка «сбросить статистику» в строке узла; счётчик на кнопке «Восстановить
// удалённые»).

import (
	"os"
	"regexp"
	"testing"
)

var (
	reExportedFunc = regexp.MustCompile(`(?m)^export function (\w+)\(`)
	reCalledFunc   = regexp.MustCompile(`App\.(\w+)\s*\(`)
)

// intentionallyUnwiredBindings — экспорт App.js существует, но НЕ вызывается из
// index.html по осознанному, задокументированному решению (не забытый провис).
var intentionallyUnwiredBindings = map[string]string{
	"SetTrafficPadding": "тумблер убран из UI лотом K2-D раньше этого лота (index.html: " +
		"«Traffic Padding · не реализовано») — padding честно не работает в этой сборке " +
		"(GetDPIStatus().padding_enabled=false), вызывать нечего.",
}

func readGuiSourceFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("не удалось прочитать %s: %v", rel, err)
	}
	return string(data)
}

func exportedAppFuncs(t *testing.T) map[string]bool {
	t.Helper()
	js := readGuiSourceFile(t, "frontend/wailsjs/go/main/App.js")
	out := map[string]bool{}
	for _, m := range reExportedFunc.FindAllStringSubmatch(js, -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("не нашли ни одного 'export function' в App.js — регэксп или путь сломаны")
	}
	return out
}

func calledAppFuncs(t *testing.T) map[string]bool {
	t.Helper()
	html := readGuiSourceFile(t, "frontend/src/index.html")
	out := map[string]bool{}
	for _, m := range reCalledFunc.FindAllStringSubmatch(html, -1) {
		out[m[1]] = true
	}
	return out
}

// TestBindings_EveryFrontendCallHasExport — обратное направление: index.html не должен
// звать App.X, которого нет в App.js (сразу разбитый onclick/await в реальном окне).
func TestBindings_EveryFrontendCallHasExport(t *testing.T) {
	exported := exportedAppFuncs(t)
	html := readGuiSourceFile(t, "frontend/src/index.html")
	for _, m := range reCalledFunc.FindAllStringSubmatch(html, -1) {
		name := m[1]
		if !exported[name] {
			t.Errorf("index.html вызывает App.%s(...), но такого экспорта нет в App.js", name)
		}
	}
}

// TestBindings_NoUndocumentedUnwiredExports — U-15в: каждый экспорт App.js либо вызван из
// index.html, либо в intentionallyUnwiredBindings с причиной. bindings_unwired_after в
// result.json лота L2-D обязан быть равен числу FAIL этого теста (0 после фикса).
func TestBindings_NoUndocumentedUnwiredExports(t *testing.T) {
	exported := exportedAppFuncs(t)
	called := calledAppFuncs(t)
	for name := range exported {
		if called[name] {
			continue
		}
		if _, documented := intentionallyUnwiredBindings[name]; documented {
			continue
		}
		t.Errorf("App.%s экспортирован в App.js, но index.html его не вызывает, и решения "+
			"в intentionallyUnwiredBindings нет — U-15 требует подключить или удалить "+
			"с записанным решением", name)
	}
}
