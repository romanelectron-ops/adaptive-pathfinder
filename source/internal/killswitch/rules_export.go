package killswitch

import (
	_ "embed"
	"encoding/json"
)

// B-0403 · R-7 (C-13) — единственный источник имён правил Kill Switch.
//
// До этого список имён существовал в ПЯТИ местах: `windowsRuleSuffixes` в Go и по копии в каждом
// аварийном скрипте восстановления. Копии разошлись: ни один скрипт не удалял `-allow-tun` и
// `-allow-vpn6`, а `windows/reset_network.bat` не удалял ещё и `-allow-vpn`. Именно эти скрипты
// пользователь запускает, когда интернет уже не работает, — и они оставляли правила, которые
// продолжали блокировать трафик. Заодно это прямое нарушение TG-1 («0 остаточных правил APF»).
//
// Теперь Go-список — истина, `ks_rules.json` — его машиночитаемый экспорт, скрипты
// переписываются генератором `go generate ./internal/killswitch`, а тест-страж
// (`rules_guard_test.go`) независимо перечитывает скрипты и падает при любом расхождении.

//go:generate go run ../../tools/genksrules

// ks_rules.json встроен в бинарь: экспорт не должен «отстать» от сборки — если файл забыли
// перегенерировать, тест-страж это увидит на том же коммите, а не через релиз.
//
//go:embed ks_rules.json
var ksRulesJSON []byte

// RuleExport — форма ks_rules.json (потребители: генератор скриптов, внешняя оснастка).
type RuleExport struct {
	Comment   string   `json:"_comment"`
	Prefix    string   `json:"rule_prefix"`
	TunSubnet string   `json:"tun_subnet"`
	Rules     []string `json:"rules"`
}

// WindowsRuleNames — ПОЛНЫЕ имена всех netsh-правил APF (текущих и legacy) в порядке объявления.
//
//	Инвариант: любое имя, которое APF способен создать, обязано присутствовать здесь — иначе
//	правило переживёт Disable и аварийный сброс.
func WindowsRuleNames() []string {
	out := make([]string, 0, len(windowsRuleSuffixes))
	for _, s := range windowsRuleSuffixes {
		out = append(out, ksRuleName+s)
	}
	return out
}

// RulePrefix — общий префикс имён правил APF (по нему их находят внешние скрипты).
func RulePrefix() string { return ksRuleName }

// TunSubnet — подсеть TUN-интерфейса, используемая правилом -allow-tun.
func TunSubnet() string { return ksTunSubnet }

// LoadRuleExport разбирает встроенный ks_rules.json.
func LoadRuleExport() (RuleExport, error) {
	var e RuleExport
	err := json.Unmarshal(ksRulesJSON, &e)
	return e, err
}
