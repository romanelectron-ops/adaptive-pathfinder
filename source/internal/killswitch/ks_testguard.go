package killswitch

import "github.com/apf/adaptive-pathfinder/internal/hostguard"

// DEF-08 — защитный барьер: под `go test` пакет killswitch НИКОГДА не выполняет
// реальные системные команды (netsh/iptables). Иначе любой тест (в т.ч. engine),
// дошедший до включения Kill Switch, оставлял на ХОСТЕ боевые block-правила фаервола
// и у пользователя пропадал интернет.
//
// Признак тестового режима — ЕДИНЫЙ для всего проекта (internal/hostguard): барьер обобщён
// с killswitch на все пакеты, меняющие состояние ОС (sysproxy, leakguard).
func underTest() bool { return !hostguard.Allowed() }

func init() {
	if !underTest() {
		return
	}
	// Кроссплатформенные швы исполнения команд → безопасный no-op.
	execCmdFn = func(string, ...string) error { return nil }
	iptablesRunFn = func(...string) (string, error) { return "", nil }
	ip6tablesRunFn = func(...string) (string, error) { return "", nil }
	// DNS-швы reset.go: под `go test` не опрашивать/не менять DNS адаптеров хоста.
	showInterfacesFn = func() ([]byte, error) { return nil, nil }
	getDNSInfoFn = func(string) ([]byte, error) { return nil, nil }
	setDNSDHCPFn = func(string) {}
}
