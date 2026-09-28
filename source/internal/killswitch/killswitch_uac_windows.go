//go:build windows

// DEF-03: реализация windowsKS.EnableWithUAC — единый UAC-запрос на включение Kill Switch.
//
// Раньше метод был объявлен только в интерфейсе движка (engine.go), но НЕ реализован ни одним
// типом → type-assertion в enableKillSwitchWithUAC всегда был ложным, и UAC-путь был мёртвым кодом
// (Kill Switch на Windows пытался ставить netsh-правила без повышения прав). Здесь метод реализован:
// все netsh-команды собираются в ОДИН скрипт и выполняются ОДНИМ вызовом с повышением прав
// (netsh -f script), поэтому пользователь видит ровно один UAC-диалог на сессию.
package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// buildKSNetshScript формирует netsh-скрипт (по одной команде в строке, без префикса "netsh").
// Идемпотентно: сперва удаляет прежние правила APF (текущие и legacy), затем применяет актуальный
// набор D-31 (§6.1): allow-исключения + default-block-outbound (политика последней). Один источник
// истины с admin-путём windowsKS.Enable — ksCleanupCommands()/ksApplyCommands().
// vpnIP — транспортная форма Я-31.0 (один IP или список через запятую); раскладывается по
// семействам (R-2.3/C-5), как и в admin-пути.
func buildKSNetshScript(vpnIP string) string {
	v4, v6 := splitVPNIPs(vpnIP)
	var b strings.Builder
	for _, cmd := range ksCleanupCommands() {
		b.WriteString(strings.Join(cmd, " ") + "\r\n")
	}
	for _, cmd := range ksApplyCommands(v4, v6) {
		b.WriteString(strings.Join(cmd, " ") + "\r\n")
	}
	return b.String()
}

// EnableWithUAC включает Kill Switch одним UAC-запросом (DEF-03).
//
// Вход:  vpnIP — адрес VPN-сервера (для allow-правила; "" допустимо), port — резерв (правила по remoteip).
// Тело:  пишет netsh-скрипт во временный файл и исполняет его повышенно: netsh -f script.
//
//	Уже admin → прямой вызов; иначе → ShellExecuteEx(verb=runas) (один UAC-диалог).
//
// Выход: nil при успехе (+enabled, +sentinel); ErrUACCancelled при отказе пользователя; иначе ошибка.
// Fail-safe: при ошибке/отмене состояние НЕ переводится в enabled и маркер не ставится.
func (k *windowsKS) EnableWithUAC(vpnIP string, port int) error {
	_ = port // правила фильтруют по remoteip VPN-сервера; порт зарезервирован для будущих правил

	// Держим состояние согласованным с admin-путём: последующий Enable()/disable() работает
	// с тем же набором адресов, что попал в UAC-скрипт.
	k.vpnV4, k.vpnV6 = splitVPNIPs(vpnIP)

	script := buildKSNetshScript(vpnIP)
	scriptPath := filepath.Join(os.TempDir(), "apf_killswitch.netsh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("killswitch: запись netsh-скрипта: %w", err)
	}
	defer os.Remove(scriptPath)

	var err error
	if isAdminFn() {
		// Уже admin — без диалога, напрямую.
		cmd := exec.Command("netsh", "-f", scriptPath)
		if out, e := netshCombinedOutputFn(cmd); e != nil {
			err = fmt.Errorf("killswitch: netsh -f: %w\n%s", e, string(out))
		}
	} else {
		// Не admin — один UAC-диалог (путь с кавычками безопасен для пробелов в %TEMP%).
		err = shellExecNetshFn(`-f "` + scriptPath + `"`)
	}
	if err != nil {
		return err // в т.ч. ErrUACCancelled — обрабатывается движком (engine.go)
	}

	k.enabled = true
	markActive()
	return nil
}
