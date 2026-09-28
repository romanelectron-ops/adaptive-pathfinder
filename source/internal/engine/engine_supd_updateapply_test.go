// engine_supd_updateapply_test.go — S-UPD (2026-09-15, security).
//
// Дефект (аудит 2026-09-01, перепроверен по коду 09-15): ApplyUpdate заменял APF.exe бинарником
// из НЕподписанного канала (api.github.com/repos/apf/adaptive-pathfinder — репозиторий не
// существует, имя org сквоттируемо), а ожидаемая SHA бралась из того же релиза. Владелец релиза
// (в т.ч. сквоттер) контролировал и файл, и сумму → замена файла службы SYSTEM = supply-chain RCE.
// Фикс: применение обновлений fail-closed (updateApplyEnabled=false) до появления подписанного
// канала; проверка версии (CheckForUpdate/StartAutoCheck) не трогается — она файл не заменяет.
package engine

import (
	"context"
	"strings"
	"testing"
)

// TestApplyUpdate_DisabledByDefault_FailClosed — по умолчанию применение отклоняется ДО любой
// сетевой активности, с понятной причиной.
func TestApplyUpdate_DisabledByDefault_FailClosed(t *testing.T) {
	if updateApplyEnabled {
		t.Fatal("S-UPD: применение обновлений обязано быть выключено по умолчанию (fail-closed)")
	}
	e := newTestEngine()
	err := e.ApplyUpdate(context.Background(), "https://example.com/APF.exe", func(int) {})
	if err == nil {
		t.Fatal("S-UPD: ApplyUpdate вернул nil — применение неподписанного обновления не заблокировано")
	}
	if !strings.Contains(err.Error(), "отключено") {
		t.Fatalf("S-UPD: ожидался отказ политики применения, получено: %v", err)
	}
}

// TestApplyUpdate_WhenEnabled_PassesPolicyGate — контроль обратимости: при снятом флаге гейт
// политики не срабатывает, управление доходит до штатной проверки URL в DownloadAndApply (пустой
// URL → своя ошибка), БЕЗ похода в сеть.
func TestApplyUpdate_WhenEnabled_PassesPolicyGate(t *testing.T) {
	old := updateApplyEnabled
	updateApplyEnabled = true
	defer func() { updateApplyEnabled = old }()

	e := newTestEngine()
	err := e.ApplyUpdate(context.Background(), "", func(int) {})
	if err == nil {
		t.Fatal("ожидалась ошибка пустого URL за гейтом политики")
	}
	if strings.Contains(err.Error(), "отключено") {
		t.Fatalf("гейт политики не должен срабатывать при включённом флаге, получено: %v", err)
	}
}
