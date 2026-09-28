// engine_v13_f6_killswitch_test.go — ТЗ v1.3 F6 (живой отчёт пользователя 2026-09-05): текст
// Kill Switch не должен показывать десктопные пути (WFP/служба APF/права администратора) на
// Android — раньше applyKillSwitch отдавал ОДНО сообщение на все платформы разом.
package engine

import (
	"runtime"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// killSwitchUnsupportedModeHint не может быть проверена на всех трёх ветках в одном прогоне
// без seam для runtime.GOOS (которого в этом файле умышленно нет — engine.go нигде не вводит
// его для остальных runtime.GOOS-проверок, см. connectNode/openFileLog: тот же принцип
// «платформенная ветка живёт непроверенной юнит-тестом, верифицируется на реальном
// устройстве» уже применяется в этом пакете). Проверяем инвариант «на ЭТОЙ площадке нет
// терминов ЧУЖИХ платформ» — он ловит именно тот класс регрессии, который был найден живьём:
// один текст на всех сразу.
func TestKillSwitchUnsupportedModeHint_NoCrossPlatformWording(t *testing.T) {
	hint := killSwitchUnsupportedModeHint()
	if hint == "" {
		t.Fatal("подсказка не должна быть пустой")
	}
	desktopTerms := []string{"WFP", "netsh", "администратор", "apf-svc", "UAC"}
	androidTerms := []string{"Always-on VPN", "Настройки → Сеть → VPN"}
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(hint, "WFP") {
			t.Errorf("на Windows подсказка обязана упоминать WFP: %q", hint)
		}
		for _, term := range androidTerms {
			if strings.Contains(hint, term) {
				t.Errorf("на Windows подсказка не должна содержать Android-термин %q: %q", term, hint)
			}
		}
	case "android":
		if !strings.Contains(hint, "Always-on VPN") {
			t.Errorf("на Android подсказка обязана упоминать Always-on VPN: %q", hint)
		}
		for _, term := range desktopTerms {
			if strings.Contains(hint, term) {
				t.Errorf("на Android подсказка не должна содержать десктопный термин %q: %q", term, hint)
			}
		}
	}
}

// Регрессия: сама ошибка капабилити-гейта (не только хелпер) обязана подставлять эту
// платформенную подсказку, а не старый жёстко зашитый текст «нужен WFP...» на все платформы.
func TestApplyKillSwitch_GateMessageUsesPlatformHint(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}} // не поддерживает VPN
	e := engineWithKS(models.ModeVPN, ks)

	err := e.applyKillSwitch(&models.Node{Address: "127.0.0.1"}, nil)
	if err == nil {
		t.Fatal("proxy-only бэкенд не должен допускаться в VPN-режим")
	}
	if !strings.Contains(err.Error(), killSwitchUnsupportedModeHint()) {
		t.Errorf("сообщение гейта должно содержать платформенную подсказку: %v", err)
	}
}

// Регрессия для Windows/Linux (единственных платформ, где эта ветка живьём выполняется в
// тестах на этом хосте): проверка «Kill Switch в proxy-режиме без системного прокси» обязана
// по-прежнему срабатывать — новый guard `runtime.GOOS != "android"` не должен был ослабить её
// ни на одной НЕ-Android платформе.
func TestApplyKillSwitch_ProxyWithoutSystemProxyStillGatedOnNonAndroid(t *testing.T) {
	if runtime.GOOS == "android" {
		t.Skip("на Android эта проверка намеренно снята — см. комментарий у applyKillSwitch")
	}
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}}
	e := engineWithKS(models.ModeProxy, ks)
	e.cfg.SetSystemProxy = false

	err := e.applyKillSwitch(&models.Node{Address: "127.0.0.1"}, nil)
	if err == nil {
		t.Fatal("proxy-режим без системного прокси обязан отвергаться на этой платформе")
	}
	if !strings.Contains(err.Error(), "Системный прокси") {
		t.Errorf("сообщение должно называть причину: %v", err)
	}
}
