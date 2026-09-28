// bridge_v14_test.go — лот L1b-ENG2 ТЗ v1.4: C-13 (часть моста).
//
// FAIL B2 живого прогона: на свежем старте приложения движок на Android ещё не поднят
// (он поднимается при подключении), поэтому ВСЕ read-back-геттеры моста возвращали false, а
// Kotlin рисовал тумблеры выключенными. «Неизвестно» показывалось как «выключено».
package androidbridge

import (
	"encoding/json"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// v14TempDataDir — свой каталог данных на тест: состояние тумблеров читается из config.json,
// и заглядывать в настоящий файл владельца машины (пусть даже только на чтение) незачем —
// иначе тест ещё и зависел бы от того, что у владельца выключено.
func v14TempDataDir(t *testing.T) {
	t.Helper()
	prev := config.DataDir()
	config.SetDataDirOverride(t.TempDir())
	t.Cleanup(func() { config.SetDataDirOverride(prev) })
}

// TestV14_C13_ToggleState_UnknownWithoutEngine — главный тест: без движка мост обязан
// сказать «неизвестно», а не «выключено».
func TestV14_C13_ToggleState_UnknownWithoutEngine(t *testing.T) {
	v14TempDataDir(t)
	if getEngine() != nil {
		t.Skip("в этом прогоне движок уже поднят — проверять нечего")
	}
	for _, name := range []string{ToggleIPv6Block, ToggleWebRTCBlock, ToggleCyclicSearch, ToggleNodeAutoSwitch} {
		if got := GetToggleState(name); got != ToggleUnknown {
			t.Errorf("GetToggleState(%q)=%q, ожидалось %q: UI обязан отличать «ядро не запущено» "+
				"от «выключено пользователем»", name, got, ToggleUnknown)
		}
	}
}

// TestV14_C13_ToggleState_UnknownName — неизвестное имя тумблера не выдаётся за «выключено».
func TestV14_C13_ToggleState_UnknownName(t *testing.T) {
	if got := GetToggleState("нет-такого-тумблера"); got != ToggleUnknown {
		t.Errorf("GetToggleState для неизвестного имени вернул %q", got)
	}
}

// TestV14_C13_ProtectionStateJSON_CarriesKnownFlag — сводка тумблеров несёт признак known и
// значения из КОНФИГА, чтобы UI мог показать положение с пометкой «ядро не запущено».
func TestV14_C13_ProtectionStateJSON_CarriesKnownFlag(t *testing.T) {
	var st struct {
		Known         bool   `json:"known"`
		IPv6Block     bool   `json:"ipv6_block"`
		WebRTCBlock   bool   `json:"webrtc_block"`
		CyclicSearch  bool   `json:"cyclic_search"`
		AutoSwitch    bool   `json:"node_auto_switch"`
		StickyPolicy  string `json:"sticky_policy"`
		SourceOfTruth string `json:"source"`
	}
	v14TempDataDir(t)
	raw := GetProtectionStateJSON()
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("GetProtectionStateJSON вернул неразбираемый JSON (%v): %s", err, raw)
	}
	if getEngine() == nil {
		if st.Known {
			t.Error("без движка known=true — мост выдаёт догадку за факт")
		}
		if st.SourceOfTruth != "config" {
			t.Errorf("источник значений без движка должен быть config, получено %q", st.SourceOfTruth)
		}
		// Дефолты конфига: обе защиты включены. Именно это положение UI и обязан показать
		// (с пометкой), а не «выключено».
		if !st.IPv6Block || !st.WebRTCBlock {
			t.Errorf("значения взяты не из конфига: ipv6=%v webrtc=%v", st.IPv6Block, st.WebRTCBlock)
		}
		if st.StickyPolicy == "" {
			t.Error("политика Sticky пуста — спиннер снова стартует с чужой позиции")
		}
	}
}
