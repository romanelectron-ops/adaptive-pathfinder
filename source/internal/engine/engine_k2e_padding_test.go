// engine_k2e_padding_test.go — К2-E П9 (свод C, трек 1 №9; B1 #5, B3 #4, D6, B3-опоры).
//
// Дефект: Traffic Padding отчитывается включённым, хотя ни один байт трафика через него не
// проходит. Методы данных пакета dpi — TrafficPadder.WrapConn, TrafficPadder.JitteredDial,
// dpi.NewPaddedConn — не вызываются НИГДЕ в продакшн-коде (проверяется тестом ниже по
// исходникам). Движок при этом отдавал padding_enabled=true, писал в лог «enabling aggressive
// traffic padding» и переприменял настройку по патчу конфигурации. Пользователь видел
// включённую маскировку, которой нет.
package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/detector"
	"github.com/apf/adaptive-pathfinder/internal/dpi"
)

// TestK2E_GetDPIStatus_PaddingAlwaysFalse — статус честен при любой конфигурации и после
// любого способа «включить» padding.
func TestK2E_GetDPIStatus_PaddingAlwaysFalse(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		set  func(e *Engine)
	}{
		{"по умолчанию", func(e *Engine) {}},
		{"EnableTrafficPadding(true, aggressive)", func(e *Engine) { e.EnableTrafficPadding(true, true) }},
		{"EnableTrafficPadding(true, standard)", func(e *Engine) { e.EnableTrafficPadding(true, false) }},
		{"конфиг + applyDPIFromConfig", func(e *Engine) {
			e.cfg.TrafficPaddingEnabled = true
			e.cfg.TrafficPaddingAggressive = true
			e.applyDPIFromConfig()
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withTempDataDir(t)
			e := newTestEngine()
			c.set(e)
			status := e.GetDPIStatus(ctx)
			v, ok := status["padding_enabled"]
			if !ok {
				t.Fatal("GetDPIStatus потерял ключ padding_enabled")
			}
			if v != false {
				t.Fatalf("padding_enabled=%v — статус обещает маскировку, которой нет", v)
			}
		})
	}
	t.Log("OK: padding_enabled=false при любом конфиге")
}

// TestK2E_DPICounterMeasures_NoPaddingPromise — контрмеры Canary не заявляют включение
// padding'а. Ветка reality+utls обязана сохранить своё РЕАЛЬНОЕ действие — предпочтение
// Reality через тип блокировки (единственный слой маскировки, который действительно работает,
// см. вердикт B3/DPI).
func TestK2E_DPICounterMeasures_NoPaddingPromise(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	lines := captureLog(e)

	for _, cm := range []string{"reality+utls", "traffic_padding+websocket", "utls"} {
		e.applyDPICounterMeasures(&dpi.CanaryResult{CounterMeasure: cm, VPNDetectable: true, Score: 80})
	}
	if bt := e.getBlockageType(); bt != detector.BlockageSNI {
		t.Errorf("ветка reality+utls потеряла своё реальное действие (Reality-first): тип блокировки %q", bt)
	}
	for _, l := range lines() {
		low := strings.ToLower(l)
		if strings.Contains(low, "enabling") && strings.Contains(low, "padding") {
			t.Errorf("лог обещает включение padding'а: %q", l)
		}
	}
	t.Logf("OK: %d строк лога без обещаний padding'а", len(lines()))
}

// TestK2E_PaddingDataPath_StillUnused — опора, на которой держится честный статус: методы
// данных padding'а действительно не вызываются из продакшн-кода. Если кто-то однажды подключит
// padding по-настоящему, этот тест покраснеет и напомнит вернуть честное «включено».
func TestK2E_PaddingDataPath_StillUnused(t *testing.T) {
	root := filepath.Join("..", "..")
	needles := []string{".WrapConn(", ".JitteredDial(", "NewPaddedConn("}
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", "node_modules", ".git", "dist", "build", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Определения и внутренние вызовы самого пакета dpi не считаются использованием.
		if strings.Contains(filepath.ToSlash(path), "/internal/dpi/") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, n := range needles {
			if strings.Contains(string(data), n) {
				hits = append(hits, path+" → "+n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("padding начали применять на данных — статус пора вернуть к правде: %v", hits)
	}
	t.Log("OK: WrapConn/JitteredDial/NewPaddedConn вне пакета dpi не вызываются")
}
