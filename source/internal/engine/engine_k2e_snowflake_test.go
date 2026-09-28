// engine_k2e_snowflake_test.go — К2-E П7(а,б) (свод C, трек 1 №7; B3 #3).
//
// Дефект: движок обещает Snowflake, которого не существует ни в одном исполняемом пути.
// Опоры B3: результат FallbackOrchestrator.GetSingBoxConfig выбрасывается (engine.go),
// applyTorFallback строит СВОЙ конфиг через builder.BuildTor() — голый {type:"tor"};
// ключи Snowflake (torrc/ClientTransportPlugin) невыразимы в singbox.Outbound и не совпадают
// с вендорной схемой; на Android уровней L3/L4 нет структурно. При этом:
//   (а) ActivateFallbackTunnel("tor_snowflake") делала вид, что активирует Snowflake;
//   (б) лог писал «Fallback L3: Tor + Snowflake», когда шёл ЧИСТЫЙ Tor, а узел в интерфейсе
//       назывался «Tor Snowflake» даже на уровне L4 («последний резерв — чистый Tor»).
package engine

import (
	"strings"
	"sync"
	"testing"
)

// captureLog собирает строки лога движка на время теста.
func captureLog(e *Engine) (lines func() []string) {
	var mu sync.Mutex
	var got []string
	e.AddLogSink(func(s string) {
		mu.Lock()
		got = append(got, s)
		mu.Unlock()
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(got))
		copy(out, got)
		return out
	}
}

// TestK2E_ActivateFallbackTunnel_Snowflake_HonestRefusal — ручная активация Snowflake обязана
// отказать понятной ошибкой, а не изображать успех, подменяя его чистым Tor.
func TestK2E_ActivateFallbackTunnel_Snowflake_HonestRefusal(t *testing.T) {
	e := newTestEngine()
	err := e.ActivateFallbackTunnel("tor_snowflake")
	if err == nil {
		t.Fatal("ActivateFallbackTunnel(\"tor_snowflake\") вернула nil — движок «включил» Snowflake, которого нет")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "snowflake") {
		t.Errorf("ошибка должна называть, ЧТО именно недоступно: %v", err)
	}
	t.Logf("OK: честный отказ — %v", err)
}

// TestK2E_ActivateFallbackTunnel_OtherTunnels_Unchanged — отказ адресный: "tor" и "psiphon"
// идут прежним путём (у них свои причины отказа, не связанные со Snowflake).
func TestK2E_ActivateFallbackTunnel_OtherTunnels_Unchanged(t *testing.T) {
	e := newTestEngine()
	for _, tunnel := range []string{"tor", "psiphon"} {
		err := e.ActivateFallbackTunnel(tunnel)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "snowflake") {
			t.Errorf("%s ошибочно отвергнут как Snowflake: %v", tunnel, err)
		}
	}
	if err := e.ActivateFallbackTunnel("no-such-tunnel"); err == nil {
		t.Error("неизвестный туннель должен отвергаться")
	}
	t.Log("OK: отказ адресный")
}

// TestK2E_TryFallback_LogsDoNotPromiseSnowflake — иерархия резервов не обещает Snowflake ни в
// одной строке лога и ни в одном отображаемом имени узла.
//
// Без бинарника tor (типичное состояние машины и ВСЕГДА — Android) SelectBest отдаёт ветку
// Psiphon, движок честно переключается на Tor, applyTorFallback отказывает ErrTorUnavailable
// и до старта sing-box дело не доходит — путь безопасен для тестового прогона.
func TestK2E_TryFallback_LogsDoNotPromiseSnowflake(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	lines := captureLog(e)
	e.cancel() // диагностика L2 не уходит в сеть

	if err := e.tryFallback(); err == nil {
		t.Log("tryFallback вернула nil (на машине найден tor) — проверяем только лог")
	}
	// Запрещены именно ОБЕЩАНИЯ применить Snowflake — то, что видит пользователь как
	// «сейчас работает Snowflake». Перечисление вариантов выбора («Tor/Snowflake/Psiphon»)
	// и объяснение, почему Snowflake применить нечем, ложью не являются.
	forbidden := []string{"tor + snowflake", "tor snowflake", "tor-snowflake"}
	for _, l := range lines() {
		low := strings.ToLower(l)
		for _, bad := range forbidden {
			if strings.Contains(low, bad) {
				t.Errorf("лог резервов обещает Snowflake, которого не применяет: %q", l)
			}
		}
	}
	t.Logf("OK: %d строк лога, Snowflake не обещан", len(lines()))
}
