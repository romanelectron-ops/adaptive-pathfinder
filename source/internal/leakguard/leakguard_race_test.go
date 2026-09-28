package leakguard

import (
	"sync"
	"testing"
)

// Регресс на гонку данных 2026-09-14. Поле enabled в IPv6Guard/WebRTCGuard писалось в
// Enable/Disable и читалось в IsEnabled/Status без синхронизации. Всплыло под -race в
// engine.TestRestart_KillSwitch: engine.enableDeviceProtection (Start) пишет enabled в одной
// горутине, engine.Stop читает IsEnabled в другой. Теперь поле — atomic.Bool; конкурентный
// доступ обязан быть чистым под детектором гонок.
//
// Тест НЕ трогает движок/sing-box/сеть — только методы guard'ов, поэтому безопасен на хосте и
// независим от других пакетов.
func TestGuards_ConcurrentEnableIsEnabled_NoRace(t *testing.T) {
	ipv6 := NewIPv6Guard()
	webrtc := NewWebRTCGuard()

	const workers = 8
	const iters = 500

	var wg sync.WaitGroup
	start := make(chan struct{})
	launch := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // синхронный старт всех горутин → максимум перекрытия по времени
			for i := 0; i < iters; i++ {
				fn()
			}
		}()
	}

	for w := 0; w < workers; w++ {
		launch(func() { _ = ipv6.Enable("") })
		launch(func() { _ = ipv6.Disable() })
		launch(func() { _ = ipv6.IsEnabled() })
		launch(func() { _ = ipv6.Status(true) })
		launch(func() { _ = webrtc.Enable() })
		launch(func() { _ = webrtc.Disable() })
		launch(func() { _ = webrtc.IsEnabled() })
		launch(func() { _ = webrtc.Status() })
	}

	close(start)
	wg.Wait()
}
