package relay

import (
	"os"
	"testing"
	"time"
)

// capsWaitWindowProd — боевое значение окна ожидания CAPS (tunnel_server.go), запомненное ДО
// сжатия в TestMain: тест ниже проверяет именно его.
var capsWaitWindowProd time.Duration

// TestMain сжимает окно ожидания CAPS на весь прогон пакета. [ревью 1.1.10, C1/F1] Теперь
// handleEntry ждёт CAPS у «молодой» сессии до ~1 с. Старые тесты этого пакета регистрируют
// «Выход» вручную (без CAPS, как старая версия) и тут же стучатся «Входом» с узкими запасами
// по времени — например, медленный редозвон «Выхода» на 800 мс в бюджете 2 с
// (tunnel_server_test.go). Их запас рассчитан на мгновенный NEWSTREAM; боевое окно съело бы его
// целиком и дало бы ложные провалы. Тот же приём, что уже применяется к streamDialTimeoutNs:
// тесты, которым важно окно, задают его явно (setCapsWaitWindow), остальные живут со сжатым.
func TestMain(m *testing.M) {
	capsWaitWindowProd = capsWaitWindow()
	capsWaitWindowNs.Store(int64(100 * time.Millisecond))
	os.Exit(m.Run())
}

// Боевое окно должно оставаться порядка секунды: короче — не покрывает RTT мобильной сети (CAPS
// снова начнёт опаздывать за первым ENTRY), длиннее — старые «Выходы» без CAPS заметно
// задерживают первый поток после каждой регистрации.
func TestCapsWaitWindow_ProductionDefault(t *testing.T) {
	if capsWaitWindowProd < 500*time.Millisecond || capsWaitWindowProd > 2*time.Second {
		t.Errorf("боевое окно ожидания CAPS = %v, ожидалось порядка 1 с (0.5–2 с)", capsWaitWindowProd)
	}
}
