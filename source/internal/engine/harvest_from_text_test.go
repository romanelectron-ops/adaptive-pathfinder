package engine

// harvest_from_text_test.go — движковая обвязка разбора ВСТАВЛЕННОГО ПОЛЬЗОВАТЕЛЕМ текста
// (HarvestFromText). Blackbox-контракт того, что добавляет именно движок поверх детерминированного
// экстрактора (он покрыт тестами пакета harvester):
//   - валидные ссылки из произвольного текста доходят до пула через ту же границу доверия;
//   - пустой ввод → ошибка и НЕ оставляет взведённым single-flight;
//   - параллельный проход отбивается ErrHarvestBusy;
//   - повтор той же ссылки не задваивает узел (дедуп по ID).
// Сеть не используется вовсе — тело приносит вызывающий (I-1 соблюдён тривиально).

import (
	"context"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// harvestTextTempDataDir — HarvestFromText → mergeFetchedNodes → saveNodes пишет в config.DataDir().
// Подменяем на временный каталог швом config.SetDataDirOverride, чтобы тест не трогал реальный
// %APPDATA%\APF (урок «тесты снимают DataDir» из памяти проекта — androidbridge test-pollution).
func harvestTextTempDataDir(t *testing.T) {
	t.Helper()
	config.SetDataDirOverride(t.TempDir())
	t.Cleanup(func() { config.SetDataDirOverride("") })
}

// TestHarvestFromText_ExtractsAndMerges — две валидные ссылки, разбросанные в свободном тексте,
// детерминированно извлекаются и добавляются в пул.
func TestHarvestFromText_ExtractsAndMerges(t *testing.T) {
	harvestTextTempDataDir(t)
	e := newTestEngine()

	before := len(e.nodes)
	text := "Свежие узлы на сегодня:\n" +
		"vless://00000000-0000-0000-0000-000000000001@198.51.100.10:443#Alpha\n" +
		"немного текста между ссылками\n" +
		"trojan://pass@t1.example.com:443#Bravo\n" +
		"на этом всё."

	res, err := e.HarvestFromText(context.Background(), text)
	if err != nil {
		t.Fatalf("HarvestFromText вернул ошибку: %v", err)
	}
	if res.Merged != 2 {
		t.Fatalf("Merged=%d, ожидалось 2 (vless+trojan из текста); parsed=%d parseFailed=%d",
			res.Merged, res.Parsed, res.ParseFailed)
	}
	if got := len(e.nodes) - before; got != 2 {
		t.Fatalf("в пул добавлено %d узлов, ожидалось 2", got)
	}
	// single-flight освобождён после успешного прохода.
	if e.harvestActive.Load() {
		t.Error("harvestActive остался true после успешного прохода")
	}
}

// TestHarvestFromText_EmptyInput — пустой/пробельный ввод даёт ошибку и НЕ взводит single-flight
// (проверка пустоты идёт до CompareAndSwap).
func TestHarvestFromText_EmptyInput(t *testing.T) {
	e := newTestEngine()
	for _, in := range []string{"", "   ", "\n\t  \n"} {
		if _, err := e.HarvestFromText(context.Background(), in); err == nil {
			t.Errorf("пустой ввод %q должен вернуть ошибку", in)
		}
	}
	if e.harvestActive.Load() {
		t.Error("harvestActive остался true после ошибки пустого ввода — ранняя ошибка не должна трогать флаг")
	}
}

// TestHarvestFromText_SingleFlight — пока идёт проход (harvestActive держится), повторный вызов
// отбивается ErrHarvestBusy до любой работы (тот же single-flight, что и у HarvestNow).
func TestHarvestFromText_SingleFlight(t *testing.T) {
	e := newTestEngine()
	if !e.harvestActive.CompareAndSwap(false, true) {
		t.Fatal("harvestActive обязан быть свободен в начале теста")
	}
	defer e.harvestActive.Store(false)

	_, err := e.HarvestFromText(context.Background(),
		"vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443#X")
	if err != ErrHarvestBusy {
		t.Fatalf("ожидалась ErrHarvestBusy при идущем проходе, получено: %v", err)
	}
}

// TestHarvestFromText_DedupAgainstPool — повтор той же ссылки не задваивает узел: mergeFetchedNodes
// отсекает дубликат по стабильному ID (второй проход добавляет 0).
func TestHarvestFromText_DedupAgainstPool(t *testing.T) {
	harvestTextTempDataDir(t)
	e := newTestEngine()

	const link = "trojan://pass@dup.example.com:443#Dup"

	res1, err := e.HarvestFromText(context.Background(), link)
	if err != nil {
		t.Fatalf("первый проход: %v", err)
	}
	if res1.Merged != 1 {
		t.Fatalf("первый Merged=%d, ожидалось 1", res1.Merged)
	}

	res2, err := e.HarvestFromText(context.Background(), link)
	if err != nil {
		t.Fatalf("второй проход: %v", err)
	}
	if res2.Merged != 0 {
		t.Fatalf("второй Merged=%d, ожидалось 0 (дедуп по ID уже известного узла)", res2.Merged)
	}
}
