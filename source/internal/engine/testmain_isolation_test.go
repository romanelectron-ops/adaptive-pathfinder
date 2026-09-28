package engine

import (
	"os"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/testenv"
)

// Изоляция каталога данных на весь пакет (дефект D-E2).
//
// Тесты движка пишут туда, куда указывает config.DataDir(), то есть в профиль
// пользователя. Помимо загрязнения профиля это давало плавающий отказ: общий на весь
// пакет nodes_cache.json одновременно писали несколько тестов, и
// TestSaveNodes_WriteFailure14, которому нужно этот файл удалить, падал с «The process
// cannot access the file because it is being used by another process».
//
// Почему здесь НЕТ проверки «каталог пользователя не изменился». Такая проверка тут была
// и оказалась неверной по существу: `go test ./...` запускает пакеты параллельно, каталог
// данных у них общий, и сторож обвинял свой пакет в записях соседнего. Ложное обвинение
// хуже отсутствия проверки — оно уводит от настоящего виновника. Судить о том, тронут ли
// профиль за прогон, может только наблюдатель вне процессов тестов: метрика data.appdata
// в tools\apf_host_snapshot.ps1.
func TestMain(m *testing.M) {
	tmp, cleanup := testenv.MustIsolate("apf-engine-data-")
	testenv.CheckRedirected(config.DataDir(), tmp)
	// ТЗ v1.3 F4 Stage 1: автообход пула после Start() в тестах не нужен (сеть, гонки с
	// утверждениями тестов) — тесты обхода зовут StartSweep явно.
	autoSweepDelay = time.Hour

	code := m.Run()

	cleanup()
	os.Exit(code)
}
