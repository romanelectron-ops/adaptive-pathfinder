package main

import (
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// svcName — имя службы, должно совпадать с svcName в cmd/apf-svc/main.go
// (два разных бинарника main, общую константу импортировать неоткуда — тот
// же приём, что и в cmd/apf-tray/main.go).
const svcName = "APFService"

// serviceStartWaitTimeout/serviceStartPollInterval — см. waitServiceRunning.
const (
	serviceStartWaitTimeout  = 2 * time.Second
	serviceStartPollInterval = 100 * time.Millisecond
)

// ensureServiceStarted — по требованию пользователя 2026-08-25 служба APFService
// зарегистрирована с StartManual (см. installService() в cmd/apf-svc/main.go): она
// НЕ поднимается сама при загрузке Windows, а живёт ровно пока нужна приложению.
// GUI (APF.exe — то, что реально ставит установщик и запускает пользователь) —
// основная точка входа, поэтому именно она инициирует запуск службы при своём
// старте, тем же приёмом, что и cmd/apf-tray/main.go. Best-effort: служба нужна
// прежде всего как привилегированный исполнитель Kill Switch — если поднять её
// не удалось (нет прав, не установлена и т.п.), GUI всё равно продолжает работу
// и сам становится владельцем движка через обычную гонку AcquireEngine() в
// startup(); сообщение в лог, не паника и не блокировка запуска.
func ensureServiceStarted() {
	m, err := mgr.Connect()
	if err != nil {
		log.Printf("[APF] служба: подключение к SCM не удалось (%v) — продолжаю без неё", err)
		return
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		log.Printf("[APF] служба APFService не установлена — продолжаю без неё")
		return
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		return
	}
	if err := s.Start(); err != nil {
		log.Printf("[APF] не удалось запустить службу APFService (%v) — "+
			"Kill Switch может быть недоступен, GUI продолжает работу сам", err)
		return
	}
	log.Printf("[APF] служба APFService запущена по требованию GUI")
	waitServiceRunning(s)
}

// waitServiceRunning — пункт аудита "Два движка одновременно при старте (гонка
// singleinstance)". apfService.Execute (cmd/apf-svc/main.go) сообщает SCM свой
// svc.Running ТОЛЬКО ПОСЛЕ собственного singleinstance.AcquireEngine() — то есть к
// моменту, когда мы здесь увидим Running, служба уже либо стала владельцем движка,
// либо уступила его (если тот был занят раньше). Раньше ensureServiceStarted()
// запускалась через `go` и startup() тут же (в основном потоке) шёл на свой
// AcquireEngine() — два независимых захвата гонялись параллельно без какой-либо
// синхронизации между собой: непривилегированный GUI мог выиграть лок раньше, чем
// только что поднятая служба успевала попытаться, и единственный процесс с правами
// на TUN-адаптер становился «наблюдателем» по случайности таймингов, а не архитектурно.
// Ограничено по времени (serviceStartWaitTimeout) — тот же fail-open принцип, что и у
// остальных вызовов singleinstance в этом файле: не укладывается служба — не блокируем
// GUI бесконечно, дальше решает обычная гонка AcquireEngine() как раньше.
func waitServiceRunning(s *mgr.Service) {
	deadline := time.Now().Add(serviceStartWaitTimeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return
		}
		if status.State == svc.Running {
			return
		}
		time.Sleep(serviceStartPollInterval)
	}
}
