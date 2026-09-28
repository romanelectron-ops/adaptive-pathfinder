package androidbridge

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// tunRunner — задача #11, вариант 2 (2026-08-17). Оборачивает singbox.InProcessRunner
// и реализует singbox.TunReloader: вместо обычного Reload поверх ПЕРЕИСПОЛЬЗУЕМОГО
// системного TUN-интерфейса запрашивает у Kotlin АБСОЛЮТНО НОВЫЙ (см. TunFdCallback) и
// полностью пересобирает InProcessRunner вокруг него, прежде чем поднять sing-box заново.
//
// Зачем отдельный тип, а не правка самого InProcessRunner. InProcessRunner (internal/
// singbox) — общий, платформонезависимый код; понятие "TUN-fd" и "как получить новый"
// целиком принадлежит Android-мосту. tunRunner — единственное место, которому известно
// и то, и другое: реализует singbox.Runner (делегированием ко ВНУТРЕННЕМУ *InProcessRunner)
// плюс singbox.TunReloader (собственная логика пересоздания).
//
// Инвариант: t.inner меняется ТОЛЬКО под t.mu — engine.go уже сериализует вызовы через
// свой connMu, но t.mu — вторая, независимая линия защиты на случай, если что-то (Stop
// через restartEngine, например) обратится к этому Runner мимо applySingBoxConfig.
type tunRunner struct {
	mu      sync.Mutex
	inner   *singbox.InProcessRunner
	protect ProtectCallback
}

func newTunRunner(inner *singbox.InProcessRunner, protect ProtectCallback) *tunRunner {
	return &tunRunner{inner: inner, protect: protect}
}

var _ singbox.Runner = (*tunRunner)(nil)
var _ singbox.TunReloader = (*tunRunner)(nil)

func (t *tunRunner) current() *singbox.InProcessRunner {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inner
}

func (t *tunRunner) IsInstalled() bool        { return t.current().IsInstalled() }
func (t *tunRunner) Version() (string, error) { return t.current().Version() }
func (t *tunRunner) IsRunning() bool          { return t.current().IsRunning() }
func (t *tunRunner) WriteConfig(cfg *singbox.Config) error {
	return t.current().WriteConfig(cfg)
}
func (t *tunRunner) Start(ctx context.Context) error {
	return t.current().Start(ctx)
}
func (t *tunRunner) Stop() error {
	return t.current().Stop()
}

// Reload — обычный путь (WriteConfig+Start поверх ТОГО ЖЕ fd). engine.go предпочитает
// ReloadWithFreshTun, пока TunFdCallback установлен (штатный Android VPN-режим), но метод
// обязателен для соответствия singbox.Runner и служит запасным путём, если колбэк почему-то
// не задан (см. ReloadWithFreshTun ниже).
func (t *tunRunner) Reload(ctx context.Context, cfg *singbox.Config) error {
	return t.current().Reload(ctx, cfg)
}

// ReloadWithFreshTun — см. package-level комментарий и singbox.TunReloader.
//
// РЕГРЕССИЯ 2026-08-17 (живой WiFi-flap стресс-тест, найдена сразу после первой реализации):
// первая версия этой функции запускала НОВЫЙ инстанс ДО остановки старого (ради отката, если
// новый не поднимется) — но старый и новый инстансы sing-box слушают ОДИН И ТОТ ЖЕ фиксированный
// локальный порт (`cfg.ListenPort`, SOCKS/HTTP-inbound — engine.go:2803, тот же порт что и
// probeListenPort() проверяет на холодном старте). Два живых инстанса НИКОГДА не могут
// одновременно забиндить один порт — поэтому КАЖДЫЙ вызов гарантированно проваливался
// (`bind: address already in use`, 4/4 попыток живьём), приложение проходило всю лестницу
// отказоустойчивости и объявляло полную потерю связи — хуже исходного бага (несколько минут
// деградации трафика) до этого фикса. Хуже того: поскольку `oldInner.Stop()` вызывался ТОЛЬКО
// после УСПЕШНОГО старта нового (которого никогда не происходило), старый SOCKS-listener
// НИКОГДА не освобождался — порт оставался занятым насовсем, заклинивая приложение (не помогал
// даже ручной повторный коннект) до принудительного завершения процесса.
//
// Порядок теперь ОБРАТНЫЙ — сначала остановить старый инстанс (освобождает и TUN, и
// SOCKS/HTTP-порт), потом поднять новый на свободном порту:
//  1. Запросить новый fd у Kotlin ДО остановки старого — если Kotlin откажет (VPN-разрешение
//     отозвано и т.п.), старое соединение продолжает работать нетронутым вместо разрыва связи
//     ради переключения, которое всё равно не удалось бы.
//  2. Подготовить (WriteConfig, но НЕ Start) новый InProcessRunner на новом fd.
//  3. Только теперь остановить старый инстанс — освобождает порт.
//  4. Запустить новый. Если старт не удался — соединение честно потеряно (та же деградация,
//     что и у любого другого отказа applySingBoxConfig/rollbackConnectionAttempt — ожидаемое,
//     восстановимое повторным подключением состояние, НЕ утечка: порт уже свободен, новый
//     Runner уже установлен держателем t.inner, следующая попытка подключения отработает
//     штатно).
//
// Цена: короткое окно без локального listener'а между шагами 3 и 4 (миллисекунды) — тот же
// класс кратковременного разрыва, что уже был у встроенного StartOrReloadService при обычном
// Reload() ДО этого фикса (он тоже закрывает старый listener перед тем как поднять новый,
// просто внутри ОДНОГО инстанса — здесь то же самое, но между двумя).
//
// FU-1 (ТЗ v1.6, продолжение консилиума P0-1, 2026-09-14): «миллисекунды» выше — оптимистичная
// оценка. oldInner.Stop() НЕ гарантирует синхронного освобождения ОС-порта (см.
// waitForListenPortRelease ниже и комментарий над InProcessRunner.Stop в
// internal/singbox/inprocess_runner.go:171-179), поэтому шаг 4 (Start нового инстанса) теперь
// предваряется ОГРАНИЧЕННЫМ ожиданием реального освобождения фиксированного SOCKS/HTTP-порта.
// Это зеркало P0-1 engine.ensureListenPortFree, но для ГОРЯЧЕГО пути реконнекта — P0-1
// сознательно покрывал только холодный старт (wasRunning==false), см. engine.go комментарий
// над ensureListenPortFree.
func (t *tunRunner) ReloadWithFreshTun(ctx context.Context, cfg *singbox.Config) error {
	cb := getTunFdCallback()
	if cb == nil {
		// Десктоп-сборка сюда никогда не попадает (tunRunner существует только в
		// androidbridge), но отсутствие колбэка на Android — конфигурационная ошибка
		// инициализации (ApfCore.setTunFdCallback не вызван), а не повод потерять
		// подключение целиком: откатываемся на прежнее поведение.
		return t.Reload(ctx, cfg)
	}

	newFd := cb.RequestFd()
	if newFd <= 0 {
		return fmt.Errorf("androidbridge: TunFdCallback вернул недопустимый fd (%d) — "+
			"пересоздание TUN-интерфейса отклонено платформой", newFd)
	}

	newAdapter := newPlatformAdapter(t.protect, int32(newFd))
	newInner, err := singbox.NewInProcessRunner(newAdapter)
	if err != nil {
		closeTunFd(newFd)
		return fmt.Errorf("androidbridge: пересоздание in-process runner: %w", err)
	}

	t.mu.Lock()
	oldInner := t.inner
	newInner.OnInternalLog = oldInner.OnInternalLog
	t.mu.Unlock()

	if err := newInner.WriteConfig(cfg); err != nil {
		closeTunFd(newFd)
		return fmt.Errorf("androidbridge: WriteConfig на новом TUN-интерфейсе: %w", err)
	}

	// Остановить старый ПЕРЕД стартом нового — единственный способ не столкнуть их лбами на
	// общем SOCKS/HTTP-порту (см. комментарий выше). Держатель t.inner уже переключаем на
	// новый инстанс здесь же, а не после Start: если Start ниже провалится, движок обязан
	// работать со СВЕЖИМ (пусть ещё не запущенным) Runner'ом на следующей попытке подключения,
	// а не с уже остановленным старым.
	if stopErr := oldInner.Stop(); stopErr != nil && newInner.OnInternalLog != nil {
		newInner.OnInternalLog("warn", fmt.Sprintf("ReloadWithFreshTun: остановка "+
			"прежнего TUN-инстанса: %v", stopErr))
	}

	t.mu.Lock()
	t.inner = newInner
	t.mu.Unlock()
	swapHeldTunFd(newFd)

	// FU-1 (ТЗ v1.6): ждём ПОСЛЕ свопа t.inner намеренно, а не до него. Порт входа держит (или
	// уже не держит) oldInner, которого мы уже остановили строкой выше, — своп двумя строками
	// выше лишь переключает, какой Runner теперь отвечает t.inner, и никак не влияет на то, кто
	// в ОС держит порт. Так расположенное ожидание сохраняет уже принятый инвариант: если Start
	// ниже всё равно провалится, t.inner остаётся=newInner для следующей попытки (комментарий
	// над Stop() выше). Таймаут здесь — best-effort: НЕ абортим реконнект и не возвращаемся
	// раньше срока, только предупреждаем и пробуем Start всё равно — настоящая ошибка bind,
	// если порт и правда занят посторонним процессом, естественно всплывёт из Start ниже.
	if err := waitForListenPortRelease(ctx, socksListenPort(cfg)); err != nil && newInner.OnInternalLog != nil {
		newInner.OnInternalLog("warn", fmt.Sprintf("ReloadWithFreshTun: ожидание освобождения "+
			"порта входа: %v — запускаю новый TUN-инстанс без подтверждения освобождения", err))
	}

	if err := newInner.Start(ctx); err != nil {
		return fmt.Errorf("androidbridge: запуск sing-box на новом TUN-интерфейсе: %w", err)
	}
	return nil
}

// portReleaseTimeout / portReleasePoll — FU-1 (ТЗ v1.6, продолжение консилиума P0-1). Окно
// ожидания РЕАЛЬНОГО освобождения фиксированного локального порта входа прежним
// InProcessRunner'ом. var, а не const: тесты подменяют на короткие значения — тот же приём,
// что у одноимённых portReleaseTimeout/portReleasePoll в internal/engine/engine.go
// (engine.ensureListenPortFree, P0-1). НЕ переиспользованы оттуда напрямую (androidbridge не
// импортирует internal/engine — см. ownership лота): имена и семантика сознательно зеркальны,
// значения независимы.
var (
	portReleaseTimeout = 3 * time.Second
	portReleasePoll    = 100 * time.Millisecond
)

// listenProbeFn — шов: занятость локального порта в тестах иначе воспроизводится только
// реальным сокетом (тот же приём, что engine.listenProbeFn в internal/engine/engine.go).
var listenProbeFn = func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// socksListenPort извлекает фиксированный локальный SOCKS-порт входа из cfg.Inbounds для
// waitForListenPortRelease. cfg — *singbox.Config (JSON-конфигурация, которая сейчас пишется
// в новый InProcessRunner), а НЕ *models.AppConfig — в отличие от e.cfg в engine.go, здесь
// НЕТ верхнеуровневого поля ListenPort, порт живёт внутри Inbounds[i].ListenPort. Зеркалит
// выбор readinessPort() (internal/singbox/process.go): предпочитает inbound типа "socks" —
// тот же порт, который engine.probeListenPort проверяет как "base" (HTTP-inbound идёт следом
// на base+1 по построению, см. config_builder.go: ListenPort b.socksPort / b.socksPort+1).
// readinessPort — неэкспортированная функция чужого пакета, отсюда недостижима, поэтому здесь
// собственная копия того же выбора, а не общий код.
//
// Выход: 0, если socks-inbound не найден (например, гипотетическая TUN-only конфигурация без
// локального SOCKS/HTTP входа) — waitForListenPortRelease трактует port<=0 как fail-safe
// "нечего ждать", тот же контракт, что у probeListenPort.
func socksListenPort(cfg *singbox.Config) int {
	if cfg == nil {
		return 0
	}
	for _, in := range cfg.Inbounds {
		if in.Type == "socks" && in.ListenPort > 0 {
			return in.ListenPort
		}
	}
	return 0
}

// waitForListenPortRelease — FU-1 (ТЗ v1.6), закрывает ГОРЯЧИЙ путь пробела, оставленного
// P0-1 (engine.ensureListenPortFree покрывает только холодный старт, wasRunning==false — см.
// комментарий над ensureListenPortFree в internal/engine/engine.go).
//
// oldInner.Stop() (см. ReloadWithFreshTun выше) НЕ гарантирует синхронного освобождения
// ОС-порта: InProcessRunner.IsRunning() читает только Instance()!=nil, что может разойтись с
// реальным состоянием listener'а/serviceStatus (internal/singbox/inprocess_runner.go:171-179 —
// та же живая находка 2026-08-25, что уже описана в комментарии над Stop()). Без этого
// ожидания newInner.Start(ctx) может столкнуться с ещё не отпущенным портом старого инстанса и
// упасть "bind: address already in use" даже на ОБЫЧНОМ, ничем не перекрывающемся реконнекте —
// класс живого симптома телефона 2026-09-14.
//
//	Порты:     port и port+1 (SOCKS+HTTP — то же допущение, что и у engine.probeListenPort).
//	Fail-safe: port<=0 (сюда попадает и Android-конфигурация без локального SOCKS/HTTP-входа,
//	           см. socksListenPort) — проверка пропускается, функция возвращает nil немедленно,
//	           ни разу не вызвав listenProbeFn.
//	Поллинг:   всегда через select с ctx.Done() — НИКОГДА голый time.Sleep; отмена ctx
//	           (Stop/Disconnect) обязана прервать ожидание немедленно, а не только по истечении
//	           portReleaseTimeout.
//	Выход:     nil — порт подтверждённо свободен (мгновенно либо после поллинга).
//	           ctx.Err() — ожидание прервано отменой контекста.
//	           иначе обычная ошибка — portReleaseTimeout истёк, порт всё ещё занят.
//	           ВСЕ ненулевые случаи — best-effort: вызывающая сторона (ReloadWithFreshTun)
//	           обязана только залогировать предупреждение и продолжить, НЕ абортить
//	           переподключение (см. вызов выше).
func waitForListenPortRelease(ctx context.Context, port int) error {
	if port <= 0 {
		return nil
	}
	probeFree := func() bool {
		for _, p := range [2]int{port, port + 1} {
			ln, err := listenProbeFn(fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				return false
			}
			_ = ln.Close()
		}
		return true
	}
	if probeFree() {
		return nil
	}
	deadline := time.Now().Add(portReleaseTimeout)
	for {
		timer := time.NewTimer(portReleasePoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if probeFree() {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("androidbridge: локальный порт входа (%d/%d) не подтвердил "+
				"освобождение за %v", port, port+1, portReleaseTimeout)
		}
	}
}
