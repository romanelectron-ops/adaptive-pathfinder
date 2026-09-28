package singbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/sagernet/sing-box/daemon"
	libbox "github.com/sagernet/sing-box/experimental/libbox"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// InProcessRunner — sing-box В ПРОЦЕССЕ приложения, через libbox.CommandServer
// (этап Э-4, Ш-3). Второй Runner, наряду с Process (внешний процесс); выбор — за
// вызывающей стороной через Engine.SetRunner (docs/TZ_ANDROID_E4_v1.1.md §1: TUN-дескриптор
// и protect() не пересекают границу процессов, поэтому на Android VPN-режиму нужен именно
// этот запускатель).
//
// Вход:      libbox.PlatformInterface — уже готовая реализация (platformAdapter из
// mobile/androidbridge, B-A14); этот файл ничего не знает про Kotlin/gomobile, только про
// публичный интерфейс libbox.
// Тело:      оборачивает libbox.NewCommandServer и его CommandServer.StartOrReloadService/
// CloseService/Instance — тот единственный путь подключения PlatformInterface к box.New,
// что подтверждён по исходнику (ТЗ §2.2). gRPC-поверхность CommandServer (Listen/Serve)
// НИКОГДА не поднимается: APF пользуется только встроенным Go API, gRPC ему не нужен.
// Выход:     соответствует контракту Runner — остальной engine.go не отличает этот
// запускатель от внешнего процесса.
// Fail-safe: WriteConfig без последующего Start — соединение не поднимается, а не выдумывает
// пустую конфигурацию. Stop на неподнятом сервисе — не ошибка (тот же контракт, что у
// Process.Stop).
// Инвариант: IsRunning() отражает состояние libbox-инстанса, а не локальный флаг —
// расхождение между «мы думаем, что работает» и «на самом деле работает» здесь невозможно
// структурно (истинный источник один — CommandServer.Instance()).
type InProcessRunner struct {
	mu     sync.Mutex
	server *libbox.CommandServer
	cfg    *Config

	// OnInternalLog, если задан, получает СЫРЫЕ логи самого sing-box (не только события
	// APF) — диагностика D-A37 (Task #25, 2026-08-11). На Android box.New() глушит
	// собственный вывод sing-box в io.Discard, как только задан PlatformInterface
	// (vendor/.../sing-box/box.go: `if platformInterface != nil { defaultLogWriter =
	// io.Discard }`) — обычным способом эти логи никак не увидеть. Единственный не-gRPC
	// путь к ним — daemon.StartedService.SubscribeLog, обычный Go-метод (CommandServer
	// встраивает *daemon.StartedService), который APF никогда не поднимал как сеть
	// ("gRPC-поверхность CommandServer НИКОГДА не поднимается", inprocess_runner.go
	// выше) — сам метод остаётся обычным вызовом, требует только реализации
	// grpc.ServerStreamingServer[daemon.Log] без единого байта по сети.
	OnInternalLog func(level, message string)
	logCancel     context.CancelFunc
}

// NewInProcessRunner создаёt InProcessRunner с уже готовым platformInterface.
func NewInProcessRunner(platformInterface libbox.PlatformInterface) (*InProcessRunner, error) {
	if platformInterface == nil {
		return nil, errors.New("singbox: platformInterface не задан")
	}
	setupLibbox()
	r := &InProcessRunner{}
	server, err := libbox.NewCommandServer(&inProcessHandler{runner: r}, platformInterface)
	if err != nil {
		return nil, fmt.Errorf("singbox: создание in-process запускателя: %w", err)
	}
	r.server = server
	return r, nil
}

// setupLibbox — дефект D-A35 (продолжение), приёмка Э-Выход-1 на устройстве 2026-08-10.
//
// libbox.NewCommandServer → baseContext() → filemanager.WithDefault(ctx, sWorkingPath,
// sTempPath, sUserID, sGroupID) — но sUserID/sGroupID/sWorkingPath/sTempPath ЭТО
// ПАКЕТНЫЕ ПЕРЕМЕННЫЕ libbox, которые заполняет ТОЛЬКО libbox.Setup(...) (setup.go). Наш
// код никогда его не вызывал — ни androidbridge, ни этот пакет. Без Setup() sUserID/
// sGroupID остаются нулём (Go zero value), а filemanager.WithDefault решает, нужен ли
// chown, сравнением `userID != os.Getuid()`: 0 почти никогда не совпадает с реальным UID
// приложения (на Android — что-то вроде 10091), поэтому cache-file init на КАЖДОМ старте
// пытался chown файл к UID/GID 0 (root) — операция, которую Android-песочница честно
// отвергает: "platform chown: chown .../cache.db: operation not permitted". Конфиг к тому
// моменту уже был правильным (см. Config.Experimental.CacheFile, тот же заход) — не
// хватало этого вызова.
//
// Пакетные переменные libbox — общие на весь процесс, поэтому вызывается здесь, при
// каждом создании InProcessRunner (дёшево, идемпотентно: просто переприсваивает те же
// значения), а не полагается на то, что кто-то вызвал Setup() раньше в другом месте.
func setupLibbox() {
	dataDir := config.DataDir()
	libbox.Setup(&libbox.SetupOptions{
		BasePath:        dataDir,
		WorkingPath:     dataDir,
		TempPath:        filepath.Join(dataDir, "tmp"),
		FixAndroidStack: runtime.GOOS == "android",
	})
}

var _ Runner = (*InProcessRunner)(nil)

// IsInstalled — код sing-box уже слинкован в бинарник приложения, отдельной установки нет.
func (r *InProcessRunner) IsInstalled() bool {
	return true
}

// Version возвращает версию из того же единого источника, что и внешний процесс —
// SingBoxVersion привязана к схеме, которую понимает config_builder.go (дефект D-A27),
// а не к тому, что физически запущено (для in-process это одно и то же, версия вкомпилена).
func (r *InProcessRunner) Version() (string, error) {
	return SingBoxVersion, nil
}

// WriteConfig фиксирует конфигурацию для следующего Start/Reload. В отличие от Process
// (пишет во временный файл для внешнего бинарника), здесь конфигурация остаётся в памяти:
// StartOrReloadService принимает JSON-строку напрямую.
func (r *InProcessRunner) WriteConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("singbox: WriteConfig(nil)")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = cfg
	return nil
}

// Start поднимает sing-box по записанной конфигурации.
//
// StartOrReloadService у sing-box уже реализует и старт с нуля, и горячую замену поверх
// работающего инстанса (закрывает старый перед поднятием нового) — поэтому Reload ниже
// просто вызывает Start повторно, а не дублирует логику.
func (r *InProcessRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	cfg := r.cfg
	r.mu.Unlock()
	if cfg == nil {
		return errors.New("singbox: WriteConfig не вызван перед Start")
	}

	data, err := ToJSON(cfg)
	if err != nil {
		return fmt.Errorf("singbox: сериализация конфигурации: %w", err)
	}
	// CommandServer.StartOrReloadService разыменовывает *options.AutoRedirect БЕЗ проверки
	// на nil (command_server.go:172-177 в sing-box v1.13.16) — nil здесь означал не
	// «настройки по умолчанию», а гарантированную панику nil pointer dereference на первом
	// же реальном Start() (найдено на устройстве в Ш-6: goroutine ScanAndConnect уронила
	// весь процесс через considered SIGABRT ровно в этом вызове). Пустая структура — тот же
	// эффект «настроек по умолчанию», без разыменования nil.
	if err := r.server.StartOrReloadService(string(data), &libbox.OverrideOptions{}); err != nil {
		return fmt.Errorf("singbox: запуск in-process: %w", err)
	}

	r.mu.Lock()
	if r.OnInternalLog != nil && r.logCancel == nil {
		subCtx, cancel := context.WithCancel(context.Background())
		r.logCancel = cancel
		go r.streamInternalLogs(subCtx)
	}
	r.mu.Unlock()

	return nil
}

// Stop останавливает sing-box. Идемпотентен: CloseService у sing-box возвращает ошибку
// на уже остановленном сервисе (os.ErrInvalid) — здесь это гасится тем же контрактом,
// что и у Process.Stop (повторный вызов не ошибка).
//
// Живая находка 2026-08-25 (роль «Выход» на Android, тот же CommandServer): IsRunning()
// смотрит только на Instance() (s.instance != nil), а CloseService() внутри sing-box
// (started_service.go) отдаёт os.ErrInvalid по СВОЕМУ ОТДЕЛЬНОМУ полю serviceStatus —
// эти два никогда не гарантированно синхронны (serviceStatus мог уйти из STARTED/STARTING
// в ERROR/IDLE асинхронно — например, если inbound-листенер не смог забиндиться — а
// instance ещё не обнулили). Раньше проверки на !IsRunning() было недостаточно: именно
// такое расхождение и производило "invalid argument" наружу, хотя комментарий выше уже
// обещал его гасить. Явно ловим os.ErrInvalid здесь — это и есть тот самый обещанный
// идемпотентный путь.
func (r *InProcessRunner) Stop() error {
	r.mu.Lock()
	if r.logCancel != nil {
		r.logCancel()
		r.logCancel = nil
	}
	r.mu.Unlock()

	if !r.IsRunning() {
		return nil
	}
	if err := r.server.CloseService(); err != nil {
		if errors.Is(err, os.ErrInvalid) {
			return nil
		}
		return fmt.Errorf("singbox: остановка in-process: %w", err)
	}
	return nil
}

// streamInternalLogs — тело подписки на SubscribeLog (см. комментарий у OnInternalLog).
// Живёт до отмены subCtx (Stop) или до закрытия сервиса самим sing-box; ошибку канала
// специально не пробрасывает наверх — потеря диагностических логов не должна валить VPN.
func (r *InProcessRunner) streamInternalLogs(ctx context.Context) {
	_ = r.server.SubscribeLog(&emptypb.Empty{}, &internalLogSink{ctx: ctx, onMsg: r.OnInternalLog})
}

// internalLogSink — минимальная реализация grpc.ServerStreamingServer[daemon.Log] в
// процессе, без единого байта по сети (см. комментарий у OnInternalLog выше).
type internalLogSink struct {
	ctx   context.Context
	onMsg func(level, message string)
}

func (s *internalLogSink) Send(msg *daemon.Log) error {
	if s.onMsg == nil {
		return nil
	}
	for _, m := range msg.GetMessages() {
		s.onMsg(m.GetLevel().String(), m.GetMessage())
	}
	return nil
}

func (s *internalLogSink) Context() context.Context     { return s.ctx }
func (s *internalLogSink) SetHeader(metadata.MD) error  { return nil }
func (s *internalLogSink) SendHeader(metadata.MD) error { return nil }
func (s *internalLogSink) SetTrailer(metadata.MD)       {}
func (s *internalLogSink) SendMsg(m interface{}) error  { return nil }
func (s *internalLogSink) RecvMsg(m interface{}) error  { return nil }

// Reload — горячая перезагрузка. StartOrReloadService уже умеет заменять работающий
// инстанс, поэтому Reload — это WriteConfig + Start, без отдельного пути.
//
// Задача #11 (2026-08-13): живой WiFi-flap стресс-тест обнаружил, что после успешного
// Reload (err=nil, 40-70мс) трафик минутами продолжает долбиться в адрес БРОШЕННОГО узла
// под тем же тегом "proxy" — похоже на retry-состояние внутри vendored gVisor/sing-tun
// TUN-стека, не на гонку в нашем коде (connMu подтверждён железно диагностическим логом
// diag-11, box.Box.Close() подтверждён полностью синхронным по исходнику). Пробовали
// защитную меру — явный Stop() + пауза 300мс перед Start() вместо доверия встроенному
// swap'у: живой повтор того же сценария показал took=~350мс (мера точно исполнялась), но
// утечка не сократилась (16m21s+, дольше исходных 7m34s+) — эффекта НЕТ, мера снята.
// Первопричина остаётся внутри vendor gVisor/sing-tun, не патчится на этом уровне — см.
// память apf-overlapping-singbox-instances.
func (r *InProcessRunner) Reload(ctx context.Context, cfg *Config) error {
	if err := r.WriteConfig(cfg); err != nil {
		return err
	}
	return r.Start(ctx)
}

// IsRunning отражает истинное состояние libbox-инстанса, а не локальный флаг.
func (r *InProcessRunner) IsRunning() bool {
	return r.server.Instance() != nil
}

// ─── inProcessHandler · libbox.CommandServerHandler ────────────────────────────
//
// Формальная реализация: gRPC-поверхность CommandServer (единственный вызывающий этих
// методов путь) никогда не поднимается — APF использует CommandServer только как держатель
// связки PlatformInterface → adapter.PlatformInterface (ТЗ §2.2), а не как gRPC-сервис.
type inProcessHandler struct {
	runner *InProcessRunner
}

func (h *inProcessHandler) ServiceStop() error {
	return h.runner.Stop()
}

func (h *inProcessHandler) ServiceReload() error {
	h.runner.mu.Lock()
	cfg := h.runner.cfg
	h.runner.mu.Unlock()
	if cfg == nil {
		return errors.New("singbox: нет сохранённой конфигурации для перезагрузки")
	}
	return h.runner.Reload(context.Background(), cfg)
}

// GetSystemProxyStatus — на Android понятия «системный прокси» (в смысле, в каком его
// знают десктопные sing-box клиенты) не существует; честно "недоступен", не выдумка.
func (h *inProcessHandler) GetSystemProxyStatus() (*libbox.SystemProxyStatus, error) {
	return &libbox.SystemProxyStatus{Available: false, Enabled: false}, nil
}

func (h *inProcessHandler) SetSystemProxyEnabled(enabled bool) error {
	return errors.New("singbox: системный прокси на этой платформе не поддерживается")
}

func (h *inProcessHandler) WriteDebugMessage(message string) {}
