package singbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sagernet/sing-box/daemon"
	libbox "github.com/sagernet/sing-box/experimental/libbox"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// androidServerRunner — Э-Выход-2 (docs/PLAN_APF_VHOD_VYHOD_v1.0.md): реализация
// ServerRunner для Android. Android не позволяет запускать сторонний исполняемый
// sing-box.exe отдельным процессом так, как это делает windows_server_runner.go
// (см. его комментарий) — единственный путь, уже проверенный живьём для роли «Вход»
// (Э-4, InProcessRunner), это sing-box В ПРОЦЕССЕ приложения через libbox.CommandServer.
// Роль «Выход» переиспользует ровно тот же путь, другую форму конфигурации (ServerDoc,
// не Config — см. server_config.go) и без PlatformLogWriter-специфики TUN.
//
// PlatformInterface передаётся вызывающей стороной (mobile/androidbridge) — этот файл,
// как и inprocess_runner.go, ничего не знает про Kotlin/gomobile напрямую. ServerDoc
// (BuildServerConfig) не содержит tun-инбаунда, поэтому OpenTun() у переданного
// PlatformInterface никогда не вызывается — но AutoDetectInterfaceControl (protect())
// вызывается ПОТЕНЦИАЛЬНО, потому что BuildServerConfig ставит route.auto_detect_interface
// = true (тот же документ, что и у Windows): исходящий "direct" outbound роли «Выход»
// обязан пройти через protect(), если на устройстве в это же время активен какой-либо
// VPN (свой или сторонний) — иначе его пакеты рискуют уйти в чужой туннель вместо
// реального интернета (vendor/.../route/network.go, AutoDetectInterfaceFunc/ProtectFunc).
// Отсутствие рабочего protect() здесь — фатальная ошибка вызывающей стороны, а не тихая
// деградация: тот же контракт, что уже действует у platformAdapter.AutoDetectInterfaceControl
// в mobile/androidbridge/platform_adapter.go («ни один исходящий сокет sing-box не
// остаётся незащищённым»).
type AndroidServerRunner struct {
	mu     sync.Mutex
	server *libbox.CommandServer
	doc    *ServerDoc

	// OnInternalLog, если задан, получает СЫРЫЕ логи самого sing-box серверной роли —
	// тот же диагностический путь, что уже есть у клиента (InProcessRunner.OnInternalLog,
	// задача #25/D-A37): без него ЕДИНСТВЕННЫЙ видимый симптом отказа Reality-рукопожатия —
	// "connection reset by peer" на КЛИЕНТСКОЙ стороне, а настоящая причина (например,
	// "reality: processed invalid connection") видна только в логах самого сервера.
	// Тип экспортирован (не androidServerRunner) именно ради этого поля — mobile/
	// androidbridge держит конкретный *AndroidServerRunner, а не интерфейс ServerRunner,
	// тем же приёмом, что tun.go уже делает для *InProcessRunner.
	OnInternalLog func(level, message string)
	logCancel     context.CancelFunc
}

// NewAndroidServerRunner создаёт ServerRunner для роли «Выход»/«Транзит» на Android.
func NewAndroidServerRunner(platformInterface libbox.PlatformInterface) (*AndroidServerRunner, error) {
	if platformInterface == nil {
		return nil, errors.New("singbox: NewAndroidServerRunner: platformInterface не задан")
	}
	setupLibbox()
	r := &AndroidServerRunner{}
	server, err := libbox.NewCommandServer(&androidServerHandler{runner: r}, platformInterface)
	if err != nil {
		return nil, fmt.Errorf("singbox: создание серверного in-process запускателя: %w", err)
	}
	r.server = server
	return r, nil
}

// IsInstalled — sing-box уже слинкован в бинарник приложения, отдельной установки нет
// (тот же контракт, что у InProcessRunner.IsInstalled).
func (r *AndroidServerRunner) IsInstalled() bool { return true }

func (r *AndroidServerRunner) Version() (string, error) { return SingBoxVersion, nil }

// GenerateIdentity — тонкая обёртка над GenerateServerIdentity (server_identity.go),
// см. тот же метод у windowsServerRunner.
func (r *AndroidServerRunner) GenerateIdentity() (ServerIdentity, error) {
	return GenerateServerIdentity()
}

// WriteConfig фиксирует конфигурацию для следующего Start. validateServerDoc
// (server_config.go) — общая граница проверки листен-порта, одна на все платформы.
func (r *AndroidServerRunner) WriteConfig(doc *ServerDoc) error {
	if err := validateServerDoc(doc); err != nil {
		return err
	}
	r.mu.Lock()
	r.doc = doc
	r.mu.Unlock()
	return nil
}

// Start поднимает sing-box по записанной конфигурации — StartOrReloadService умеет и
// старт с нуля, и горячую замену поверх работающего инстанса (тот же контракт, что у
// InProcessRunner.Start).
func (r *AndroidServerRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	doc := r.doc
	r.mu.Unlock()
	if doc == nil {
		return errors.New("singbox: WriteConfig не вызван перед Start")
	}

	data, err := ToServerJSON(doc)
	if err != nil {
		return fmt.Errorf("singbox: сериализация серверного конфига: %w", err)
	}
	// &libbox.OverrideOptions{} не nil — та же регрессия Ш-6, что уже закрыта у
	// InProcessRunner.Start (command_server.go разыменовывает *options.AutoRedirect без
	// проверки на nil, литеральный nil здесь означал бы гарантированную панику).
	if err := r.server.StartOrReloadService(string(data), &libbox.OverrideOptions{}); err != nil {
		return fmt.Errorf("singbox: запуск серверной роли in-process: %w", err)
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

// Stop останавливает sing-box. Идемпотентен, тот же контракт, что у InProcessRunner.Stop —
// включая живую находку 2026-08-25 про os.ErrInvalid при расхождении Instance()/serviceStatus
// (см. комментарий у InProcessRunner.Stop, inprocess_runner.go).
func (r *AndroidServerRunner) Stop() error {
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
		return fmt.Errorf("singbox: остановка серверной роли in-process: %w", err)
	}
	return nil
}

// IsRunning отражает истинное состояние libbox-инстанса, а не локальный флаг (тот же
// инвариант, что у InProcessRunner.IsRunning).
func (r *AndroidServerRunner) IsRunning() bool {
	return r.server.Instance() != nil
}

// streamInternalLogs — та же подписка на SubscribeLog, что у InProcessRunner
// (inprocess_runner.go, см. комментарий у OnInternalLog там про причину: gRPC-поверхность
// CommandServer никогда не поднимается, SubscribeLog остаётся обычным Go-вызовом).
func (r *AndroidServerRunner) streamInternalLogs(ctx context.Context) {
	_ = r.server.SubscribeLog(&emptypb.Empty{}, &androidServerLogSink{ctx: ctx, onMsg: r.OnInternalLog})
}

type androidServerLogSink struct {
	ctx   context.Context
	onMsg func(level, message string)
}

func (s *androidServerLogSink) Send(msg *daemon.Log) error {
	if s.onMsg == nil {
		return nil
	}
	for _, m := range msg.GetMessages() {
		s.onMsg(m.GetLevel().String(), m.GetMessage())
	}
	return nil
}

func (s *androidServerLogSink) Context() context.Context     { return s.ctx }
func (s *androidServerLogSink) SetHeader(metadata.MD) error  { return nil }
func (s *androidServerLogSink) SendHeader(metadata.MD) error { return nil }
func (s *androidServerLogSink) SetTrailer(metadata.MD)       {}
func (s *androidServerLogSink) SendMsg(m interface{}) error  { return nil }
func (s *androidServerLogSink) RecvMsg(m interface{}) error  { return nil }

var _ ServerRunner = (*AndroidServerRunner)(nil)

// ─── androidServerHandler · libbox.CommandServerHandler ──────────────────────────
//
// Формальная реализация — зеркало inProcessHandler (inprocess_runner.go): gRPC-поверхность
// CommandServer никогда не поднимается, этот тип только держатель PlatformInterface для
// libbox.NewCommandServer.
type androidServerHandler struct {
	runner *AndroidServerRunner
}

func (h *androidServerHandler) ServiceStop() error {
	return h.runner.Stop()
}

func (h *androidServerHandler) ServiceReload() error {
	h.runner.mu.Lock()
	doc := h.runner.doc
	h.runner.mu.Unlock()
	if doc == nil {
		return errors.New("singbox: нет сохранённой серверной конфигурации для перезагрузки")
	}
	return h.runner.Start(context.Background())
}

// GetSystemProxyStatus — понятия «системный прокси» у роли «Выход» не существует (это
// клиентское понятие), честно "недоступен", как и у клиентского inProcessHandler.
func (h *androidServerHandler) GetSystemProxyStatus() (*libbox.SystemProxyStatus, error) {
	return &libbox.SystemProxyStatus{Available: false, Enabled: false}, nil
}

func (h *androidServerHandler) SetSystemProxyEnabled(enabled bool) error {
	return errors.New("singbox: системный прокси на этой платформе не поддерживается")
}

func (h *androidServerHandler) WriteDebugMessage(message string) {}
