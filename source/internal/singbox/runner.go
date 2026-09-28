package singbox

import "context"

// Runner — то, что engine.Engine на самом деле требует от «запускателя» sing-box:
// семь методов Process, которыми engine.go уже пользуется (дефект/этап Э-4, Ш-3).
//
// Зачем интерфейс, а не *Process напрямую. На Android в режиме VPN sing-box обязан жить
// В ПРОЦЕССЕ приложения (см. docs/TZ_ANDROID_E4_v1.1.md §1 — TUN-дескриптор и protect()
// не пересекают границу процессов), поэтому нужен ВТОРОЙ запускатель — оборачивающий
// libbox.CommandServer, а не exec.Command. Остальной engine.go (подбор узла, watchdog,
// аварийное переключение) не обязан знать, какой из двух работает под капотом: он уже
// написан и покрыт тестами в терминах Start/Stop/WriteConfig/Reload/IsRunning.
//
// *Process удовлетворяет Runner структурно, без единой правки: все семь методов у него
// уже были нужной формы до появления этого файла — см. static-assert ниже.
type Runner interface {
	// IsInstalled сообщает, есть ли чем запускать sing-box.
	IsInstalled() bool
	// Version возвращает версию установленного sing-box.
	Version() (string, error)
	// WriteConfig фиксирует конфигурацию для следующего Start/Reload.
	WriteConfig(cfg *Config) error
	// Start поднимает sing-box по записанной конфигурации.
	Start(ctx context.Context) error
	// Stop останавливает sing-box. Идемпотентен: повторный вызов не ошибка.
	Stop() error
	// Reload — горячая перезагрузка конфигурации без полной пересборки состояния.
	Reload(ctx context.Context, cfg *Config) error
	// IsRunning сообщает текущее состояние.
	IsRunning() bool
}

var _ Runner = (*Process)(nil)

// TunReloader — необязательное расширение Runner для запускателей, которым обычного
// Reload недостаточно: задача #11 (2026-08-13/17), «зомби»-трафик в брошенный узел
// после автопереключения на Android TUN. Обычный Reload (WriteConfig+Start поверх ТОГО
// ЖЕ TUN-fd) не решил проблему — рабочая гипотеза указывает на состояние где-то внутри
// vendored gVisor/sing-tun, живущее ДОЛЬШЕ, чем полностью синхронный box.Box.Close().
// ReloadWithFreshTun — архитектурный обход, а не патч симптома: вместо переиспользования
// существующего системного TUN-интерфейса запрашивает у платформы АБСОЛЮТНО НОВЫЙ
// (Android VpnService.Builder.establish() заново, "seamless handover") и поднимает
// sing-box поверх него, оставляя старый интерфейс полностью изолированным от реальной
// маршрутизации ОС — какие бы горутины ни продолжали жить внутри старого gVisor-стека,
// их пакеты уже не попадают в реальный сетевой путь пользователя.
//
// engine.applySingBoxConfig проверяет эту опциональную реализацию только для Reload
// (wasRunning==true); обычный Start (первое подключение) всегда идёт через Runner.Start.
type TunReloader interface {
	ReloadWithFreshTun(ctx context.Context, cfg *Config) error
}
