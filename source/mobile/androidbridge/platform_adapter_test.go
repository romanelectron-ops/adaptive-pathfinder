package androidbridge

import (
	"testing"

	libbox "github.com/sagernet/sing-box/experimental/libbox"
)

// fakeProtect — управляемая реализация ProtectCallback для тестов.
type fakeProtect struct {
	result   bool
	lastFd   int
	callsLen int
}

func (f *fakeProtect) Protect(fd int) bool {
	f.lastFd = fd
	f.callsLen++
	return f.result
}

// Контракт UsePlatformAutoDetectInterfaceControl (дефект D-A28, продолжение).
//
// Инвариант: platformAdapter обязан ответить true. Ложное false вернуло бы sing-box
// к собственному auto_detect_interface на базе netlink, который на Android запрещён —
// молчаливый откат к уже пройденному отказу.
func TestUsePlatformAutoDetectInterfaceControl_AlwaysTrue(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 5)
	if !p.UsePlatformAutoDetectInterfaceControl() {
		t.Fatal("UsePlatformAutoDetectInterfaceControl() = false — " +
			"sing-box откатится на запрещённый netlink auto_detect_interface")
	}
}

// Контракт AutoDetectInterfaceControl (B-A02) — успех.
//
// Вход:      fd от sing-box, ProtectCallback, отвечающий true.
// Выход:     nil.
// Инвариант: fd, дошедший до Protect, совпадает с переданным (никакой подмены).
func TestAutoDetectInterfaceControl_ProtectSucceeds(t *testing.T) {
	cb := &fakeProtect{result: true}
	p := newPlatformAdapter(cb, 5)

	if err := p.AutoDetectInterfaceControl(42); err != nil {
		t.Fatalf("AutoDetectInterfaceControl() = %v, ожидался успех", err)
	}
	if cb.lastFd != 42 {
		t.Errorf("Protect вызван с fd=%d, ожидалось 42", cb.lastFd)
	}
	if cb.callsLen != 1 {
		t.Errorf("Protect вызван %d раз, ожидался 1", cb.callsLen)
	}
}

// Контракт AutoDetectInterfaceControl — отказ Protect (B-A02 fail-safe).
//
// Fail-safe: false от Protect обязан стать ошибкой, а не проглатываться. Незащищённый
// сокет sing-box уходит обратно в собственный TUN — петля и полный обрыв связи.
func TestAutoDetectInterfaceControl_ProtectFails(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: false}, 5)

	if err := p.AutoDetectInterfaceControl(7); err == nil {
		t.Fatal("AutoDetectInterfaceControl() = nil при отказе Protect — " +
			"незащищённый сокет остался бы в петле")
	}
}

// Контракт AutoDetectInterfaceControl — ProtectCallback не задан.
//
// Отвергает: nil ProtectCallback — с внятной причиной, не паникой (паника в Go на
// Android убивает процесс приложения целиком).
func TestAutoDetectInterfaceControl_NilCallback(t *testing.T) {
	p := newPlatformAdapter(nil, 5)

	err := p.AutoDetectInterfaceControl(1)
	if err == nil {
		t.Fatal("AutoDetectInterfaceControl() = nil при отсутствующем ProtectCallback")
	}
}

// Контракт OpenTun (B-A13, часть B-A14) — успех.
//
// Тело: возвращает УЖЕ установленный дескриптор, не создаёт новый и не смотрит на options
// (маршруты/адреса уже применены Android Builder-ом до вызова StartTun).
func TestOpenTun_ReturnsExistingFd(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 9)

	fd, err := p.OpenTun(nil)
	if err != nil {
		t.Fatalf("OpenTun() = %v, ожидался успех", err)
	}
	if fd != 9 {
		t.Errorf("OpenTun() = %d, ожидался установленный fd 9", fd)
	}
}

// Контракт OpenTun — дескриптор не установлен.
//
// Отвергает: tunFd <= 0 — с внятной причиной, а не выдуманным дескриптором.
func TestOpenTun_RejectsMissingFd(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 0)

	if _, err := p.OpenTun(nil); err == nil {
		t.Fatal("OpenTun() = nil при отсутствующем дескрипторе")
	}
}

// Контракт заглушек, которым ОШИБКА безопасна (не участвуют в старте туннеля):
// используются точечно, по одному вызову — ошибка теряет один опциональный ответ,
// не прерывает поднятие VPN.
func TestStubs_SafeToError(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 1)

	if _, err := p.FindConnectionOwner(0, "", 0, "", 0); err == nil {
		t.Error("FindConnectionOwner() = nil — должен честно сообщать о нереализованности")
	}
	if err := p.SendNotification(&libbox.Notification{}); err == nil {
		t.Error("SendNotification() = nil — должен честно сообщать о нереализованности")
	}
	if p.UseProcFS() {
		t.Error("UseProcFS() = true — procfs-поиск не реализован")
	}
}

// Контракт заглушек, которым ОШИБКА ОПАСНА: запускаются изнутри старта туннеля
// (platformDefaultInterfaceMonitor.Start вызывается из старта network-менеджера) —
// ошибка оттуда прервала бы весь box.New()/instance.Start(). Здесь "не реализовано"
// обязано означать успешный no-op, а не отказ.
func TestStubs_MustSucceed_NotBreakTunnelStartup(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 1)

	if err := p.StartDefaultInterfaceMonitor(nil); err != nil {
		t.Errorf("StartDefaultInterfaceMonitor() = %v — старт туннеля был бы сорван", err)
	}
	if err := p.CloseDefaultInterfaceMonitor(nil); err != nil {
		t.Errorf("CloseDefaultInterfaceMonitor() = %v", err)
	}
	iter, err := p.GetInterfaces()
	if err != nil {
		t.Fatalf("GetInterfaces() = %v — ошибка здесь используется для решений о состоянии "+
			"сети, а не только для старта, но всё равно обязана быть честным \"пусто\", не отказом", err)
	}
	if iter == nil {
		t.Fatal("GetInterfaces() вернул nil-итератор без ошибки — вызывающая сторона запаникует " +
			"на HasNext()")
	}
	if iter.HasNext() {
		t.Error("пустой итератор сообщает HasNext() = true")
	}
}

// SystemCertificates не должен возвращать nil-итератор — вызывающая сторона (box/common/
// certificate/store.go) перебирает его через HasNext()/Next() без проверки на nil.
func TestSystemCertificates_NeverNilIterator(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 1)

	iter := p.SystemCertificates()
	if iter == nil {
		t.Fatal("SystemCertificates() = nil")
	}
	if iter.HasNext() {
		t.Error("пустой итератор сообщает HasNext() = true")
	}
	if iter.Len() != 0 {
		t.Errorf("Len() = %d, ожидалось 0", iter.Len())
	}
}

// ReadWIFIState/LocalDNSTransport — заглушки, чей nil уже ожидается вызывающей стороной
// (проверено по исходнику: baseContext проверяет LocalDNSTransport на nil перед
// использованием, ReadWIFIState в ТЗ §2 заранее согласован как nil).
func TestStubs_NilIsExpectedByCaller(t *testing.T) {
	p := newPlatformAdapter(&fakeProtect{result: true}, 1)

	if p.ReadWIFIState() != nil {
		t.Error("ReadWIFIState() != nil — состояние Wi-Fi APF нигде не собирает")
	}
	if p.LocalDNSTransport() != nil {
		t.Error("LocalDNSTransport() != nil — у APF свой DNS в конфигурации sing-box")
	}
	if p.UnderNetworkExtension() {
		t.Error("UnderNetworkExtension() = true — это понятие iOS, на Android неприменимо")
	}
	if p.IncludeAllNetworks() {
		t.Error("IncludeAllNetworks() = true — это понятие iOS, на Android неприменимо")
	}
	// Не должно паниковать без собственного состояния.
	p.ClearDNSCache()
}
