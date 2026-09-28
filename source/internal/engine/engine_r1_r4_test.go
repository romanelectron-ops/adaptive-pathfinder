package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// routedKS — бэкенд, считающий обращения. Через него проверяется инвариант R-4.1:
// «не существует пути, изменяющего фаервол в обход выбранного бэкенда».
type routedKS struct {
	caps       killswitch.Capabilities
	enabled    bool
	enableErr  error
	disableErr error

	enables   int
	disables  int
	resets    int
	resetAlls int
}

func (k *routedKS) Enable(tun string, ports []int) error {
	k.enables++
	if k.enableErr != nil {
		return k.enableErr
	}
	k.enabled = true
	return nil
}
func (k *routedKS) Disable() error {
	k.disables++
	k.enabled = false
	return k.disableErr
}
func (k *routedKS) IsEnabled() bool                           { return k.enabled }
func (k *routedKS) Capabilities() killswitch.Capabilities     { return k.caps }
func (k *routedKS) Reset() error                              { k.resets++; return nil }
func (k *routedKS) ResetAll() error                           { k.resetAlls++; return nil }
func (k *routedKS) SetVPNEndpoint(ip string, port int)        {}
func (k *routedKS) EnsureTunPermit(tunInterface string) error { return nil }

// engineWithKS — движок с уже выбранным бэкендом и свежей отметкой пробы, чтобы
// currentKS() отдавал именно наш мок, а не переоценивал выбор.
func engineWithKS(mode string, ks killswitch.KillSwitch) *Engine {
	return &Engine{
		cfg:        &models.AppConfig{ConnectionMode: mode, ListenPort: 10808, EnableKillSwitch: true},
		ks:         ks,
		ksProbedAt: time.Now(),
	}
}

// ─── R-4.2 / C-7 · ленивый выбор бэкенда ─────────────────────────────────────

// В пределах TTL повторная проба не делается — иначе каждый вызов дёргал бы named-pipe.
func TestCurrentKS_TTLCacheKeepsBackend(t *testing.T) {
	// Мок не поддерживает НИЧЕГО: если бы переоценка случилась, он был бы заменён.
	ks := &routedKS{caps: killswitch.Capabilities{}}
	e := engineWithKS(models.ModeVPN, ks)

	if got := e.currentKS(); got != killswitch.KillSwitch(ks) {
		t.Fatal("в пределах TTL бэкенд обязан возвращаться как есть")
	}
	if got := e.currentKS(); got != killswitch.KillSwitch(ks) {
		t.Fatal("повторный вызов в пределах TTL переоценил выбор")
	}
}

// Инвариант R-4.2: АКТИВНЫЙ бэкенд не подменяется никогда. Иначе поставленные им правила
// остались бы бесхозными, а Disable ушёл бы «не туда» — это и есть класс дефекта C-3.
func TestCurrentKS_NeverSwapsEnabledBackend(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{}, enabled: true}
	e := engineWithKS(models.ModeVPN, ks)
	e.ksProbedAt = time.Time{} // форсируем переоценку

	if got := e.currentKS(); got != killswitch.KillSwitch(ks) {
		t.Fatal("активный бэкенд подменён — уже поставленные правила стали бы бесхозными")
	}
}

// Локальный бэкенд, не покрывающий текущий режим, обязан быть пересоздан (R-1.2/C-1).
func TestCurrentKS_RecreatesLocalBackendNotSupportingMode(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}} // netsh-подобный
	e := engineWithKS(models.ModeVPN, ks)
	e.ksProbedAt = time.Time{}

	if got := e.currentKS(); got == killswitch.KillSwitch(ks) {
		t.Fatal("proxy-only бэкенд оставлен для VPN-режима — это и есть C-1")
	}
}

// А покрывающий — не пересоздаётся: лишние пересоздания теряли бы состояние.
func TestCurrentKS_KeepsLocalBackendSupportingMode(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeProxy, ks)
	e.ksProbedAt = time.Time{}

	if got := e.currentKS(); got != killswitch.KillSwitch(ks) {
		t.Fatal("подходящий бэкенд пересоздан без причины")
	}
}

// P0.1 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md, живой инцидент 2026-08-19): процесс-служба
// сам обслуживает \\.\pipe\APF-KS — currentKS() НЕ должен пытаться дозвониться до своего же
// пайпа (killswitch.NewServiceClient()), иначе self-IPC подменяет уже корректно выбранный
// локальный бэкенд (обычно WFP) на бэкенд пайпа (netsh по умолчанию), понижая Capabilities до
// TunMode=false и вызывая fail-closed отказ КАЖДОГО VPN-подключения. Инвариант проверяем
// косвенно, но детерминированно: после переоценки с ksSelfService=true результирующее
// e.ksIsService обязано остаться false — единственная ветка, которая его выставляет true,
// гейтится этим флагом.
func TestCurrentKS_SelfServiceNeverDialsOwnPipe(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}} // не поддерживает VPN — форсирует пересоздание
	e := engineWithKS(models.ModeVPN, ks)
	e.ksSelfService = true
	e.ksProbedAt = time.Time{} // форсируем переоценку

	_ = e.currentKS()
	if e.ksIsService {
		t.Fatal("ksSelfService=true, но currentKS() всё равно выбрал serviceClientKS — self-dial по своему же пайпу")
	}
}

// ─── R-1.2 / C-1 · capability-gate ───────────────────────────────────────────

// Главный смысл R-1.2: бэкенд без TunMode до применения KS в VPN-режиме не допускается.
func TestApplyKillSwitch_GateBlocksProxyOnlyBackendInVPNMode(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeVPN, ks)

	err := e.applyKillSwitch(&models.Node{Address: "127.0.0.1"}, nil)
	if err == nil {
		t.Fatal("proxy-only бэкенд допущен в VPN-режим: netsh заблокировал бы весь трафик")
	}
	if !strings.Contains(err.Error(), "vpn") {
		t.Errorf("в сообщении не назван режим: %v", err)
	}
	if ks.enables != 0 {
		t.Errorf("Enable вызван %d раз(а) вопреки гейту", ks.enables)
	}
}

// Fail-closed R-2.1: неразрешимый адрес узла ⇒ ошибка, а НЕ «включим KS как-нибудь».
// Адрес "[]" отвергается разбором ДО обращения к резолверу — тест не ходит в сеть.
func TestApplyKillSwitch_UnresolvableNodeFailsClosed(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}}
	e := engineWithKS(models.ModeProxy, ks)

	err := e.applyKillSwitch(&models.Node{Address: "[]"}, nil)
	if err == nil {
		t.Fatal("нерезолвящийся адрес обязан прерывать подключение")
	}
	if ks.enables != 0 {
		t.Errorf("Enable вызван %d раз(а) при неизвестном IP — правило разрешило бы не тот адрес", ks.enables)
	}
}

// ─── R-4.1 / C-3 · единый маршрут KS-операций ────────────────────────────────

func TestKSReset_RoutesThroughBackend(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeProxy, ks)

	e.ksReset()
	if ks.resets != 1 {
		t.Errorf("Reset бэкенда вызван %d раз(а), ожидался 1 (иначе netsh пошёл бы в обход)", ks.resets)
	}
}

func TestKSResetAll_RoutesThroughBackend(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeProxy, ks)

	if err := e.ksResetAll(); err != nil {
		t.Fatalf("ksResetAll: %v", err)
	}
	if ks.resetAlls != 1 {
		t.Errorf("ResetAll бэкенда вызван %d раз(а), ожидался 1", ks.resetAlls)
	}
}

// ksCall (P0.1-доп., живой инцидент 2026-08-19, ДВА раунда в один день:
// "VPN долго включается/отключается, потом сам отключился и не включился больше — помогло
// только полное удаление приложения" повторилось ДАЖЕ ПОСЛЕ первого таймаут-фикса, потому что
// та версия только переставала ЖДАТЬ зависший вызов, но не лечила сам бэкенд — wfpKS.mu
// оставался захвачен брошенной горутиной НАВСЕГДА, и КАЖДАЯ следующая попытка тоже упиралась в
// тот же mu). Тесты проверяют сам механизм таймаута+самолечения изолированно от реального WFP.
func TestKSCall_ReturnsResultWhenFast(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeProxy, ks)

	got := e.ksCall("op", ks, func() error { return nil })
	if got != nil {
		t.Fatalf("ksCall = %v, want nil", got)
	}
}

func TestKSCall_PropagatesUnderlyingError(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeProxy, ks)

	want := errors.New("boom")
	got := e.ksCall("op", ks, func() error { return want })
	if !errors.Is(got, want) {
		t.Fatalf("ksCall = %v, want %v", got, want)
	}
}

// blockingKS — мок, чей IsEnabled()/Enable() виснут навсегда (имитация зависшего BFE-вызова,
// держащего внутреннюю блокировку бэкенда). block закрывается ТОЛЬКО самим тестом (или никогда).
type blockingKS struct {
	caps  killswitch.Capabilities
	block chan struct{}
}

func (k *blockingKS) Enable(tun string, ports []int) error { <-k.block; return nil }
func (k *blockingKS) Disable() error                       { <-k.block; return nil }
func (k *blockingKS) IsEnabled() bool                       { <-k.block; return false }
func (k *blockingKS) Capabilities() killswitch.Capabilities { return k.caps }

func TestKSCall_GivesUpOnHangAndReplacesBackend(t *testing.T) {
	orig := ksCallTimeout
	ksCallTimeout = 30 * time.Millisecond
	defer func() { ksCallTimeout = orig }()

	stuck := &blockingKS{caps: killswitch.Capabilities{ProxyMode: true}, block: make(chan struct{})}
	e := engineWithKS(models.ModeProxy, stuck)

	start := time.Now()
	err := e.ksCall("Enable", stuck, func() error { return stuck.Enable("apf0", nil) })
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ksCall = nil на зависшем вызове, ожидалась ошибка таймаута")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ksCall вернулся через %v — таймаут не сработал, вызывающий код завис бы вместе с fn", elapsed)
	}
	// Самолечение: после таймаута e.ks должен указывать на НОВЫЙ (не stuck) бэкенд — иначе
	// следующая же попытка снова упёрлась бы в ту же захваченную блокировку stuck.mu.
	e.ksMu.Lock()
	healed := e.ks
	e.ksMu.Unlock()
	if healed == killswitch.KillSwitch(stuck) {
		t.Fatal("e.ks всё ещё указывает на зависший бэкенд — самолечения не произошло, следующая попытка тоже зависнет")
	}
}

// Живой симптом второго раунда: не только Enable/Disable зависают, но и обычный статус-чек
// (currentKS()'а собственный IsEnabled()) — если его не защитить, currentKS() держит e.ksMu на
// всё своё тело, и один зависший бэкенд глушит ВЕСЬ Kill Switch (ksDisable/ksReset/PatchConfig
// и т.п. тоже идут через currentKS()), а не только текущую попытку.
func TestCurrentKS_SelfHealsWhenIsEnabledHangs(t *testing.T) {
	origProbe := ksProbeTimeout
	ksProbeTimeout = 30 * time.Millisecond
	defer func() { ksProbeTimeout = origProbe }()

	stuck := &blockingKS{caps: killswitch.Capabilities{ProxyMode: true}, block: make(chan struct{})}
	e := engineWithKS(models.ModeProxy, stuck)
	e.ksProbedAt = time.Time{} // форсируем переоценку — иначе TTL-кэш вернёт stuck без проверки

	start := time.Now()
	got := e.currentKS()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("currentKS() вернулся через %v — не защищён от зависшего IsEnabled()", elapsed)
	}
	if got == killswitch.KillSwitch(stuck) {
		t.Fatal("currentKS() вернул зависший бэкенд вместо пересозданного")
	}
}

func TestKSDisable_RoutesThroughBackendAndPropagatesError(t *testing.T) {
	want := errors.New("служба отказала")
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}, disableErr: want}
	e := engineWithKS(models.ModeProxy, ks)

	if err := e.ksDisable(); !errors.Is(err, want) {
		t.Fatalf("ksDisable = %v, want %v", err, want)
	}
	if ks.disables != 1 {
		t.Errorf("Disable бэкенда вызван %d раз(а), ожидался 1", ks.disables)
	}
}

// ─── R-2.1 · наблюдаемость отказа ────────────────────────────────────────────

// Отказ KS обязан быть ВИДЕН в статусе, а не только в логе (иначе UI покажет «Connected»
// при снятой защите — это C-4).
func TestKillSwitchStatus_ReportsUnsupportedMode(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true}}
	e := engineWithKS(models.ModeVPN, ks)

	st := e.KillSwitchStatus()
	if !st.Requested {
		t.Error("Requested должен отражать cfg.EnableKillSwitch")
	}
	if st.SupportsMode {
		t.Error("SupportsMode=true для proxy-only бэкенда в VPN-режиме")
	}
	if st.Active {
		t.Error("Active=true при невключённом бэкенде")
	}
	if st.Mode != models.ModeVPN {
		t.Errorf("Mode = %q, want %q", st.Mode, models.ModeVPN)
	}
	if st.Backend != "local" {
		t.Errorf("Backend = %q, want %q", st.Backend, "local")
	}
}

func TestKillSwitchStatus_ReflectsEscapeHatchAndUACDecline(t *testing.T) {
	ks := &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}}
	e := engineWithKS(models.ModeProxy, ks)

	e.SetAllowConnectWithoutKS(true)
	e.setKSDeclinedThisSession(true)

	st := e.KillSwitchStatus()
	if !st.AllowedWithoutKS {
		t.Error("разовое разрешение без KS не отражено в статусе")
	}
	if !st.DeclinedUAC {
		t.Error("отказ от UAC в этой сессии не отражён в статусе")
	}
}
