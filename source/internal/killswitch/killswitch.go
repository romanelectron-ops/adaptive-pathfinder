// Package killswitch реализует Kill Switch — блокировку трафика при потере туннеля.
// Защищает от утечки реального IP.
// Реализации:
//   - Windows: Windows Filtering Platform (WFP) через netsh
//   - Linux:   iptables / nftables
//   - Android: защиту обеспечивает СИСТЕМА («Always-on VPN» + «Блокировать соединения без
//     VPN»); приложение её включить не может и лишь отражает фактическое состояние
package killswitch

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
)

// Capabilities — декларация бэкенда о том, какие режимы работы он СПОСОБЕН защитить (B-0403 · R-1.1).
//
// Мотив (C-1). netsh физически не может выразить «разрешить трафик, уходящий В туннель»:
// Windows Firewall арбитрирует исходящие по адресу НАЗНАЧЕНИЯ (ALE_AUTH_CONNECT) и не умеет
// allow-by-interface (только грубое interfacetype=wireless|lan|ras). Правило
// `remoteip=172.19.0.0/30` разрешает трафик К подсети TUN-линка, а не трафик, уходящий ЧЕРЕЗ TUN
// на произвольный адрес. При default-block-outbound это блокирует ВЕСЬ пользовательский трафик в
// VPN-режиме: «Kill Switch работает, интернета нет».
//
// Поэтому бэкенд обязан честно декларировать возможности, а движок — НИКОГДА не применять KS
// в режиме, который бэкенд не поддерживает (инвариант R-1.1).
type Capabilities struct {
	// ProxyMode — приложения ходят через локальный SOCKS/HTTP (127.0.0.1); наружу выходит только
	// sing-box к IP узла ⇒ защитимо фильтрацией по адресу назначения (это умеет и netsh).
	ProxyMode bool
	// TunMode — трафик приложений уходит через TUN на ПРОИЗВОЛЬНЫЕ адреса ⇒ требуется
	// allow-by-interface: WFP (FWPM_CONDITION_IP_LOCAL_INTERFACE по LUID) или iptables (-o tun).
	TunMode bool
}

// SupportsMode сообщает, защищает ли бэкенд заданный режим подключения.
// Строки режимов совпадают с models.ModeVPN/ModeProxy/ModeHybrid; пакет killswitch намеренно
// не импортирует internal/models (иначе получилась бы циклическая зависимость слоёв).
// Неизвестный/пустой режим трактуется как proxy — ровно так же, как движок вычисляет tunMode.
func (c Capabilities) SupportsMode(mode string) bool {
	switch mode {
	case "vpn", "hybrid":
		return c.TunMode
	default:
		return c.ProxyMode
	}
}

// KillSwitch — интерфейс Kill Switch
type KillSwitch interface {
	// Enable блокирует весь трафик кроме туннеля
	Enable(tunInterface string, allowedPorts []int) error
	// Disable снимает блокировку
	Disable() error
	// IsEnabled возвращает текущее состояние
	IsEnabled() bool
	// Capabilities декларирует, какие режимы бэкенд способен защитить (R-1.1).
	// Контракт: НЕ зависит от текущего состояния (enabled/LUID) — это статическая
	// характеристика механизма, а не рантайм-статус.
	Capabilities() Capabilities
}

// tunPermitEnsurer — опциональное расширение бэкенда: досоздать permit-правило для TUN, когда
// интерфейс наконец поднялся (R-6.1/C-10). Kill Switch включается ДО старта sing-box (иначе есть
// окно утечки), поэтому в момент Enable интерфейса apf0 ещё нет и его LUID неизвестен.
// Реализуют бэкенды с allow-by-interface (wfpKS); для остальных вызов не имеет смысла.
type tunPermitEnsurer interface {
	// EnsureTunPermit идемпотентно добавляет permit для TUN. Возвращает ошибку, если правило
	// так и не удалось поставить (вызывающий обязан считать защиту VPN-режима непригодной).
	EnsureTunPermit(tunInterface string) error
}

// Injection vars — overridden in tests.
var (
	newKSGOOS = func() string { return runtime.GOOS }
	execCmdFn = realExecCmd
)

// realExecCmd — боевое исполнение команды. В проде execCmdFn указывает на него;
// в тестах execCmdFn заменяется no-op барьером DEF-08 (ks_testguard.go), поэтому
// тесты, проверяющие реальный exec, вызывают realExecCmd через локальную подмену.
func realExecCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, out)
	}
	return nil
}

// NewLocalBackend возвращает локальный (внутрипроцессный) бэкенд KS, пригодный для нужного режима (R-1.2).
//
// Вход:  needTunMode — трафик приложений уйдёт через TUN (режим VPN/Hybrid).
// Тело:  для TUN-режима на Windows единственный подходящий механизм — WFP (allow-by-interface, C-1);
//
//	берём его, только если движок WFP реально открывается текущими правами (нужен admin/SYSTEM).
//	Для proxy-режима сознательно остаёмся на провалидированном netsh-бэкенде (D-1, вариант B).
//
// Выход: бэкенд; он МОЖЕТ не поддерживать нужный режим — тогда движок обязан отказать (fail-closed),
// а не применять KS вслепую. Проверка — через Capabilities().SupportsMode().
func NewLocalBackend(needTunMode bool) KillSwitch {
	if needTunMode && wfpUsable() {
		if ks, ok := newWFPKS(); ok {
			return ks
		}
	}
	return New()
}

// New создаёт Kill Switch для текущей платформы
func New() KillSwitch {
	switch newKSGOOS() {
	case "windows":
		return &windowsKS{}
	case "linux":
		return &linuxKS{}
	case "android":
		return &androidKS{}
	default:
		return &noopKS{}
	}
}

// ─── Windows Kill Switch (WFP через netsh) ───────────────────────────────────
// Блокирует всё кроме TUN-интерфейса APF через Windows Firewall rules

type windowsKS struct {
	enabled bool
	// РАЗРЕШЁННЫЕ IP VPN-сервера, разложенные по семействам (R-2.3/C-5): netsh отвергает
	// правило, где в одном remoteip= смешаны IPv4 и IPv6, поэтому правил всегда два.
	vpnV4 []string
	vpnV6 []string
}

const ksRuleName = "APF-KillSwitch"

// ksTunSubnet — подсеть TUN-интерфейса apf0. Зеркалит singbox/config_builder.go (Address
// "172.19.0.1/30"): если там меняется адрес TUN — обновить и здесь. Allow-tun даёт трафику,
// маршрутизированному в туннель, проходить при default-block-outbound.
const ksTunSubnet = "172.19.0.0/30"

// windowsRuleSuffixes — ЕДИНСТВЕННЫЙ источник истины об именах netsh-правил APF.
// Из него строятся: применение (ksApplyCommands), очистка (ksCleanupCommands), аварийный
// сброс (reset.go). Добавил суффикс — он автоматически попадает во все пути очистки,
// иначе правило переживёт Disable и нарушит инвариант TG-1 («0 остатков APF»).
var windowsRuleSuffixes = []string{
	// Current rule set (D-31: default-block-outbound + только allow).
	"-allow-loopback",
	"-allow-lan",
	"-allow-vpn",
	"-allow-vpn6", // R-2.3/C-5: IPv6-адреса узла — ОТДЕЛЬНЫМ правилом
	"-allow-tun",
	// Долг-5 (2026-09-21): временные allow-правила для IP кандидатов трафик-пробы скана.
	// Ставятся AllowProbeTargets на время сборки списка и снимаются ClearProbeTargets; здесь —
	// чтобы ЛЮБАЯ очистка/сброс KS их тоже гарантированно снимала (инвариант «0 остатков»).
	"-allow-probe",
	"-allow-probe6",
	// Legacy names kept for backward-compatible cleanup (старые версии ставили явные block).
	"-block-tcp",
	"-block-udp",
	"-block-out",
	"-allow-local",
	"-allow-dns",
}

// SetVPNEndpoint задаёт IP VPN-сервера для allow-правила. port зарезервирован (фильтрация по remoteip).
// Вызывается движком (engine.setVPNEndpointForKS) ПЕРЕД Enable; ip — транспортная форма Я-31.0
// (один IP или список через запятую), которая здесь раскладывается по семействам (R-2.3/C-5).
func (k *windowsKS) SetVPNEndpoint(ip string, port int) { k.vpnV4, k.vpnV6 = splitVPNIPs(ip) }

// ProbeAllower — опциональная возможность бэкенда Kill Switch: НА ВРЕМЯ трафик-пробы скана
// («Собрать список рабочих узлов») разрешить исходящие к IP кандидатов, которые иначе режет
// default-block активного KS (долг-5: скан во время подключения при KS ложно находил 0
// рабочих — проба дзвонит напрямую к endpoint'ам ДРУГИХ узлов, не входящих в allow-list
// активного соединения). Реализуют windowsKS (netsh) и wfpKS (WFP); движок делает type-assert
// и деградирует к прежнему поведению, если бэкенд интерфейс не реализует.
//
// БЕЗОПАСНОСТЬ (вердикт консилиума ACCEPT-WITH-FIXES): расширение УЗКОЕ (только конкретные
// IP узлов-кандидатов, которые пользователь и так тестирует) и ОБРАТИМОЕ; базовый allow-list и
// сама политика blockoutbound НЕ трогаются (аддитивные правила поверх). Снятие гарантируется
// defer'ом в probeCandidates + тем, что суффиксы probe-правил входят в windowsRuleSuffixes
// (их снимет и обычная очистка/аварийный сброс KS, если defer почему-то не отработал).
type ProbeAllower interface {
	AllowProbeTargets(ips []string) error
	ClearProbeTargets() error
}

// AllowProbeTargets добавляет узкие allow-правила (по семействам, R-2.3/C-5) для IP кандидатов
// пробы. Идемпотентно: сперва снимает прежние probe-правила. Аддитивно к базовому KS.
func (k *windowsKS) AllowProbeTargets(ips []string) error {
	_ = k.ClearProbeTargets() // best-effort: убрать возможные остатки прошлой волны
	// Раскладка по семействам БЕЗ ограничения maxClassifiedIPs (splitVPNIPs→classifyIPs режет до 4:
	// это анти-DNS-poisoning лимит для АКТИВНОГО endpoint, где один адрес узла не должен раздуваться
	// в произвольное число IP). Здесь наоборот — намеренно много КОНКРЕТНЫХ IP узлов-кандидатов
	// (движок уже ограничил их числом maxProbeAllowIPs и дедуплицировал в probeCandidateIPs). netsh
	// требует раздельные правила на семейство (R-2.3/C-5): смешанный remoteip= он отвергает.
	var v4, v6 []string
	for _, s := range ips {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	var firstErr error
	add := func(suffix, csv string) {
		if csv == "" {
			return
		}
		args := []string{
			"advfirewall", "firewall", "add", "rule",
			"name=" + ksRuleName + suffix,
			"dir=out", "action=allow", "protocol=any",
			"remoteip=" + csv, "profile=any",
		}
		if err := runCmd("netsh", args...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("probe-allow %s: %w", suffix, err)
		}
	}
	add("-allow-probe", strings.Join(v4, ","))
	add("-allow-probe6", strings.Join(v6, ","))
	return firstErr
}

// ClearProbeTargets снимает временные probe-правила. Best-effort: отсутствие правила — не ошибка
// (netsh вернёт ненулевой код, если правила нет, — это нормально, глотаем).
func (k *windowsKS) ClearProbeTargets() error {
	for _, s := range []string{"-allow-probe", "-allow-probe6"} {
		_ = runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ksRuleName+s)
	}
	return nil
}

// ksCleanupCommands — netsh-подкоманды удаления всех APF-правил (текущих + legacy), без префикса "netsh".
// Best-effort: отсутствие правила — не ошибка.
func ksCleanupCommands() [][]string {
	cmds := make([][]string, 0, len(windowsRuleSuffixes))
	for _, s := range windowsRuleSuffixes {
		cmds = append(cmds, []string{"advfirewall", "firewall", "delete", "rule", "name=" + ksRuleName + s})
	}
	return cmds
}

// ksApplyCommands — netsh-подкоманды включения KS по дизайну D-31 (§6.1), без префикса "netsh".
// Порядок: allow-исключения РАНЬШЕ смены политики; blockoutbound — ПОСЛЕДНИМ (к моменту блокировки
// исключения уже существуют → против гонки «KS раньше туннеля»). Эти команды ДОЛЖНЫ выполниться все.
//
// R-2.3 (C-5): семейства адресов узла НИКОГДА не смешиваются в одном remoteip= — netsh отверг бы
// такое правило, а по семантике D-34 («всё или ничего») это откатило бы ВЕСЬ Kill Switch.
// Пустой список семейства ⇒ правило этого семейства просто не создаётся (не ошибка).
func ksApplyCommands(vpnV4, vpnV6 []string) [][]string {
	allow := func(suffix, remoteip string) []string {
		return []string{
			"advfirewall", "firewall", "add", "rule",
			"name=" + ksRuleName + suffix,
			"dir=out", "action=allow", "protocol=any",
			"remoteip=" + remoteip, "profile=any",
		}
	}
	cmds := [][]string{
		// P1 (аудит 2026-09-01, security-раздел, LOW находка №24): было "127.0.0.1" — только
		// /32, тогда как WFP-бэкенд (wfp_plan.go) разрешает весь диапазон 127.0.0.0/8. Софт,
		// слушающий на 127.0.0.2+ (некоторые локальные DNS-заглушки/прокси так делают
		// намеренно, чтобы не занимать общеупотребимый 127.0.0.1), при netsh-бэкенде
		// блокировался бы, при WFP — нет: тот же Kill Switch вёл бы себя по-разному в
		// зависимости от того, какой бэкенд выбрал currentKS(). Приводим netsh к тому же
		// диапазону, что уже используется WFP.
		allow("-allow-loopback", "127.0.0.0/8"),
		allow("-allow-lan", "localsubnet"),
	}
	if len(vpnV4) > 0 {
		cmds = append(cmds, allow("-allow-vpn", strings.Join(vpnV4, ",")))
	}
	if len(vpnV6) > 0 {
		cmds = append(cmds, allow("-allow-vpn6", strings.Join(vpnV6, ",")))
	}
	cmds = append(cmds, allow("-allow-tun", ksTunSubnet))
	// Политика по умолчанию — блокировать исходящее (последним).
	cmds = append(cmds, []string{"advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"})
	return cmds
}

func (k *windowsKS) Enable(tunInterface string, allowedPorts []int) error {
	// Идемпотентная очистка прежних правил (best-effort — отсутствие правила не ошибка).
	k.cleanupRules()

	// D-34: набор применяется по семантике «всё или ничего» — при ЛЮБОЙ ошибке откат и enabled=false.
	for i, args := range ksApplyCommands(k.vpnV4, k.vpnV6) {
		if err := runCmd("netsh", args...); err != nil {
			k.disable() // fail-safe: снять частичные правила и вернуть политику allowoutbound
			k.enabled = false
			return fmt.Errorf("killswitch apply[%d] %s: %w", i, fwRuleLabel(args), err)
		}
	}
	k.enabled = true
	markActive()
	return nil
}

// fwRuleLabel — короткая метка команды для ошибок (имя правила или подкоманда set).
func fwRuleLabel(args []string) string {
	for _, a := range args {
		if len(a) > 5 && a[:5] == "name=" {
			return a[5:]
		}
	}
	if len(args) >= 2 && args[1] == "set" {
		return "set-firewallpolicy"
	}
	return "netsh"
}

// cleanupRules удаляет все APF-правила. Через runCmd (execCmdFn) — под тестом no-op/фейк.
//
// Удаление НЕсуществующего правила netsh считает ошибкой ("No rules match the specified
// criteria"), а это штатная ситуация при повторной очистке — поэтому ошибки отдельных
// delete-команд здесь не фатальны и не собираются. Значимый сигнал даёт только смена
// политики в disable(): если она не прошла, трафик остаётся заблокированным.
func (k *windowsKS) cleanupRules() {
	for _, cmd := range ksCleanupCommands() {
		_ = runCmd("netsh", cmd...)
	}
}

// disable восстанавливает сеть: СНАЧАЛА вернуть политику allowoutbound (немедленно вернуть связь),
// затем удалить все APF-правила. Идемпотентно.
//
// P0-4 (аудит 2026-09-01): возвращает ошибку, а не проглатывает её.
//
// Раньше здесь стояло `_ = runCmd(...)`, и Disable() ВСЕГДА возвращал nil. Без прав
// администратора каждый netsh падал с «Отказано в доступе», ошибка отбрасывалась,
// k.enabled ставился в false, маркер удалялся, а вызывающему сообщалось об успехе. При этом
// политика blockoutbound в Windows ПЕРСИСТЕНТНА: интернета нет и после перезагрузки, а
// приложение уверено, что защиту сняло. Ровно этот класс («пользователь остаётся без
// интернета, приложение рапортует обратное») уже случался вживую.
func (k *windowsKS) disable() error {
	// Ключевая команда: пока политика не вернулась в allowoutbound, весь исходящий трафик
	// заблокирован — её отказ обязан быть виден наверх.
	err := runCmd("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	k.cleanupRules()

	if err != nil {
		// Состояние НЕ трогаем: защита фактически осталась включённой, и врать про это
		// нельзя — иначе следующий Disable() даже не будет предпринят.
		return fmt.Errorf("не удалось вернуть политику брандмауэра (нужны права администратора): %w", err)
	}

	k.enabled = false
	clearActive()
	return nil
}

func (k *windowsKS) Disable() error {
	return k.disable()
}

func (k *windowsKS) IsEnabled() bool { return k.enabled }

// Capabilities: netsh защищает ТОЛЬКО proxy-режим (C-1).
// TunMode=false — принципиальное ограничение механизма, а не недоделка: см. Capabilities.
// Для VPN/Hybrid нужен WFP-бэкенд (wfp_windows.go) — см. R-1.2 в движке.
func (k *windowsKS) Capabilities() Capabilities {
	return Capabilities{ProxyMode: true, TunMode: false}
}

// ─── Linux Kill Switch (iptables) ────────────────────────────────────────────

type linuxKS struct {
	enabled bool
}

// apfChain — имя выделенной цепочки Kill Switch. ВСЕ правила APF живут только в ней;
// в системной цепочке OUTPUT — единственная ссылка "-j APF_KS". Так Disable снимает
// исключительно объекты APF и не затрагивает чужие правила (docker/fail2ban/ufw) — D3.
const apfChain = "APF_KS"

// iptablesRunFn / ip6tablesRunFn — инъектируемые хуки исполнения одной команды
// netfilter. Возвращают (stdout, error). В боевом коде вызывают iptables/ip6tables;
// в тестах подменяются фейковым движком для проверки семантики.
var (
	iptablesRunFn = func(args ...string) (string, error) {
		out, err := exec.Command("iptables", args...).CombinedOutput()
		return string(out), err
	}
	ip6tablesRunFn = func(args ...string) (string, error) {
		out, err := exec.Command("ip6tables", args...).CombinedOutput()
		return string(out), err
	}
)

// linuxKSRules возвращает правила, помещаемые ВНУТРЬ цепочки APF_KS (без имени цепочки —
// оно подставляется при -A). Порядок важен: допуски раньше терминального DROP.
func linuxKSRules(tunInterface string) [][]string {
	rules := [][]string{
		{"-o", "lo", "-j", "ACCEPT"},
		{"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-d", "127.0.0.1", "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
	}
	if tunInterface != "" {
		// допуск TUN вставляем вторым (после lo) — до DNS/DROP
		rules = append([][]string{rules[0], {"-o", tunInterface, "-j", "ACCEPT"}}, rules[1:]...)
	}
	return append(rules, []string{"-j", "DROP"})
}

// ensureChainV4 гарантирует существование пустой цепочки APF_KS (создаёт или флашит).
func ensureChainV4() error {
	if _, err := iptablesRunFn("-N", apfChain); err != nil {
		// уже существует — очищаем
		if _, ferr := iptablesRunFn("-F", apfChain); ferr != nil {
			return fmt.Errorf("ensure chain: %w", ferr)
		}
	}
	return nil
}

// linkChainV4 вставляет прыжок OUTPUT -> APF_KS ровно один раз (idempotent через -C).
func linkChainV4() error {
	if _, err := iptablesRunFn("-C", "OUTPUT", "-j", apfChain); err == nil {
		return nil // ссылка уже есть — не дублируем
	}
	_, err := iptablesRunFn("-I", "OUTPUT", "1", "-j", apfChain)
	return err
}

func (k *linuxKS) Enable(tunInterface string, allowedPorts []int) error {
	k.Disable() // идемпотентная очистка прежнего состояния APF

	// IPv4: создаём цепочку, наполняем, затем привязываем к OUTPUT.
	if err := ensureChainV4(); err != nil {
		k.Disable()
		return fmt.Errorf("iptables APF_KS: %w", err)
	}
	for _, r := range linuxKSRules(tunInterface) {
		args := append([]string{"-A", apfChain}, r...)
		if _, err := iptablesRunFn(args...); err != nil {
			k.Disable() // fail-safe: полный откат, чужие правила не тронуты
			return fmt.Errorf("iptables APF_KS rule: %w", err)
		}
	}
	if err := linkChainV4(); err != nil {
		k.Disable()
		return fmt.Errorf("iptables link APF_KS: %w", err)
	}

	// IPv6: best-effort (ошибки не критичны), та же структура цепочки.
	if _, err := ip6tablesRunFn("-N", apfChain); err != nil {
		ip6tablesRunFn("-F", apfChain)
	}
	for _, r := range linuxKSRules(tunInterface) {
		ip6tablesRunFn(append([]string{"-A", apfChain}, r...)...)
	}
	if _, err := ip6tablesRunFn("-C", "OUTPUT", "-j", apfChain); err != nil {
		ip6tablesRunFn("-I", "OUTPUT", "1", "-j", apfChain)
	}

	k.enabled = true
	markActive()
	return nil
}

// teardownChain снимает прыжок и удаляет цепистку APF_KS для одного семейства (v4/v6)
// через переданный хук. Идемпотентно: отсутствие объектов — не ошибка.
func teardownChain(run func(args ...string) (string, error)) {
	// удаляем ВСЕ прыжки (на случай дублей от старых версий)
	for i := 0; i < 8; i++ {
		if _, err := run("-D", "OUTPUT", "-j", apfChain); err != nil {
			break
		}
	}
	run("-F", apfChain)
	run("-X", apfChain)
}

func (k *linuxKS) Disable() error {
	teardownChain(iptablesRunFn)
	teardownChain(ip6tablesRunFn)
	k.enabled = false
	clearActive()
	return nil
}

func (k *linuxKS) IsEnabled() bool { return k.enabled }

// Capabilities: iptables умеет allow-by-interface (`-o <tun>` в linuxKSRules) ⇒ защищает оба режима.
func (k *linuxKS) Capabilities() Capabilities {
	return Capabilities{ProxyMode: true, TunMode: true}
}

// ─── Android Kill Switch ──────────────────────────────────────────────────────
//
// На Android приложение НЕ МОЖЕТ включить Kill Switch само. Блокировку трафика мимо туннеля
// выполняет система: «Always-on VPN» + «Блокировать соединения без VPN». Это выбор
// пользователя в настройках ОС (или политика владельца устройства через DPC). Никакого
// программного способа включить её из обычного приложения не существует.
//
// Отсюда контракт: Go-слой ОТРАЖАЕТ реальное состояние системы, а не предполагает его.
// Прежняя реализация выставляла булево поле и рапортовала Capabilities{true, true} —
// то есть при D-2 (fail-closed) движок считал себя защищённым, не имея никакой защиты.
// Ложно-безопасное состояние опаснее честного отсутствия Kill Switch: движок не тормозит
// там, где обязан.

// androidSystemProtection — фактическое состояние системной защиты Android.
// Выставляется нативным слоем через androidbridge.SetSystemKillSwitch после опроса
// настроек ОС. По умолчанию false: пока не доказано обратное, защиты нет.
var androidSystemProtection atomic.Bool

// SetAndroidSystemProtection сообщает Go-слою реальное состояние «Always-on VPN + lockdown».
// Вызывается нативным слоем Android; на прочих платформах не имеет эффекта.
func SetAndroidSystemProtection(active bool) { androidSystemProtection.Store(active) }

// AndroidSystemProtection возвращает последнее известное состояние системной защиты.
func AndroidSystemProtection() bool { return androidSystemProtection.Load() }

type androidKS struct {
	enabled bool
}

// Enable не включает защиту — включить её из приложения невозможно. Метод лишь проверяет,
// что система её уже обеспечивает, и отказывает, если нет. Отказ обязателен: при
// fail-closed молчаливое «ок» превратилось бы в незаметную утечку.
func (k *androidKS) Enable(_ string, _ []int) error {
	if !androidSystemProtection.Load() {
		return fmt.Errorf("killswitch: на Android защиту включает система — " +
			"Настройки → VPN → «Always-on VPN» и «Блокировать соединения без VPN»; " +
			"сейчас они выключены, приложение включить их не может")
	}
	k.enabled = true
	return nil
}

func (k *androidKS) Disable() error {
	k.enabled = false
	return nil
}

// IsEnabled: защита есть только если её подтверждает система. Собственный флаг без
// системного подтверждения ничего не значит.
func (k *androidKS) IsEnabled() bool { return k.enabled && androidSystemProtection.Load() }

// Capabilities: сообщаем ровно то, что подтверждено системой. Пока «Always-on VPN +
// lockdown» не включены — защиты нет ни в одном режиме, и движок обязан это знать.
func (k *androidKS) Capabilities() Capabilities {
	active := androidSystemProtection.Load()
	return Capabilities{ProxyMode: active, TunMode: active}
}

// ─── Noop (заглушка для неподдерживаемых платформ) ───────────────────────────

type noopKS struct{}

func (k *noopKS) Enable(_ string, _ []int) error { return nil }
func (k *noopKS) Disable() error                 { return nil }
func (k *noopKS) IsEnabled() bool                { return false }

// Capabilities: заглушка не защищает НИЧЕГО и обязана в этом признаться (R-1.1).
// Иначе движок сообщал бы «Kill Switch включён» там, где никакой блокировки нет — это тот же
// класс дефекта, что C-4 (тихий fail-open).
func (k *noopKS) Capabilities() Capabilities { return Capabilities{} }

// ─── Вспомогательные функции ──────────────────────────────────────────────────

func runCmd(name string, args ...string) error {
	return execCmdFn(name, args...)
}
