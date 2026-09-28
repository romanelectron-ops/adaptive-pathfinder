//go:build windows && (amd64 || arm64)

// B-0402.4 — Windows Kill Switch на настоящем WFP (FWPM API, fwpuclnt.dll).
//
// B-0403 · R-9: тег ограничен 64-битными архитектурами намеренно. Раскладка FWPM-структур здесь
// выписана вручную под модель LLP64 (указатель 8 байт). На windows/386 указатели 4-байтные, все
// смещения уезжают, и код собрался бы, но маршалил бы мусор в ядро — то есть ставил бы фильтры
// фаервола по случайным адресам. Лучше не иметь WFP-бэкенда, чем иметь неверный (см. wfp_other.go).
//
// СТАТУС: COMPILE-VERIFIED SCAFFOLD. Разметка FWPM-структур (unions/выравнивание) ДОЛЖНА быть
// сверена на живом admin-Windows (см. ТЗ §6 «Риски»). Логика набора фильтров — в wfp_plan.go (тесты).
//
// Ключевой выигрыш: движок открывается с FWPM_SESSION_FLAG_DYNAMIC → ВСЕ объекты авто-удаляются при
// закрытии хэндла (в т.ч. смерти процесса) → crash-safe без маркера/admin-delete (снимает D-33).
package killswitch

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── биндинг fwpuclnt.dll ─────────────────────────────────────────────────────
var (
	modFwpuclnt               = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0       = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0      = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0      = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0        = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0 = modFwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmTxnBegin0         = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTxnCommit0        = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTxnAbort0         = modFwpuclnt.NewProc("FwpmTransactionAbort0")

	modIphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
)

// resolveTunLUID переводит alias интерфейса (apf0) в NET_LUID (uint64). 0 при неудаче
// (apf0 ещё нет / ошибка) → permit-tun просто пропускается (plan это допускает).
func resolveTunLUID(alias string) uint64 {
	if alias == "" {
		return 0
	}
	p, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0
	}
	var luid uint64
	r, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&luid)))
	if r != 0 {
		return 0
	}
	return luid
}

// ─── константы FWP ────────────────────────────────────────────────────────────
const (
	rpcCAuthnWinNT           = 10         // RPC_C_AUTHN_WINNT
	fwpmSessionFlagDynamic   = 0x00000001 // FWPM_SESSION_FLAG_DYNAMIC — авто-снятие при закрытии движка
	fwpActionFlagTerminating = 0x00001000 // FWP_ACTION_FLAG_TERMINATING
	fwpActionBlock           = 0x00000001 | fwpActionFlagTerminating
	fwpActionPermitVal       = 0x00000002 | fwpActionFlagTerminating

	fwpUint8             = 1   // FWP_UINT8
	fwpUint64            = 4   // FWP_UINT64 (значение — указатель на uint64)
	fwpV4AddrAndMaskType = 256 // 0x100 FWP_V4_ADDR_AND_MASK (значение — указатель на структуру)
	fwpV6AddrAndMaskType = 257 // 0x101 FWP_V6_ADDR_AND_MASK (значение — указатель на структуру)

	fwpMatchEqual = 0 // FWP_MATCH_EQUAL
)

// Well-known GUID (layers/conditions). Парсим канонические строки — без ручной упаковки Data4.
func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic("killswitch/wfp: bad GUID " + s + ": " + err.Error())
	}
	return g
}

var (
	guidLayerALEAuthConnectV4 = mustGUID("{C38D57D1-05A7-4C33-904F-7FBCEEE60E82}")
	guidLayerALEAuthConnectV6 = mustGUID("{4A72393B-319F-44BC-84C3-BA54DCB3B6B4}")
	guidCondIPRemoteAddress   = mustGUID("{B235AE9A-1D64-49B8-A44C-5FF3D9095045}")
	guidCondIPLocalInterface  = mustGUID("{4CD62A49-59C3-4969-B7F3-BDA5D32890A4}")
	guidAPFSubLayer           = mustGUID("{A9F1B2C3-1111-2222-3333-AABBCCDDEEFF}") // наш sublayer
)

// ─── структуры FWPM (x64; РАЗМЕТКУ СВЕРИТЬ НА СТЕНДЕ) ──────────────────────────
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpByteBlob struct {
	size uint32
	_    uint32 // pad
	data *uint8
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	_                    uint32 // pad перед указателем sid (x64)
	sid                  uintptr
	username             *uint16
	kernelMode           int32
	_                    uint32 // pad до 8
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint16
	_            [6]byte // pad до 8 перед указателем
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
	_            [6]byte
}

// fwpValue0 — union {type UINT32; value(8B)}. На x64: 4(type)+4(pad)+8(value)=16.
type fwpValue0 struct {
	typ   uint32
	_     uint32
	value uint64 // прямое значение (uint8..64) ИЛИ указатель (как uintptr)
}

type fwpConditionValue0 struct {
	typ   uint32
	_     uint32
	value uint64
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	_              uint32
	conditionValue fwpConditionValue0
}

// fwpmAction0 — FWPM_ACTION0 { FWP_ACTION_TYPE type; union { GUID filterType; GUID calloutKey; }; }.
//
// B-0403 · R-9 (C-16). Здесь был лишний `_ uint32` — «выравнивание» перед GUID. Его быть не
// должно: windows.GUID выровнен по 4 (DWORD/WORD/WORD/BYTE[8]), поэтому в C структура занимает
// 4+16=20 байт, а не 24. Из-за лишнего паддинга GUID уезжал на 4 байта, и — что важнее — на
// столько же уезжало ВСЁ, что лежит в FWPM_FILTER0 после action.
type fwpmAction0 struct {
	actionType uint32
	guid       windows.GUID // filterType/calloutKey (не используем)
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

// FWP_V6_ADDR_AND_MASK { UINT8 addr[16]; UINT8 prefixLength; } — 17 байт, выравнивание 1.
type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

// fwpmFilter0 — FWPM_FILTER0. Раскладка x64 (и arm64: та же LLP64-модель) выверена по
// fwpmtypes.h; каждое смещение закреплено тестом wfp_layout_windows_test.go.
//
// B-0403 · R-9 (C-16). Было ДВЕ ошибки, частично компенсировавшие друг друга (192 байта вместо
// 200), из-за чего структура «почти работала» и дефект не проявлялся:
//   - action занимала 24 байта вместо 20 (лишний паддинг в fwpmAction0);
//   - union { UINT64 rawContext; GUID providerContextKey; } описан как uint64 (8 байт), хотя
//     GUID в нём делает союз 16-байтным.
//
// Последствие: всё после action читалось API не по своим смещениям, а последние 8 байт
// effectiveWeight лежали ЗА пределами выделенной Go памяти — FwpmFilterAdd0 читал чужие байты.
// Работало это лишь потому, что все «съехавшие» поля при добавлении фильтра игнорируются
// или обязаны быть нулевыми.
type fwpmFilter0 struct {
	filterKey           windows.GUID          // @0   16
	displayData         fwpmDisplayData0      // @16  16
	flags               uint32                // @32   4
	_                   uint32                // @36   4 (выравнивание указателя)
	providerKey         *windows.GUID         // @40   8
	providerData        fwpByteBlob           // @48  16
	layerKey            windows.GUID          // @64  16
	subLayerKey         windows.GUID          // @80  16
	weight              fwpValue0             // @96  16
	numFilterConditions uint32                // @112  4
	_                   uint32                // @116  4 (выравнивание указателя)
	filterCondition     *fwpmFilterCondition0 // @120  8
	action              fwpmAction0           // @128 20
	_                   uint32                // @148  4 (выравнивание union по 8 из-за UINT64)
	rawContext          [16]byte              // @152 16 union{UINT64 rawContext; GUID ctxKey}
	reserved            *windows.GUID         // @168  8
	filterId            uint64                // @176  8
	effectiveWeight     fwpValue0             // @184 16 → размер 200
}

// ─── wfpKS ────────────────────────────────────────────────────────────────────
type wfpKS struct {
	mu      sync.Mutex
	engine  windows.Handle
	enabled bool
	vpnIP   string
	tunLUID uint64
	// tunAlias — имя интерфейса, переданное в Enable. R-6.1: нужно, чтобы повторить резолв LUID
	// позже, когда apf0 уже поднят, БЕЗ участия вызывающего.
	tunAlias string
	// keep — marshaled-буферы, которые обязаны пережить FwpmFilterAdd0: WFP хранит их содержимое,
	// а сборщик мусора Go об этом не знает. Ключ — имя фильтра (R-9/C-15), чтобы targeted-switch
	// отпускал буферы вместе со снятыми фильтрами, а не копил их до Disable.
	keep      map[string][]interface{}
	filterIds map[string]uint64 // имя фильтра → filterId (для targeted-switch)
}

// newWFPKS возвращает WFP-исполнитель (доступность fwpuclnt проверяется лениво при Enable).
func newWFPKS() (KillSwitch, bool) { return &wfpKS{filterIds: map[string]uint64{}}, true }

// wfpUsable проверяет, что WFP реально доступен ЭТОМУ процессу: открывает динамическую сессию и
// сразу закрывает её. Побочных эффектов нет — ни sublayer, ни фильтры не создаются.
// Нужен, чтобы не выбирать WFP-бэкенд там, где FwpmEngineOpen0 всё равно откажет (нет admin/SYSTEM).
func wfpUsable() bool {
	// DEF-08: под `go test` НИКОГДА не трогаем WFP хоста.
	if underTest() {
		return false
	}
	k := &wfpKS{filterIds: map[string]uint64{}}
	if err := k.engineOpen(); err != nil {
		return false
	}
	k.engineClose()
	return true
}

// SetVPNEndpoint задаёт VPN-IP. Если KS активен — выполняет TARGETED switch (удаляет только старые
// permit-vpn фильтры по filterId и добавляет новые в транзакции), без полного re-apply и без реэлевации.
func (k *wfpKS) SetVPNEndpoint(ip string, port int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.vpnIP == ip {
		return
	}
	k.vpnIP = ip
	if k.enabled && k.engine != 0 {
		k.switchVPNLocked(ip) // best-effort; при ошибке транзакция откатывается
		// R-6.1: смена узла — удобный момент повторить резолв LUID. К этому времени apf0, скорее
		// всего, уже поднят, даже если в момент Enable его ещё не было. Так снимается зависимость
		// от порядка «TUN up → Enable»: permit-tun появится сам, без участия вызывающего.
		if k.tunLUID == 0 && k.tunAlias != "" {
			if err := k.ensureTunPermitLocked(k.tunAlias); err != nil {
				wfpLogf("killswitch/wfp: повторный резолв LUID при смене узла не удался: " + err.Error())
			} else {
				wfpLogf("killswitch/wfp: permit-tun досоздан при смене узла (LUID разрешился позже Enable)")
			}
		}
	}
}

// switchVPNLocked (под k.mu): удалить старые permit-vpn/-vpn6 по filterId, добавить новые для ip.
func (k *wfpKS) switchVPNLocked(ip string) {
	if r, _, _ := procFwpmTxnBegin0.Call(uintptr(k.engine), 0); r != 0 {
		return
	}
	ok := true
	// R-2.3: снимаем ВСЕ permit-vpn*/permit-vpn6* (у узла может быть несколько A/AAAA-записей).
	for name, id := range k.filterIds {
		if !strings.HasPrefix(name, wfpVpnNamePrefix) {
			continue
		}
		if r, _, _ := procFwpmFilterDeleteById0.Call(uintptr(k.engine), uintptr(id)); r != 0 {
			ok = false
		}
		delete(k.filterIds, name)
		delete(k.keep, name) // R-9/C-15: фильтра больше нет — держать его буферы незачем
	}
	for _, spec := range wfpVpnSpecs(ip) {
		if err := k.addFilter(spec); err != nil {
			ok = false
		}
	}
	if ok {
		procFwpmTxnCommit0.Call(uintptr(k.engine))
	} else {
		procFwpmTxnAbort0.Call(uintptr(k.engine))
	}
}

func (k *wfpKS) engineOpen() error {
	if k.engine != 0 {
		return nil
	}
	name, _ := windows.UTF16PtrFromString("APF Kill Switch (WFP)")
	sess := fwpmSession0{
		flags:       fwpmSessionFlagDynamic, // headline: авто-снятие при закрытии движка
		displayData: fwpmDisplayData0{name: name},
	}
	var engine windows.Handle
	r, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0,
		uintptr(unsafe.Pointer(&sess)), uintptr(unsafe.Pointer(&engine)))
	if r != 0 {
		return fmt.Errorf("killswitch/wfp: FwpmEngineOpen0 = 0x%x (нужны права admin/SYSTEM)", r)
	}
	k.engine = engine
	return nil
}

func (k *wfpKS) engineClose() {
	if k.engine != 0 {
		procFwpmEngineClose0.Call(uintptr(k.engine))
		k.engine = 0
	}
}

func (k *wfpKS) addSublayer() error {
	name, _ := windows.UTF16PtrFromString(ksRuleName)
	sl := fwpmSublayer0{
		subLayerKey: guidAPFSubLayer,
		displayData: fwpmDisplayData0{name: name},
		weight:      0xFFFF,
	}
	r, _, _ := procFwpmSubLayerAdd0.Call(uintptr(k.engine), uintptr(unsafe.Pointer(&sl)), 0)
	// FWP_E_ALREADY_EXISTS (0x80320009) — не ошибка (идемпотентно).
	if r != 0 && r != 0x80320009 {
		return fmt.Errorf("killswitch/wfp: FwpmSubLayerAdd0 = 0x%x", r)
	}
	return nil
}

// addFilter маршалит один wfpFilterSpec и добавляет его.
//
// Буферы условия обязаны пережить вызов: WFP хранит их содержимое, но Go об этом не знает, и без
// удержания сборщик мусора освободил бы память под фильтром. B-0403 · R-9 (C-15): удержание теперь
// ПОИМЁННОЕ — при targeted-switch буферы снятых фильтров отпускаются вместе с ними. Прежний общий
// срез рос при каждой смене узла и не освобождался до Disable.
func (k *wfpKS) addFilter(spec wfpFilterSpec) error {
	var keep []interface{}
	name, _ := windows.UTF16PtrFromString(spec.Name)
	layer := guidLayerALEAuthConnectV4
	if spec.V6 {
		layer = guidLayerALEAuthConnectV6
	}
	f := fwpmFilter0{
		displayData: fwpmDisplayData0{name: name},
		subLayerKey: guidAPFSubLayer,
		layerKey:    layer,
		weight:      fwpValue0{typ: fwpUint8, value: uint64(spec.Weight)},
	}
	if spec.Action == wfpActionBlock {
		f.action = fwpmAction0{actionType: fwpActionBlock}
	} else {
		f.action = fwpmAction0{actionType: fwpActionPermitVal}
	}

	// условие (для permit-фильтров)
	if spec.Condition.Kind != wfpCondNone {
		cond := fwpmFilterCondition0{matchType: fwpMatchEqual}
		switch spec.Condition.Kind {
		case wfpCondRemoteAddrV4Range, wfpCondRemoteAddrV4Equal:
			mask := spec.Condition.Mask
			if spec.Condition.Kind == wfpCondRemoteAddrV4Equal {
				mask = 0xFFFFFFFF
			}
			am := &fwpV4AddrAndMask{addr: spec.Condition.Addr, mask: mask}
			keep = append(keep, am)
			cond.fieldKey = guidCondIPRemoteAddress
			cond.conditionValue = fwpConditionValue0{typ: fwpV4AddrAndMaskType, value: uint64(uintptr(unsafe.Pointer(am)))}
		case wfpCondRemoteAddrV6Range:
			am := &fwpV6AddrAndMask{addr: spec.Condition.Addr6, prefixLength: spec.Condition.Prefix6}
			keep = append(keep, am)
			cond.fieldKey = guidCondIPRemoteAddress
			cond.conditionValue = fwpConditionValue0{typ: fwpV6AddrAndMaskType, value: uint64(uintptr(unsafe.Pointer(am)))}
		case wfpCondLocalInterfaceLUID:
			luid := new(uint64)
			*luid = spec.Condition.LUID
			keep = append(keep, luid)
			cond.fieldKey = guidCondIPLocalInterface
			cond.conditionValue = fwpConditionValue0{typ: fwpUint64, value: uint64(uintptr(unsafe.Pointer(luid)))}
		}
		keep = append(keep, &cond)
		f.numFilterConditions = 1
		f.filterCondition = &cond
	}

	var id uint64
	r, _, _ := procFwpmFilterAdd0.Call(uintptr(k.engine), uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	if r != 0 {
		return fmt.Errorf("killswitch/wfp: FwpmFilterAdd0(%s) = 0x%x", spec.Name, r)
	}
	if k.filterIds == nil {
		k.filterIds = map[string]uint64{}
	}
	k.filterIds[spec.Name] = id
	keep = append(keep, &f, name)
	if k.keep == nil {
		k.keep = map[string][]interface{}{}
	}
	k.keep[spec.Name] = keep
	return nil
}

func (k *wfpKS) Enable(tunInterface string, allowedPorts []int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.enabled {
		return nil // уже активен; смена узла — через SetVPNEndpoint (targeted switch), без re-apply
	}
	k.tunAlias = tunInterface
	k.tunLUID = resolveTunLUID(tunInterface) // apf0 → LUID для permit-tun (0 = пропустить)
	if k.tunLUID == 0 && tunInterface != "" {
		// R-6.1: это НОРМАЛЬНЫЙ случай (KS включается до старта sing-box), но он обязан быть виден:
		// пока permit-tun нет, весь трафик приложений через туннель блокируется терминальным
		// block-all. Досоздаст его EnsureTunPermit (движок) или SetVPNEndpoint (смена узла).
		wfpLogf("killswitch/wfp: ПРЕДУПРЕЖДЕНИЕ — интерфейс " + tunInterface +
			" ещё не существует (LUID=0), permit-tun будет добавлен позже")
	}
	if err := k.engineOpen(); err != nil {
		return err
	}
	// транзакция: sublayer + все фильтры атомарно
	if r, _, _ := procFwpmTxnBegin0.Call(uintptr(k.engine), 0); r != 0 {
		k.engineClose()
		return fmt.Errorf("killswitch/wfp: TransactionBegin = 0x%x", r)
	}
	apply := func() error {
		if err := k.addSublayer(); err != nil {
			return err
		}
		for _, spec := range wfpBuildPlan(k.vpnIP, k.tunLUID) {
			if err := k.addFilter(spec); err != nil {
				return err
			}
		}
		return nil
	}
	if err := apply(); err != nil {
		procFwpmTxnAbort0.Call(uintptr(k.engine))
		k.engineClose()
		k.enabled = false
		return err
	}
	if r, _, _ := procFwpmTxnCommit0.Call(uintptr(k.engine)); r != 0 {
		procFwpmTxnAbort0.Call(uintptr(k.engine))
		k.engineClose()
		k.enabled = false
		return fmt.Errorf("killswitch/wfp: TransactionCommit = 0x%x", r)
	}
	k.enabled = true
	markActive()
	return nil
}

// Disable снимает KS. Достаточно закрыть движок: dynamic session авто-удалит sublayer+фильтры.
func (k *wfpKS) Disable() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.engineClose()
	k.keep = map[string][]interface{}{}
	k.filterIds = map[string]uint64{}
	k.enabled = false
	// R-6.1: фильтров больше нет, значит и запомненный LUID недействителен. Иначе следующий
	// EnsureTunPermit счёл бы permit-tun уже поставленным и молча ничего не сделал.
	k.tunLUID = 0
	clearActive()
	return nil
}

func (k *wfpKS) IsEnabled() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.enabled
}

// Capabilities: WFP — единственный механизм на Windows, умеющий allow-by-interface
// (FWPM_CONDITION_IP_LOCAL_INTERFACE по NET_LUID) ⇒ защищает и VPN/TUN-режим (R-1.1).
//
// Это СТАТИЧЕСКАЯ характеристика механизма, а не «есть ли сейчас LUID»: KS включается ДО старта
// sing-box, поэтому в момент Enable apf0 ещё не существует. Фактическое наличие permit-tun
// обеспечивает EnsureTunPermit, вызываемый движком после подъёма туннеля (R-6.1/C-10).
func (k *wfpKS) Capabilities() Capabilities {
	return Capabilities{ProxyMode: true, TunMode: true}
}

// EnsureTunPermit добавляет permit-фильтры для TUN, когда интерфейс поднялся (R-6.1/C-10).
//
// Вход:  tunInterface — alias интерфейса (apf0).
// Тело:  резолвит LUID; если он уже был учтён при Enable — ничего не делает (идемпотентность);
//
//	иначе добавляет permit-tun/-tun6 в существующий набор ОДНОЙ транзакцией.
//
// Выход: nil — permit-tun гарантированно присутствует; error — нет (VPN-режим не защищён и
//
//	вызывающий обязан отнестись к этому как к сбою KS, а не как к предупреждению).
//
// Fail-safe: при сбое транзакции набор остаётся прежним (блокирующим) — утечки не возникает.
func (k *wfpKS) EnsureTunPermit(tunInterface string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if tunInterface != "" {
		k.tunAlias = tunInterface // запоминаем для отложенного резолва в SetVPNEndpoint (R-6.1)
	}
	return k.ensureTunPermitLocked(tunInterface)
}

// ensureTunPermitLocked — тело EnsureTunPermit под уже взятым k.mu.
func (k *wfpKS) ensureTunPermitLocked(tunInterface string) error {
	if !k.enabled || k.engine == 0 {
		return fmt.Errorf("killswitch/wfp: EnsureTunPermit при неактивном KS")
	}
	luid := resolveTunLUID(tunInterface)
	if luid == 0 {
		return fmt.Errorf("killswitch/wfp: интерфейс %q не найден (LUID=0) — permit-tun не поставлен", tunInterface)
	}
	if _, has := k.filterIds[ksRuleName+"-permit-tun"]; has && k.tunLUID == luid {
		return nil // уже учтён при Enable — идемпотентно
	}
	if r, _, _ := procFwpmTxnBegin0.Call(uintptr(k.engine), 0); r != 0 {
		return fmt.Errorf("killswitch/wfp: TransactionBegin(tun) = 0x%x", r)
	}
	// Снимаем permit-tun от прежнего LUID (смена интерфейса), затем ставим актуальные.
	ok := true
	for _, name := range []string{ksRuleName + "-permit-tun", ksRuleName + "-permit-tun6"} {
		if id, has := k.filterIds[name]; has {
			if r, _, _ := procFwpmFilterDeleteById0.Call(uintptr(k.engine), uintptr(id)); r != 0 {
				ok = false
			}
			delete(k.filterIds, name)
			delete(k.keep, name) // R-9/C-15
		}
	}
	for _, spec := range wfpTunSpecs(luid) {
		if err := k.addFilter(spec); err != nil {
			ok = false
		}
	}
	if !ok {
		procFwpmTxnAbort0.Call(uintptr(k.engine))
		return fmt.Errorf("killswitch/wfp: не удалось добавить permit-tun для LUID %#x", luid)
	}
	if r, _, _ := procFwpmTxnCommit0.Call(uintptr(k.engine)); r != 0 {
		procFwpmTxnAbort0.Call(uintptr(k.engine))
		return fmt.Errorf("killswitch/wfp: TransactionCommit(tun) = 0x%x", r)
	}
	k.tunLUID = luid
	return nil
}

// Reset для WFP = Disable (закрытие динамической сессии снимает ВСЕ наши фильтры) + чистка
// netsh-правил, которые мог оставить прежний бэкенд/прошлая сессия (R-4.1).
func (k *wfpKS) Reset() error {
	_ = k.Disable()
	QuickReset()
	return nil
}

// ResetAll для WFP = Disable + полный откат сетевых настроек (R-4.1).
func (k *wfpKS) ResetAll() error {
	_ = k.Disable()
	return ResetAll()
}

// EnableWithUAC для WFP = обычный Enable (нужен admin; элевация — задача вызывающего/службы).
func (k *wfpKS) EnableWithUAC(vpnIP string, port int) error {
	k.SetVPNEndpoint(vpnIP, port)
	return k.Enable("apf0", []int{port})
}
