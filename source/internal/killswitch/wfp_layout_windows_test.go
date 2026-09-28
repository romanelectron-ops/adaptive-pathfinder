//go:build windows && (amd64 || arm64)

package killswitch

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// B-0402.4 + B-0403 · R-9 — офлайн-сверка РАЗМЕРОВ И СМЕЩЕНИЙ FWPM-структур с C-ABI (x64/arm64,
// модель LLP64: указатель 8, UINT32 4, выравнивание GUID 4).
//
// Размеров недостаточно: две ошибки могут скомпенсировать друг друга по итоговому размеру и
// разъехаться по смещениям — ровно это и было в fwpmFilter0 (см. C-16). Поэтому каждое поле,
// которое читает API, закреплено отдельно.
// Ожидаемые значения выведены из fwpmtypes.h/fwptypes.h. Рантайм-сверка на admin-стенде этим НЕ
// отменяется, но риск снижается радикально.

func TestWFPStructSizes(t *testing.T) {
	if unsafe.Sizeof(windows.GUID{}) != 16 {
		t.Fatalf("GUID size %d, want 16", unsafe.Sizeof(windows.GUID{}))
	}
	if unsafe.Alignof(windows.GUID{}) != 4 {
		t.Fatalf("GUID align %d, want 4 (иначе весь расчёт паддингов неверен)",
			unsafe.Alignof(windows.GUID{}))
	}
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"fwpValue0", unsafe.Sizeof(fwpValue0{}), 16},
		{"fwpConditionValue0", unsafe.Sizeof(fwpConditionValue0{}), 16},
		{"fwpV4AddrAndMask", unsafe.Sizeof(fwpV4AddrAndMask{}), 8},
		{"fwpV6AddrAndMask", unsafe.Sizeof(fwpV6AddrAndMask{}), 17},
		{"fwpByteBlob", unsafe.Sizeof(fwpByteBlob{}), 16},
		{"fwpmDisplayData0", unsafe.Sizeof(fwpmDisplayData0{}), 16},
		{"fwpmFilterCondition0", unsafe.Sizeof(fwpmFilterCondition0{}), 40},
		// R-9/C-16: 20, а не 24 — у GUID выравнивание 4, паддинг после UINT32 не нужен.
		{"fwpmAction0", unsafe.Sizeof(fwpmAction0{}), 20},
		{"fwpmSession0", unsafe.Sizeof(fwpmSession0{}), 72},
		{"fwpmSublayer0", unsafe.Sizeof(fwpmSublayer0{}), 72},
		// R-9/C-16: 200, а не 192 — union rawContext/providerContextKey занимает 16 байт.
		{"fwpmFilter0", unsafe.Sizeof(fwpmFilter0{}), 200},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s size = %d, want %d (C-ABI x64)", c.name, c.got, c.want)
		}
	}
}

// Смещения внутри union-значений — то, от чего зависит marshaling условий фильтра.
func TestWFPValueOffsets(t *testing.T) {
	if off := unsafe.Offsetof(fwpValue0{}.value); off != 8 {
		t.Errorf("fwpValue0.value offset = %d, want 8", off)
	}
	if off := unsafe.Offsetof(fwpConditionValue0{}.value); off != 8 {
		t.Errorf("fwpConditionValue0.value offset = %d, want 8", off)
	}
	if off := unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue); off != 24 {
		t.Errorf("fwpmFilterCondition0.conditionValue offset = %d, want 24", off)
	}
	// GUID действия обязан идти сразу за типом: если между ними появится паддинг, API прочитает
	// его как filterType и для FWP_ACTION_CALLOUT_* взяло бы мусорный GUID.
	if off := unsafe.Offsetof(fwpmAction0{}.guid); off != 4 {
		t.Errorf("fwpmAction0.guid offset = %d, want 4", off)
	}
}

// Полная карта FWPM_FILTER0. Именно её разъезд и был дефектом C-16.
func TestWFPFilterFieldOffsets(t *testing.T) {
	var f fwpmFilter0
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"filterKey", unsafe.Offsetof(f.filterKey), 0},
		{"displayData", unsafe.Offsetof(f.displayData), 16},
		{"flags", unsafe.Offsetof(f.flags), 32},
		{"providerKey", unsafe.Offsetof(f.providerKey), 40},
		{"providerData", unsafe.Offsetof(f.providerData), 48},
		{"layerKey", unsafe.Offsetof(f.layerKey), 64},
		{"subLayerKey", unsafe.Offsetof(f.subLayerKey), 80},
		{"weight", unsafe.Offsetof(f.weight), 96},
		{"numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112},
		{"filterCondition", unsafe.Offsetof(f.filterCondition), 120},
		{"action", unsafe.Offsetof(f.action), 128},
		{"rawContext", unsafe.Offsetof(f.rawContext), 152},
		{"reserved", unsafe.Offsetof(f.reserved), 168},
		{"filterId", unsafe.Offsetof(f.filterId), 176},
		{"effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("fwpmFilter0.%s offset = %d, want %d (C-ABI x64) — поле уедет мимо того, "+
				"что читает FwpmFilterAdd0", c.name, c.got, c.want)
		}
	}
}
