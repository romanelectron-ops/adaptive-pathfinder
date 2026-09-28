package killswitch

import "testing"

// ─── B-0403 · R-6.1 (C-10) · наблюдаемость и полнота permit-tun ──────────────

// «LUID=0» — штатная ситуация (KS включается до старта sing-box), но она обязана быть ВИДНА:
// пока permit-tun нет, терминальный block-all глушит весь трафик приложений через туннель.
func TestSetWFPLogger_ReceivesWarningsAndResets(t *testing.T) {
	old := wfpLogf
	defer func() { wfpLogf = old }()

	var got []string
	SetWFPLogger(func(m string) { got = append(got, m) })
	wfpLogf("предупреждение")
	if len(got) != 1 || got[0] != "предупреждение" {
		t.Fatalf("логгер не получил сообщение: %v", got)
	}

	// nil обязан возвращать «в никуда», а не оставлять прежний логгер и не ронять бэкенд.
	SetWFPLogger(nil)
	wfpLogf("после сброса")
	if len(got) != 1 {
		t.Errorf("после SetWFPLogger(nil) сообщения продолжают идти в старый логгер: %v", got)
	}
}

// permit-tun обязан существовать в ОБОИХ семействах: иначе v6 внутри туннеля упрётся
// в block-all6, и «VPN работает, но половина интернета недоступна».
func TestWFPTunSpecs_CoversBothFamilies(t *testing.T) {
	const luid = uint64(0x1234_5678_9abc_def0)
	specs := wfpTunSpecs(luid)
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2: %+v", len(specs), specs)
	}
	sawV4, sawV6 := false, false
	for _, s := range specs {
		if s.Action != wfpActionPermit {
			t.Errorf("%s: действие не permit", s.Name)
		}
		if s.Weight != wfpWeightPermit {
			t.Errorf("%s: вес %d, permit обязан быть тяжелее block", s.Name, s.Weight)
		}
		if s.Condition.Kind != wfpCondLocalInterfaceLUID || s.Condition.LUID != luid {
			t.Errorf("%s: условие не по LUID интерфейса: %+v", s.Name, s.Condition)
		}
		if s.V6 {
			sawV6 = true
		} else {
			sawV4 = true
		}
	}
	if !sawV4 || !sawV6 {
		t.Errorf("покрыты не оба семейства (v4=%v v6=%v)", sawV4, sawV6)
	}
}

// LUID=0 — «интерфейса ещё нет»; правил в этом случае быть не должно (иначе фильтр по нулевому
// LUID разрешил бы трафик через ЛЮБОЙ интерфейс, то есть открыл бы дыру вместо защиты).
func TestWFPTunSpecs_ZeroLUIDEmitsNothing(t *testing.T) {
	if specs := wfpTunSpecs(0); len(specs) != 0 {
		t.Fatalf("при LUID=0 создано %d правил: %+v", len(specs), specs)
	}
}

// План целиком при LUID=0 обязан оставаться БЛОКИРУЮЩИМ (block-all в обоих семействах на месте).
func TestWFPBuildPlan_ZeroLUIDStaysBlocking(t *testing.T) {
	specs := wfpBuildPlan("1.2.3.4", 0)
	blockV4, blockV6 := false, false
	for _, s := range specs {
		switch s.Name {
		case ksRuleName + "-block-all":
			blockV4 = s.Action == wfpActionBlock
		case ksRuleName + "-block-all6":
			blockV6 = s.Action == wfpActionBlock
		case ksRuleName + "-permit-tun", ksRuleName + "-permit-tun6":
			t.Errorf("permit-tun создан при отсутствующем интерфейсе: %+v", s)
		}
	}
	if !blockV4 || !blockV6 {
		t.Errorf("терминальный блок неполон (v4=%v v6=%v) — возможна утечка", blockV4, blockV6)
	}
}
