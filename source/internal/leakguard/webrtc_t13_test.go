package leakguard

import "testing"

// T-13(б) — WebRTC Status честно отражает «partial»/«none», никогда не «full».

func TestWebRTCGuard_Status_HonestPartial(t *testing.T) {
	g := NewWebRTCGuard()

	// выключено → none
	st := g.Status()
	if st.Enforced != "none" || st.Enabled {
		t.Errorf("выключенный guard: ожидался none/disabled, got %+v", st)
	}

	// включено → partial (НИКОГДА не full)
	if err := g.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	st = g.Status()
	if !st.Enabled {
		t.Error("после Enable должно быть enabled")
	}
	if st.Enforced != "partial" {
		t.Errorf("включённый guard должен быть partial (APF не закрывает WebRTC из вне), got %q", st.Enforced)
	}
	if st.Enforced == "full" {
		t.Error("Enforced никогда не должен быть full — это вводит в заблуждение")
	}
	if st.Note == "" {
		t.Error("должно быть честное пояснение про браузерные инструкции")
	}

	// выключение → снова none
	g.Disable()
	if g.Status().Enforced != "none" {
		t.Error("после Disable ожидался none")
	}
}
