package leakguard

import "testing"

// P1 (аудит 2026-09-01, security-раздел, находка №16). Status() раньше отвечал
// Enforced:"delegated" на голом g.enabled, не спрашивая, действует ли Kill Switch —
// единственный механизм, который на Windows хоть что-то делает для блокировки IPv6.

func TestIPv6Guard_Status_Disabled(t *testing.T) {
	g := NewIPv6Guard()
	st := g.Status(true) // killSwitchActive не должен иметь значения, пока guard выключен
	if st.Enabled || st.Enforced != "none" {
		t.Errorf("выключенный guard: ожидался Enabled=false/none, got %+v", st)
	}
}

// Разбор случая из аудита: пользователь включил тумблер "Блокировать утечку IPv6", но Kill
// Switch сейчас не активен (снят/отказал без прав/ждёт UAC) — Status() не должен утверждать
// "delegated", это вводит в заблуждение ровно там, где нужна осознанность.
func TestIPv6Guard_Status_Enabled_KillSwitchInactive_NotDelegated(t *testing.T) {
	if currentGOOS == "linux" {
		t.Skip("на Linux защита не зависит от Kill Switch")
	}
	g := NewIPv6Guard()
	g.enabled.Store(true)
	st := g.Status(false)
	if st.Enforced == "delegated" {
		t.Error("Enforced == \"delegated\" при неактивном Kill Switch — вводит в заблуждение, " +
			"защиты фактически нет")
	}
	if !st.Enabled {
		t.Error("Enabled должен остаться true — тумблер пользователя действительно включён")
	}
	if st.Note == "" {
		t.Error("должно быть честное пояснение, почему защита не действует")
	}
}

func TestIPv6Guard_Status_Enabled_KillSwitchActive_Delegated(t *testing.T) {
	if currentGOOS == "linux" {
		t.Skip("на Linux защита не делегируется Kill Switch — она полная (sysctl)")
	}
	g := NewIPv6Guard()
	g.enabled.Store(true)
	st := g.Status(true)
	if st.Enforced != "delegated" {
		t.Errorf("Enforced = %q, ожидался \"delegated\" при активном Kill Switch", st.Enforced)
	}
	if !st.Enabled {
		t.Error("Enabled должен быть true")
	}
}
