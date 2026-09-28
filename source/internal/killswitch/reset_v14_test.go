package killswitch

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
)

// S-14 (TZ v1.4, лот L1-KS) — «resetLinux работает мимо hostguard».
//
// До фикса resetLinux() вызывал exec.Command("ip","link","delete","apf0") и
// exec.Command("resolvectl","revert") НАПРЯМУЮ — не через инжектируемый var и не за барьером
// internal/hostguard (в отличие от iptablesRunFn/ip6tablesRunFn чуть выше в том же файле).
// Итог: `go test` на реальном Linux-хосте мог фактически удалить интерфейс apf0 и откатить
// DNS хоста — ровно тот класс инцидента, для которого и заведён пакет hostguard (см. его
// комментарий: «любая функция, меняющая состояние ОС, ОБЯЗАНА начинаться с проверки
// hostguard.Allow()»).
//
// Фикс (reset.go): оба вызова вынесены в инжектируемые var'ы tunDeleteFn/dnsRevertFn и
// исполняются ТОЛЬКО внутри `if hostguard.Allow(...)`.
//
// Тест ниже проверяет ИМЕННО контракт S-14: без hostguard.Allow (штатное состояние под
// `go test`, без APF_ALLOW_HOST_MUTATION) швы НЕ дёрнуты ни разу, а сама попытка
// зарегистрирована в hostguard.BlockedOps(). Позитивную ветку («если бы hostguard разрешил —
// швы вызываются») тест не воспроизводит: hostguard.Allowed() вычисляется один раз при
// старте процесса (см. internal/hostguard) и не может быть переключён внутри уже запущенного
// `go test`; принудительный override экспериментально не делается, чтобы не подделывать
// «изолированную ВМ» без реальной изоляции (запрещено правилами лота — не трогать реальный
// хост). Позитивная ветка покрыта по построению: resetLinux() вызывает tunDeleteFn/dnsRevertFn
// ТОЛЬКО внутри тела if — если бы вызов ушёл наружу условия (т.е. вернулся баг S-14), этот
// же тест немедленно становится красным (проверено вручную при разработке лота: временный
// откат на безусловный вызов валит именно этот тест — см. result.md).
func TestResetLinux_SeamsNotCalledWithoutHostguardAllow(t *testing.T) {
	if hostguard.Allowed() {
		t.Skip("hostguard снят через APF_ALLOW_HOST_MUTATION — тест неприменим в этом окружении")
	}

	origTun, origDNS := tunDeleteFn, dnsRevertFn
	origIptables, origIp6tables := iptablesRunFn, ip6tablesRunFn
	defer func() {
		tunDeleteFn, dnsRevertFn = origTun, origDNS
		iptablesRunFn, ip6tablesRunFn = origIptables, origIp6tables
	}()

	tunCalled, dnsCalled := false, false
	tunDeleteFn = func() error { tunCalled = true; return nil }
	dnsRevertFn = func() error { dnsCalled = true; return nil }
	// Нейтрализуем iptables-хуки — они не относятся к предмету этого теста (уже покрыты
	// killswitch_b0402_test.go / killswitch_branches_test.go), и оставляем чистым сигнал
	// именно о tunDeleteFn/dnsRevertFn.
	iptablesRunFn = func(...string) (string, error) { return "", nil }
	ip6tablesRunFn = func(...string) (string, error) { return "", nil }

	hostguard.ResetBlocked()
	defer hostguard.ResetBlocked()

	if err := resetLinux(); err != nil {
		t.Fatalf("resetLinux() неожиданная ошибка: %v", err)
	}

	if tunCalled {
		t.Error("tunDeleteFn был вызван БЕЗ hostguard.Allow — S-14 не исправлен")
	}
	if dnsCalled {
		t.Error("dnsRevertFn был вызван БЕЗ hostguard.Allow — S-14 не исправлен")
	}

	found := false
	for _, op := range hostguard.BlockedOps() {
		if op == "killswitch.resetLinux.tun+dns" {
			found = true
		}
	}
	if !found {
		t.Errorf("hostguard.BlockedOps() = %v, ожидалась запись о заблокированной resetLinux-мутации",
			hostguard.BlockedOps())
	}
}

// Регресс-предохранитель: resetLinux() не должен возвращать ошибку из-за самого факта, что
// hostguard заблокировал мутацию (best-effort семантика, как и раньше — resetLinux всегда
// возвращал nil).
func TestResetLinux_ReturnsNilEvenWhenHostguardBlocks(t *testing.T) {
	origTun, origDNS := tunDeleteFn, dnsRevertFn
	origIptables, origIp6tables := iptablesRunFn, ip6tablesRunFn
	defer func() {
		tunDeleteFn, dnsRevertFn = origTun, origDNS
		iptablesRunFn, ip6tablesRunFn = origIptables, origIp6tables
	}()
	tunDeleteFn = func() error { return nil }
	dnsRevertFn = func() error { return nil }
	iptablesRunFn = func(...string) (string, error) { return "", nil }
	ip6tablesRunFn = func(...string) (string, error) { return "", nil }

	if err := resetLinux(); err != nil {
		t.Errorf("resetLinux() = %v, want nil", err)
	}
}
