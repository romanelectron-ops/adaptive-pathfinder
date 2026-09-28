package androidbridge

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Осторожность этого файла умышленная (см. tun_test.go — тот же принцип): ни один тест
// здесь не должен доходить до singbox.NewInProcessRunner/Start — hostguard НЕ прикрывает
// этот уровень (единственная точка входа под hostguard.Allow — engine.applySingBoxConfig,
// который тесты этого пакета никогда не вызывают напрямую). Проверяются только пути,
// возвращающиеся ДО касания t.inner/реального libbox — то же самое ограничение, которое
// уже соблюдает весь остальной tun_test.go.

type fakeTunFdCB struct{ fd int }

func (f fakeTunFdCB) RequestFd() int { return f.fd }

func TestSetTunFdCallback_RoundTrip(t *testing.T) {
	t.Cleanup(func() { SetTunFdCallback(nil) })

	if got := getTunFdCallback(); got != nil {
		t.Fatalf("getTunFdCallback() до установки = %v, ожидался nil", got)
	}

	cb := fakeTunFdCB{fd: 42}
	SetTunFdCallback(cb)

	got := getTunFdCallback()
	if got == nil {
		t.Fatal("getTunFdCallback() после SetTunFdCallback = nil")
	}
	if got.RequestFd() != 42 {
		t.Errorf("getTunFdCallback().RequestFd() = %d, ожидалось 42", got.RequestFd())
	}
}

func TestSwapHeldTunFd_ReplacesHolder(t *testing.T) {
	t.Cleanup(func() {
		tunMu.Lock()
		tunFdHolder = nil
		tunMu.Unlock()
	})

	tunMu.Lock()
	tunFdHolder = os.NewFile(uintptr(999999), "apf-tun-test-old")
	tunMu.Unlock()

	swapHeldTunFd(999998)

	tunMu.Lock()
	holder := tunFdHolder
	tunMu.Unlock()

	if holder == nil {
		t.Fatal("swapHeldTunFd не установил новый держатель")
	}
	if holder.Name() != "apf-tun" {
		t.Errorf("новый держатель Name() = %q, ожидалось \"apf-tun\" (см. swapHeldTunFd)", holder.Name())
	}
}

func TestSwapHeldTunFd_SafeWithoutPreviousHolder(t *testing.T) {
	t.Cleanup(func() {
		tunMu.Lock()
		tunFdHolder = nil
		tunMu.Unlock()
	})

	tunMu.Lock()
	tunFdHolder = nil
	tunMu.Unlock()

	swapHeldTunFd(999997) // не должно паниковать при отсутствии прежнего держателя

	if heldTunFdForTest() == nil {
		t.Fatal("swapHeldTunFd не установил держатель при пустом предыдущем состоянии")
	}
}

// ReloadWithFreshTun обязан отвергать невалидный fd от колбэка ДО того, как коснётся
// t.inner — здесь он намеренно nil, паника на этом пути была бы регрессией контракта.
func TestTunRunner_ReloadWithFreshTun_RejectsInvalidFdFromCallback(t *testing.T) {
	t.Cleanup(func() { SetTunFdCallback(nil) })

	for _, fd := range []int{0, -1} {
		SetTunFdCallback(fakeTunFdCB{fd: fd})
		tr := &tunRunner{}

		err := tr.ReloadWithFreshTun(context.Background(), nil)
		if err == nil {
			t.Fatalf("ReloadWithFreshTun() с fd=%d = nil, ожидался отказ", fd)
		}
		if !strings.Contains(err.Error(), "fd") {
			t.Errorf("ReloadWithFreshTun() с fd=%d = %v, ожидался текст про fd", fd, err)
		}
	}
}
