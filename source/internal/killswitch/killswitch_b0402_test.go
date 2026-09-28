package killswitch

import (
	"fmt"
	"strings"
	"testing"
)

// ════════════════════════════════════════════════════════════════════════════
// B-04.2 — Linux Kill Switch на выделенной цепочке APF_KS.
// Фейковый «движок netfilter» учитывает цепочки и правила в памяти, чтобы
// проверять СЕМАНТИКУ (где живут правила, цел ли OUTPUT), а не строки команд.
// ════════════════════════════════════════════════════════════════════════════

// fakeNetfilter моделирует минимальный iptables: набор цепочек и упорядоченных
// правил в каждой. Поддерживает -N/-X/-F/-A/-I/-D/-C, нужные KS.
type fakeNetfilter struct {
	chains map[string][]string // имя цепочки → список правил (как одна строка спецификации)
}

func newFakeNetfilter() *fakeNetfilter {
	return &fakeNetfilter{chains: map[string][]string{
		"OUTPUT": {}, // встроенная цепочка существует всегда
	}}
}

// run исполняет одну iptables-команду над моделью. Возвращает (вывод, ошибка).
// Сигнатура совпадает с боевым хуком iptablesRunFn.
func (f *fakeNetfilter) run(args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("empty args")
	}
	op := args[0]
	switch op {
	case "-N": // создать цепочку
		ch := args[1]
		if _, ok := f.chains[ch]; ok {
			return "", fmt.Errorf("chain %s exists", ch) // как реальный iptables
		}
		f.chains[ch] = []string{}
		return "", nil
	case "-X": // удалить цепочку
		ch := args[1]
		if _, ok := f.chains[ch]; !ok {
			return "", fmt.Errorf("no chain %s", ch)
		}
		delete(f.chains, ch)
		return "", nil
	case "-F": // очистить цепочку
		ch := args[1]
		if _, ok := f.chains[ch]; !ok {
			return "", fmt.Errorf("no chain %s", ch)
		}
		f.chains[ch] = []string{}
		return "", nil
	case "-A": // добавить в конец
		ch := args[1]
		f.ensure(ch)
		f.chains[ch] = append(f.chains[ch], strings.Join(args[2:], " "))
		return "", nil
	case "-I": // вставить (поддержим "-I OUTPUT 1 …" и "-I CHAIN …")
		ch := args[1]
		f.ensure(ch)
		spec := args[2:]
		if len(spec) > 0 && spec[0] == "1" {
			spec = spec[1:]
		}
		f.chains[ch] = append([]string{strings.Join(spec, " ")}, f.chains[ch]...)
		return "", nil
	case "-D": // удалить совпадающее правило (одно вхождение)
		ch := args[1]
		spec := strings.Join(args[2:], " ")
		lst := f.chains[ch]
		for i, r := range lst {
			if r == spec {
				f.chains[ch] = append(append([]string{}, lst[:i]...), lst[i+1:]...)
				return "", nil
			}
		}
		return "", fmt.Errorf("rule not found") // как реальный -D при отсутствии
	case "-C": // проверка существования правила
		ch := args[1]
		spec := strings.Join(args[2:], " ")
		for _, r := range f.chains[ch] {
			if r == spec {
				return "", nil
			}
		}
		return "", fmt.Errorf("no such rule")
	}
	return "", fmt.Errorf("unsupported op %s", op)
}

func (f *fakeNetfilter) ensure(ch string) {
	if _, ok := f.chains[ch]; !ok {
		f.chains[ch] = []string{}
	}
}

// apfArtifacts — сколько объектов APF осталось в модели (цепочка + ссылки в OUTPUT).
func (f *fakeNetfilter) apfArtifacts() int {
	n := 0
	if _, ok := f.chains["APF_KS"]; ok {
		n++
	}
	for _, r := range f.chains["OUTPUT"] {
		if strings.Contains(r, "APF_KS") {
			n++
		}
	}
	return n
}

// installFake подменяет боевой хук iptablesRunFn на модель и возвращает restore.
func installFake(f *fakeNetfilter) func() {
	origV4 := iptablesRunFn
	origV6 := ip6tablesRunFn
	iptablesRunFn = f.run
	// IPv6 пишем в ту же модель, но в отдельные цепочки с префиксом v6: чтобы не мешать
	ip6tablesRunFn = func(args ...string) (string, error) { return "", nil } // v6 не критичен в этих тестах
	return func() { iptablesRunFn = origV4; ip6tablesRunFn = origV6 }
}

// ─── (1) Позитив ─────────────────────────────────────────────────────────────

func TestLinuxKS_Enable_UsesDedicatedChain(t *testing.T) {
	f := newFakeNetfilter()
	defer installFake(f)()

	ks := &linuxKS{}
	if err := ks.Enable("apf0", nil); err != nil {
		t.Fatalf("Enable error: %v", err)
	}
	// APF_KS создана и НЕ пуста
	if rules, ok := f.chains["APF_KS"]; !ok || len(rules) == 0 {
		t.Fatalf("APF_KS должна существовать и содержать правила, got ok=%v rules=%v", ok, f.chains["APF_KS"])
	}
	// В OUTPUT ровно один прыжок -j APF_KS и НЕТ DROP-правил напрямую
	jumps := 0
	for _, r := range f.chains["OUTPUT"] {
		if strings.Contains(r, "APF_KS") {
			jumps++
		}
		if strings.Contains(r, "-j DROP") {
			t.Errorf("в OUTPUT не должно быть прямого DROP, нашли: %q", r)
		}
	}
	if jumps != 1 {
		t.Errorf("в OUTPUT должен быть ровно 1 прыжок APF_KS, нашли %d", jumps)
	}
	// DROP должен жить ВНУТРИ APF_KS
	hasDrop := false
	for _, r := range f.chains["APF_KS"] {
		if strings.Contains(r, "-j DROP") {
			hasDrop = true
		}
	}
	if !hasDrop {
		t.Error("APF_KS должна содержать терминальный DROP")
	}
}

// ─── (2) Инвариант изоляции — ГЛАВНЫЙ фикс D3 ───────────────────────────────

func TestLinuxKS_DoesNotTouchForeignRules(t *testing.T) {
	f := newFakeNetfilter()
	// пользовательское/чужое правило в OUTPUT (docker/fail2ban и т.п.)
	foreign := "-p tcp --dport 22 -j ACCEPT"
	f.chains["OUTPUT"] = []string{foreign}
	defer installFake(f)()

	ks := &linuxKS{}
	_ = ks.Enable("apf0", nil)
	_ = ks.Disable()

	// чужое правило должно остаться, артефактов APF — ноль
	found := false
	for _, r := range f.chains["OUTPUT"] {
		if r == foreign {
			found = true
		}
	}
	if !found {
		t.Errorf("чужое правило OUTPUT уничтожено! OUTPUT=%v", f.chains["OUTPUT"])
	}
	if n := f.apfArtifacts(); n != 0 {
		t.Errorf("после Disable осталось %d артефактов APF, ожидалось 0", n)
	}
}

// ─── (3) Идемпотентность ─────────────────────────────────────────────────────

func TestLinuxKS_Enable_Idempotent_NoDuplicateJump(t *testing.T) {
	f := newFakeNetfilter()
	defer installFake(f)()

	ks := &linuxKS{}
	_ = ks.Enable("apf0", nil)
	_ = ks.Enable("apf0", nil) // повторно — не должно плодить прыжки

	jumps := 0
	for _, r := range f.chains["OUTPUT"] {
		if strings.Contains(r, "APF_KS") {
			jumps++
		}
	}
	if jumps != 1 {
		t.Errorf("после двойного Enable прыжков APF_KS=%d, ожидался 1", jumps)
	}
}

func TestLinuxKS_Disable_WithoutEnable_NoError(t *testing.T) {
	f := newFakeNetfilter()
	defer installFake(f)()
	ks := &linuxKS{}
	if err := ks.Disable(); err != nil {
		t.Errorf("Disable без Enable должен быть no-op без ошибки, got %v", err)
	}
	if f.apfArtifacts() != 0 {
		t.Error("Disable без Enable не должен создавать артефактов")
	}
}

// ─── (4) Стойкость: 100 циклов (инвариант TG-1) ─────────────────────────────

func TestLinuxKS_100Cycles_NoResidue(t *testing.T) {
	f := newFakeNetfilter()
	foreign := "-p tcp --dport 22 -j ACCEPT"
	f.chains["OUTPUT"] = []string{foreign}
	defer installFake(f)()

	ks := &linuxKS{}
	for i := 0; i < 100; i++ {
		if err := ks.Enable("apf0", nil); err != nil {
			t.Fatalf("цикл %d Enable: %v", i, err)
		}
		if err := ks.Disable(); err != nil {
			t.Fatalf("цикл %d Disable: %v", i, err)
		}
	}
	if n := f.apfArtifacts(); n != 0 {
		t.Errorf("после 100 циклов осталось %d артефактов APF", n)
	}
	if len(f.chains["OUTPUT"]) != 1 || f.chains["OUTPUT"][0] != foreign {
		t.Errorf("OUTPUT испорчен после 100 циклов: %v", f.chains["OUTPUT"])
	}
}

// ─── (5) Fail-safe: ошибка при наполнении APF_KS → откат, выключено ─────────

func TestLinuxKS_Enable_FailSafe_RollbackOnError(t *testing.T) {
	f := newFakeNetfilter()
	defer installFake(f)()

	// инжектируем сбой на добавлении правила в APF_KS (op "-A APF_KS …")
	realRun := f.run
	failOnce := true
	iptablesRunFn = func(args ...string) (string, error) {
		if failOnce && len(args) >= 2 && args[0] == "-A" && args[1] == "APF_KS" {
			failOnce = false
			return "", fmt.Errorf("injected netfilter failure")
		}
		return realRun(args...)
	}

	ks := &linuxKS{}
	err := ks.Enable("apf0", nil)
	if err == nil {
		t.Fatal("ожидалась ошибка Enable при сбое наполнения APF_KS")
	}
	if ks.IsEnabled() {
		t.Error("после сбоя состояние должно быть «выключено»")
	}
	if n := f.apfArtifacts(); n != 0 {
		t.Errorf("после fail-safe отката осталось %d артефактов APF", n)
	}
}
