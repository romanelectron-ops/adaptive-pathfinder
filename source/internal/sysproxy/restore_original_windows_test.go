//go:build windows

package sysproxy

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// restore_original_windows_test.go — П1 (аудит 2026-09-01, security-раздел, находка №14):
// setHTTPProxy теперь сохраняет ProxyServer/ProxyEnable, БЫВШИЕ в реестре ДО первой правки
// APF, а disable() их восстанавливает вместо того, чтобы просто ставить ProxyEnable=0 и
// оставлять ProxyServer указывать на мёртвый адрес APF.

// fakeRegistryFull — как fakeRegistry, но с управляемыми regGetStringFn/regGetDWordFn (для
// сценария "у пользователя УЖЕ был настроен свой прокси до APF").
func fakeRegistryFull(getServer string, getServerErr error, getEnable uint32, getEnableErr error) (setCalls *[]string, restore func()) {
	origOpen, origStr, origDWord := regOpenKeyFn, regSetStringFn, regSetDWordFn
	origGetStr, origGetDWord := regGetStringFn, regGetDWordFn

	var calls []string
	regOpenKeyFn = func(_ registry.Key, _ string, _ uint32) (registry.Key, error) {
		return registry.Key(0), nil
	}
	regSetStringFn = func(_ registry.Key, name, value string) error {
		calls = append(calls, "SetString:"+name+"="+value)
		return nil
	}
	regSetDWordFn = func(_ registry.Key, name string, val uint32) error {
		calls = append(calls, "SetDWord:"+name+"="+itoa(val))
		return nil
	}
	regGetStringFn = func(_ registry.Key, _ string) (string, error) { return getServer, getServerErr }
	regGetDWordFn = func(_ registry.Key, _ string) (uint32, error) { return getEnable, getEnableErr }

	return &calls, func() {
		regOpenKeyFn, regSetStringFn, regSetDWordFn = origOpen, origStr, origDWord
		regGetStringFn, regGetDWordFn = origGetStr, origGetDWord
	}
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	return "1"
}

// setHTTPProxy с ранее настроенным пользовательским прокси в реестре обязан сохранить его в
// снимок "до APF", прежде чем перезаписать своими значениями.
func TestSetHTTPProxy_SavesOriginalBeforeOverwriting(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	_, restore := fakeRegistryFull("10.0.0.5:8080", nil, 1, nil)
	defer restore()

	if err := setHTTPProxy("127.0.0.1", 10809); err != nil {
		t.Fatalf("setHTTPProxy: %v", err)
	}

	enabled, server, ok := readOriginal()
	if !ok {
		t.Fatal("снимок 'до APF' не сохранён")
	}
	if !enabled || server != "10.0.0.5:8080" {
		t.Errorf("readOriginal() = (%v, %q), want (true, \"10.0.0.5:8080\") — "+
			"исходные настройки пользователя не сохранены верно", enabled, server)
	}
}

// Прокси у пользователя не был настроен вовсе (ErrNotExist) — снимок сохраняется как честное
// "выключено/пусто", а не пропускается вовсе.
func TestSetHTTPProxy_NoPriorProxy_SavesDisabledOriginal(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	_, restore := fakeRegistryFull("", registry.ErrNotExist, 0, registry.ErrNotExist)
	defer restore()

	if err := setHTTPProxy("127.0.0.1", 10809); err != nil {
		t.Fatalf("setHTTPProxy: %v", err)
	}

	enabled, server, ok := readOriginal()
	if !ok {
		t.Fatal("снимок 'до APF' не сохранён для случая 'прокси не настраивался'")
	}
	if enabled || server != "" {
		t.Errorf("readOriginal() = (%v, %q), want (false, \"\")", enabled, server)
	}
}

// Чтение ProxyServer провалилось НЕ из-за отсутствия значения (например, реестр временно
// недоступен) — снимок НЕ должен писаться пустым: это стёрло бы шанс когда-либо восстановить
// настоящие настройки пользователя, которые мы просто не смогли прочитать сейчас.
func TestSetHTTPProxy_ReadError_DoesNotSaveEmptyOriginal(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	_, restore := fakeRegistryFull("", errors.New("injected transient error"), 0, nil)
	defer restore()

	if err := setHTTPProxy("127.0.0.1", 10809); err != nil {
		t.Fatalf("setHTTPProxy: %v", err)
	}

	if _, _, ok := readOriginal(); ok {
		t.Error("снимок сохранён при ошибке чтения (не ErrNotExist) — " +
			"риск затереть настоящие настройки пользователя пустыми при следующем Disable")
	}
}

// disable() с сохранённым снимком восстанавливает И ProxyServer, И ProxyEnable — не только
// снимает флаг, как раньше.
func TestDisable_RestoresOriginalProxyServer(t *testing.T) {
	withTempMarker(t)
	path := withTempOriginalMarker(t)
	_ = path
	writeOriginalIfAbsent(true, "10.0.0.5:8080")

	calls, restore := fakeRegistryFull("", nil, 0, nil)
	defer restore()

	if err := disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}

	foundServer, foundEnable := false, false
	for _, c := range *calls {
		if c == "SetString:ProxyServer=10.0.0.5:8080" {
			foundServer = true
		}
		if c == "SetDWord:ProxyEnable=1" {
			foundEnable = true
		}
	}
	if !foundServer {
		t.Errorf("ProxyServer не восстановлен на исходное значение, calls=%v", *calls)
	}
	if !foundEnable {
		t.Errorf("ProxyEnable не восстановлен на исходное значение (1), calls=%v", *calls)
	}

	// Оба маркера потрачены.
	if _, _, ok := readMarker(); ok {
		t.Error("активный маркер не очищен после восстановления")
	}
	if _, _, ok := readOriginal(); ok {
		t.Error("снимок 'до APF' не очищен после восстановления")
	}
}

// disable() с сохранённым "выключенным" снимком (прокси не был настроен вовсе до APF)
// восстанавливает ProxyEnable=0 и ProxyServer="" — честно очищает след APF, а не оставляет
// мёртвый адрес.
func TestDisable_RestoresDisabledOriginal_ClearsServer(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	writeOriginalIfAbsent(false, "")

	calls, restore := fakeRegistryFull("", nil, 0, nil)
	defer restore()

	if err := disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}

	foundEmptyServer, foundDisable := false, false
	for _, c := range *calls {
		if c == "SetString:ProxyServer=" {
			foundEmptyServer = true
		}
		if c == "SetDWord:ProxyEnable=0" {
			foundDisable = true
		}
	}
	if !foundEmptyServer {
		t.Errorf("ProxyServer не очищен (мёртвый адрес APF мог остаться), calls=%v", *calls)
	}
	if !foundDisable {
		t.Errorf("ProxyEnable не выставлен в 0, calls=%v", *calls)
	}
}

// disable() БЕЗ снимка (например, отдельный вызов Disable без предшествующего SetHTTPProxy в
// этой сессии) откатывается на прежнее поведение — только ProxyEnable=0, ProxyServer не
// трогается вовсе. Строго не хуже, чем было до этой правки.
func TestDisable_NoSnapshot_FallsBackToEnableOnly(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t) // пусто — снимка нет

	calls, restore := fakeRegistryFull("", nil, 0, nil)
	defer restore()

	if err := disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}

	for _, c := range *calls {
		if len(c) >= 9 && c[:9] == "SetString" {
			t.Errorf("SetString вызван без снимка — ProxyServer не должен трогаться в fallback-пути: %v", *calls)
		}
	}
	found := false
	for _, c := range *calls {
		if c == "SetDWord:ProxyEnable=0" {
			found = true
		}
	}
	if !found {
		t.Errorf("ProxyEnable=0 не выставлен, calls=%v", *calls)
	}
}

// Полный цикл: SetHTTPProxy (сохраняет снимок) → Disable (восстанавливает) — тот же вызов,
// который будет происходить в реальном коде при подключении/отключении APF.
func TestSetHTTPProxy_ThenDisable_FullCycle_RestoresOriginal(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)

	// Шаг 1: у пользователя уже настроен свой прокси.
	_, restore1 := fakeRegistryFull("192.168.1.1:3128", nil, 1, nil)
	if err := setHTTPProxy("127.0.0.1", 10809); err != nil {
		restore1()
		t.Fatalf("setHTTPProxy: %v", err)
	}
	restore1()

	// Шаг 2: APF отключается — восстановление.
	calls, restore2 := fakeRegistryFull("", nil, 0, nil)
	defer restore2()
	if err := disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}

	foundServer := false
	for _, c := range *calls {
		if c == "SetString:ProxyServer=192.168.1.1:3128" {
			foundServer = true
		}
	}
	if !foundServer {
		t.Errorf("полный цикл не восстановил исходный прокси пользователя 192.168.1.1:3128, calls=%v", *calls)
	}
}
