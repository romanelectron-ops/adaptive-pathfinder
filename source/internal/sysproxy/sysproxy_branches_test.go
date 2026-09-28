//go:build windows

package sysproxy

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// Тесты error-веток вызывают НЕэкспортируемые setHTTPProxy/disable — тело операции без стража
// hostguard. Экспортируемые SetHTTPProxy/Disable проверяются в hostguard_windows_test.go как no-op.
//
// ПРАВИЛО (следствие реального инцидента): раз страж обойдён, ВСЕ швы реестра обязаны быть
// подменены, а не только проверяемый. Прежняя версия подменяла лишь regSetDWordFn — и настоящий
// regSetStringFn писал ProxyServer=127.0.0.1:1080 в HKCU хоста. Мутацию поймал TestMain-щит.

// fakeRegistry подменяет ВСЕ швы реестра no-op заглушками и возвращает функцию отката.
// failOpen/failString/failDWord задают, какой шов должен вернуть ошибку (nil = успех).
//
// П1 (аудит 2026-09-01, находка №14): setHTTPProxy теперь ЧИТАЕТ ProxyServer/ProxyEnable
// (regGetStringFn/regGetDWordFn) ДО их перезаписи — оба шва тоже обязаны быть подменены
// (то же ПРАВИЛО, что и в комментарии выше). Дефолт — registry.ErrNotExist: то же самое,
// что легитимное "прокси у пользователя ещё не настраивался", безопасно для всех
// существующих тестов ниже, которым read-путь не важен.
func fakeRegistry(failOpen, failString, failDWord error) func() {
	origOpen, origStr, origDWord := regOpenKeyFn, regSetStringFn, regSetDWordFn
	origGetStr, origGetDWord := regGetStringFn, regGetDWordFn

	regOpenKeyFn = func(_ registry.Key, _ string, _ uint32) (registry.Key, error) {
		// registry.Key(0) — невалидный хэндл: даже если тело попробует что-то с ним сделать
		// в обход подменённых швов, обращения к настоящему разделу реестра не будет.
		return registry.Key(0), failOpen
	}
	regSetStringFn = func(_ registry.Key, _, _ string) error { return failString }
	regSetDWordFn = func(_ registry.Key, _ string, _ uint32) error { return failDWord }
	regGetStringFn = func(_ registry.Key, _ string) (string, error) { return "", registry.ErrNotExist }
	regGetDWordFn = func(_ registry.Key, _ string) (uint32, error) { return 0, registry.ErrNotExist }

	return func() {
		regOpenKeyFn, regSetStringFn, regSetDWordFn = origOpen, origStr, origDWord
		regGetStringFn, regGetDWordFn = origGetStr, origGetDWord
	}
}

// ── SetHTTPProxy error branches ───────────────────────────────────────────────
//
// П1 (аудит 2026-09-01, находка №14): withTempMarker/withTempOriginalMarker добавлены во ВСЕ
// тесты этого блока — раньше ни setHTTPProxy, ни disable не читали второй маркер вовсе, и
// путь по умолчанию не имел значения; теперь оба читаются/пишутся в теле, и тесты обязаны
// быть герметичны, а не полагаться на то, что файла на машине, где идёт `go test`,
// вероятно нет (то же правило, которое уже действует для markerPathFn в остальном пакете).

func TestSetHTTPProxy_OpenKeyError(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	defer fakeRegistry(errors.New("injected open error"), nil, nil)()

	if err := setHTTPProxy("127.0.0.1", 1080); err == nil {
		t.Error("expected error from injected OpenKey failure")
	}
}

func TestSetHTTPProxy_SetStringError(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	defer fakeRegistry(nil, errors.New("injected SetString error"), nil)()

	if err := setHTTPProxy("127.0.0.1", 1080); err == nil {
		t.Error("expected error from injected SetStringValue failure")
	}
}

func TestSetHTTPProxy_SetDWordError(t *testing.T) {
	// SetString успешен (заглушка), падаем на первом DWord (ProxyEnable=1).
	withTempMarker(t)
	withTempOriginalMarker(t)
	defer fakeRegistry(nil, nil, errors.New("injected SetDWord error"))()

	if err := setHTTPProxy("127.0.0.1", 1080); err == nil {
		t.Error("expected error from injected SetDWordValue failure")
	}
}

// Позитив: все швы успешны → тело отрабатывает без ошибки (и всё ещё ничего не пишет в реестр).
func TestSetHTTPProxy_BodySuccess(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	defer fakeRegistry(nil, nil, nil)()

	if err := setHTTPProxy("127.0.0.1", 1080); err != nil {
		t.Errorf("unexpected error on success path: %v", err)
	}
}

// ── Disable error branches ────────────────────────────────────────────────────

func TestDisable_OpenKeyError(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	defer fakeRegistry(errors.New("injected open error"), nil, nil)()

	if err := disable(); err == nil {
		t.Error("expected error from injected OpenKey failure")
	}
}

func TestDisable_SetDWordError(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t) // пусто → нет снимка → идём в fallback-ветку disable(), которая и падает на SetDWord
	defer fakeRegistry(nil, nil, errors.New("injected SetDWord error"))()

	if err := disable(); err == nil {
		t.Error("expected error from injected SetDWordValue failure")
	}
}

func TestDisable_BodySuccess(t *testing.T) {
	withTempMarker(t)
	withTempOriginalMarker(t)
	defer fakeRegistry(nil, nil, nil)()

	if err := disable(); err != nil {
		t.Errorf("unexpected error on success path: %v", err)
	}
}

// ── recoverStale (задача найдена живым инцидентом 2026-08-13, см. marker.go) ──────

// fakeRegistryWithGet — как fakeRegistry, но добавляет управляемый regGetStringFn
// (нужен recoverStale, которого не было на момент, когда писался fakeRegistry).
// getValue/getErr — что вернуть на чтение ProxyServer; openErr — на открытие ключа.
func fakeRegistryWithGet(openErr error, getValue string, getErr error) func() {
	origOpen, origGet := regOpenKeyFn, regGetStringFn
	regOpenKeyFn = func(_ registry.Key, _ string, _ uint32) (registry.Key, error) {
		return registry.Key(0), openErr
	}
	regGetStringFn = func(_ registry.Key, _ string) (string, error) {
		return getValue, getErr
	}
	return func() { regOpenKeyFn, regGetStringFn = origOpen, origGet }
}

func withTempMarkerFile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + `\sysproxy_active.marker`
	origPath := markerPathFn
	markerPathFn = func() string { return path }
	t.Cleanup(func() { markerPathFn = origPath })
	return path
}

func TestRecoverStale_NoMarker_DoesNotTouchRegistry(t *testing.T) {
	withTempMarkerFile(t)
	withTempOriginalMarker(t)
	openCalled := false
	origOpen := regOpenKeyFn
	regOpenKeyFn = func(_ registry.Key, _ string, _ uint32) (registry.Key, error) {
		openCalled = true
		return registry.Key(0), errors.New("should not be called")
	}
	defer func() { regOpenKeyFn = origOpen }()

	recoverStale()

	if openCalled {
		t.Error("recoverStale() touched the registry despite no marker existing")
	}
}

func TestRecoverStale_MatchingMarker_Disables(t *testing.T) {
	withTempMarkerFile(t)
	withTempOriginalMarker(t)
	writeMarker("127.0.0.1", 10809)

	var dwordCalls []string
	defer fakeRegistryWithGet(nil, "127.0.0.1:10809", nil)()
	origSetDWord := regSetDWordFn
	regSetDWordFn = func(_ registry.Key, name string, val uint32) error {
		dwordCalls = append(dwordCalls, name)
		if name == "ProxyEnable" && val != 0 {
			t.Errorf("recoverStale disable path set ProxyEnable=%d, want 0", val)
		}
		return nil
	}
	defer func() { regSetDWordFn = origSetDWord }()

	recoverStale()

	if len(dwordCalls) == 0 {
		t.Error("recoverStale() did not call disable() when the marker matched the registry")
	}
	if _, _, ok := readMarker(); ok {
		t.Error("marker still present after recoverStale() handled it")
	}
}

func TestRecoverStale_NonMatchingMarker_LeavesRegistryAlone(t *testing.T) {
	withTempMarkerFile(t)
	withTempOriginalMarker(t)
	writeMarker("127.0.0.1", 10809)

	// Реестр сейчас указывает на СОВСЕМ ДРУГОЙ прокси — пользователь мог сам его
	// перенастроить между сессиями APF. recoverStale не имеет права это трогать.
	dwordCalled := false
	defer fakeRegistryWithGet(nil, "10.0.0.1:3128", nil)()
	origSetDWord := regSetDWordFn
	regSetDWordFn = func(_ registry.Key, _ string, _ uint32) error {
		dwordCalled = true
		return nil
	}
	defer func() { regSetDWordFn = origSetDWord }()

	recoverStale()

	if dwordCalled {
		t.Error("recoverStale() called disable() even though the registry no longer matched the marker")
	}
	// Метка всё равно устаревшая — стирается независимо от исхода сравнения.
	if _, _, ok := readMarker(); ok {
		t.Error("stale non-matching marker was not cleared")
	}
}

// P0-6 (аудит 2026-09-01): тест ИНВЕРТИРОВАН.
//
// Раньше он назывался ..._ClearsMarkerAndReturns и требовал, чтобы метка стиралась при
// ошибке открытия реестра — то есть закреплял дефект как ожидаемое поведение. Метка —
// единственный признак «системный прокси остался от APF»; стереть её, НЕ проверив реестр,
// значит навсегда лишить самолечение возможности сработать. Именно так пользователь и
// оставался без интернета: служба стартовала до логина, реестр был недоступен, метка
// уничтожалась, и следующий запуск уже не знал, что чинить.
func TestRecoverStale_OpenKeyError_KeepsMarkerForRetry(t *testing.T) {
	withTempMarkerFile(t)
	withTempOriginalMarker(t)
	writeMarker("127.0.0.1", 10809)
	defer fakeRegistryWithGet(errors.New("injected open error"), "", nil)()

	recoverStale() // не должно паниковать

	if _, _, ok := readMarker(); !ok {
		t.Error("P0-6: метка стёрта при недоступном реестре — состояние прокси не проверено, " +
			"а признак для повторной попытки уничтожен (самолечение больше не сработает)")
	}
}

func TestRecoverStale_GetStringError_LeavesRegistryAlone(t *testing.T) {
	withTempMarkerFile(t)
	withTempOriginalMarker(t)
	writeMarker("127.0.0.1", 10809)

	dwordCalled := false
	defer fakeRegistryWithGet(nil, "", errors.New("injected get error"))()
	origSetDWord := regSetDWordFn
	regSetDWordFn = func(_ registry.Key, _ string, _ uint32) error {
		dwordCalled = true
		return nil
	}
	defer func() { regSetDWordFn = origSetDWord }()

	recoverStale()

	if dwordCalled {
		t.Error("recoverStale() called disable() despite a ProxyServer read error")
	}
	// P0-6: состояние прокси осталось непроверенным — метка обязана пережить попытку,
	// чтобы самолечение повторилось при следующем запуске.
	if _, _, ok := readMarker(); !ok {
		t.Error("P0-6: метка стёрта при непрочитанном ProxyServer — повторить попытку уже нечем")
	}
}
