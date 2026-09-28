//go:build windows

// Package sysproxy управляет системным HTTP-прокси на уровне ОС.
// Windows: изменяет настройки через реестр HKCU Internet Settings.
package sysproxy

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
)

const inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// П1 (аудит 2026-09-01, security-раздел, находка №14): после изменения ProxyServer/
// ProxyEnable в реестре не рассылалось уведомление WinINET — уже запущенные клиенты могли
// не заметить ни включения APF-прокси (их трафик шёл бы МИМО туннеля, хотя UI показывает
// "Подключено" — класс утечки), ни выключения (продолжали бы биться в мёртвый прокси после
// Disable). InternetSetOptionW(NULL, ...) не трогает реестр и не требует прав — это
// чистое in-memory уведомление, безопасное вызывать безусловно (в т.ч. под `go test`,
// в отличие от netsh/реестра барьер hostguard здесь не нужен: нет персистентной мутации,
// которую он призван перехватывать).
var (
	wininetDLL             = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOptionW = wininetDLL.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39 // INTERNET_OPTION_SETTINGS_CHANGED
	internetOptionRefresh         = 37 // INTERNET_OPTION_REFRESH
)

// notifyWinINETSettingsChanged — best-effort: возвращаемое значение WinAPI не проверяется и
// не блокирует вызывающую операцию — реестр к этому моменту уже записан, эта функция лишь
// ускоряет момент, когда изменение увидят ДРУГИЕ уже запущенные процессы (без неё они бы
// заметили его на собственном следующем опросе реестра или при перезапуске — так по факту
// и происходило до этой правки).
var notifyWinINETSettingsChanged = func() {
	procInternetSetOptionW.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	procInternetSetOptionW.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

// Injection vars — swapped in tests to cover error branches.
var (
	regOpenKeyFn = func(base registry.Key, path string, access uint32) (registry.Key, error) {
		return registry.OpenKey(base, path, access)
	}
	// isWindowsServiceFn/consoleUserSIDFn — швы для targetHive (см. её комментарий). Отдельные
	// от regOpenKeyFn, потому что targetHive решает, В КАКОЙ куст идти, до первого обращения к
	// реестру, а не подменяет само обращение.
	isWindowsServiceFn = svc.IsWindowsService
	consoleUserSIDFn   = consoleUserSID
	regSetStringFn = func(k registry.Key, name, value string) error {
		return k.SetStringValue(name, value)
	}
	regSetDWordFn = func(k registry.Key, name string, val uint32) error {
		return k.SetDWordValue(name, val)
	}
	// regGetStringFn — читающий шов для RecoverStale (см. marker.go). ПРАВИЛО из
	// sysproxy_branches_test.go: раз страж обойдён в *_test.go, ВСЕ швы реестра обязаны
	// быть подменяемыми, не только используемые сегодняшним кодом.
	regGetStringFn = func(k registry.Key, name string) (string, error) {
		val, _, err := k.GetStringValue(name)
		return val, err
	}
	// regGetDWordFn — П1 (аудит 2026-09-01, находка №14): читающий шов для setHTTPProxy —
	// нужен читать ТЕКУЩЕЕ ProxyEnable ДО того, как APF его перезапишет (см. её комментарий).
	regGetDWordFn = func(k registry.Key, name string) (uint32, error) {
		val, _, err := k.GetIntegerValue(name)
		return uint32(val), err
	}
)

// targetHive решает, в какой куст реестра писать системный прокси.
//
//	Вход:      нет (читает состояние процесса — служба или нет).
//	Тело:      обычный GUI/CLI-процесс работает в сессии пользователя — HKCU резолвится верно,
//	           ничего не меняем. Процесс-служба (LocalSystem, P0.2 в
//	           docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md) под HKCU получает куст SYSTEM
//	           (S-1-5-18) — полностью изолированный от профиля реального пользователя: запись
//	           «успешна» (ошибки нет), а реальный браузер её не видит. Резолвим SID владельца
//	           активной консольной сессии и открываем его куст через HKEY_USERS напрямую — куст
//	           уже загружен, пока пользователь залогинен, олицетворение не требуется.
//	Выход:     (база, префикс пути, nil) — путь к ключу тогда prefix+inetKey; err != nil, если
//	           куст пользователя определить не удалось.
//	Fail-safe: нет активной консольной сессии ⇒ явная ошибка, а не тихая запись в чужой куст
//	           (до этого фикса setHTTPProxy/disable «успешно» писали в SYSTEM и молчали).
func targetHive() (base registry.Key, prefix string, err error) {
	isSvc, svcErr := isWindowsServiceFn()
	if svcErr != nil || !isSvc {
		return registry.CURRENT_USER, "", nil
	}
	sid, err := consoleUserSIDFn()
	if err != nil {
		return 0, "", fmt.Errorf("sysproxy: нет интерактивной сессии пользователя: %w", err)
	}
	return registry.USERS, sid + `\`, nil
}

// consoleUserSID — SID пользователя активной консольной сессии. Дублирует
// internal/killswitch/kspipe_auth_windows.go:consoleUserSID (тот же приём:
// WTSGetActiveConsoleSessionId + WTSQueryUserToken + GetTokenUser) — сознательно локальная копия,
// не общая зависимость, чтобы не связывать sysproxy и killswitch межпакетно ради ~15 строк.
// Требует SE_TCB_PRIVILEGE (есть у SYSTEM); при отсутствии активной консоли — явная ошибка.
func consoleUserSID() (string, error) {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		return "", fmt.Errorf("активной консольной сессии нет")
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sess, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// SetHTTPProxy устанавливает системный HTTP-прокси (host:port).
//
// ОПАСНАЯ ОПЕРАЦИЯ: направляет ВЕСЬ WinINET/WinHTTP-трафик машины на host:port. Если по этому
// адресу никто не слушает (sing-box не запущен / упал), у пользователя мгновенно «пропадает
// интернет» во всех приложениях, использующих системные настройки. Запись идёт в HKCU и НЕ требует
// прав администратора — поэтому обязателен барьер hostguard: под `go test` это no-op.
func SetHTTPProxy(host string, port int) error {
	if !hostguard.Allow("sysproxy.SetHTTPProxy") {
		return nil
	}
	return setHTTPProxy(host, port)
}

// setHTTPProxy — тело операции БЕЗ стража. Отдельная функция нужна, чтобы тесты error-веток
// могли проверить обработку ошибок реестра через инжектированные швы, не имея возможности
// обойти страж в боевом пути: экспортируемая обёртка всегда проходит через hostguard.
func setHTTPProxy(host string, port int) error {
	// Метка пишется ДО записи в реестр, не после (см. marker.go): если процесс упадёт
	// между этими двумя шагами, риск — ложная метка при НЕизменённом реестре, а
	// recoverStale() при следующем старте это отличит сам (текущий ProxyServer не
	// совпадёт с меткой) и просто её сотрёт, ничего не тронув. Обратный порядок был бы
	// опасен: крах СРАЗУ ПОСЛЕ реальной записи в реестр, но ДО метки, оставлял бы самый
	// опасный из двух возможных исходов — реестр изменён, а восстанавливать нечего.
	writeMarker(host, port)

	base, prefix, err := targetHive()
	if err != nil {
		return err
	}
	// P1 (аудит 2026-09-01, находка №14): QUERY_VALUE добавлен к SET_VALUE — нужен читать
	// ТЕКУЩИЕ ProxyServer/ProxyEnable ДО перезаписи (см. writeOriginalIfAbsent ниже). Раньше
	// этот путь был только на запись, и настройки пользователя (личный/корпоративный прокси)
	// нигде не сохранялись — Disable() умел только выключить ProxyEnable, но не мог вернуть
	// прежний ProxyServer, потому что никогда его не видел.
	k, err := regOpenKeyFn(base, prefix+inetKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open registry: %w", err)
	}
	defer k.Close()

	// Снимок «до APF» — best-effort и НЕ блокирует основную операцию.
	//
	// registry.ErrNotExist («значения ещё не было») — ЛЕГИТИМНОЕ «прокси никогда не
	// настраивался», сохраняем это честно как origEnabled=false/origServer="". Любая ДРУГАЯ
	// ошибка чтения — состояние пользователя нам НЕ известно, и снимок в этом случае лучше
	// не писать вовсе: записать пустые значения по ошибке значило бы, что Disable() позже
	// уверенно затрёт настоящий (просто не прочитанный сейчас) ProxyServer пользователя —
	// хуже, чем сегодняшнее поведение "оставить как есть".
	origEnabled, origServer, haveSnapshot := false, "", false
	switch s, errStr := regGetStringFn(k, "ProxyServer"); {
	case errStr == nil:
		origServer, haveSnapshot = s, true
		if d, errDWord := regGetDWordFn(k, "ProxyEnable"); errDWord == nil {
			origEnabled = d != 0
		}
	case errStr == registry.ErrNotExist:
		haveSnapshot = true // origEnabled=false, origServer="" — уже так по умолчанию
	}
	if haveSnapshot {
		writeOriginalIfAbsent(origEnabled, origServer)
	}

	proxy := fmt.Sprintf("%s:%d", host, port)
	if err := regSetStringFn(k, "ProxyServer", proxy); err != nil {
		return fmt.Errorf("sysproxy: set ProxyServer: %w", err)
	}
	if err := regSetDWordFn(k, "ProxyEnable", 1); err != nil {
		return fmt.Errorf("sysproxy: set ProxyEnable: %w", err)
	}
	notifyWinINETSettingsChanged()
	return nil
}

// Disable снимает системный HTTP-прокси.
//
// Барьер стоит и здесь: под `go test` реестр не трогаем вовсе (иначе тест «снятия» затирал бы
// НАСТОЯЩИЕ настройки прокси пользователя, который мог включить свой прокси сам).
func Disable() error {
	if !hostguard.Allow("sysproxy.Disable") {
		return nil
	}
	return disable()
}

// disable — тело операции БЕЗ стража (см. setHTTPProxy).
func disable() error {
	base, prefix, err := targetHive()
	if err != nil {
		return err
	}
	k, err := regOpenKeyFn(base, prefix+inetKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open registry: %w", err)
	}
	defer k.Close()

	// P1 (аудит 2026-09-01, находка №14): восстанавливаем ПРЕЖНИЙ ProxyServer/ProxyEnable,
	// если снимок "до APF" есть (см. writeOriginalIfAbsent в setHTTPProxy) — раньше здесь
	// стояло только ProxyEnable=0, а ProxyServer оставался указывать на мёртвый адрес APF:
	// пользователь с личным/корпоративным прокси после одного цикла подключения APF терял
	// свою настройку безвозвратно. Снимка может не быть (старая версия без него/файл
	// повреждён/Disable вызван без предшествующего SetHTTPProxy) — тогда честный откат на
	// прежнее поведение, строго не хуже, чем было до этой правки.
	if origEnabled, origServer, ok := readOriginal(); ok {
		if err := regSetStringFn(k, "ProxyServer", origServer); err != nil {
			return fmt.Errorf("sysproxy: restore ProxyServer: %w", err)
		}
		enableVal := uint32(0)
		if origEnabled {
			enableVal = 1
		}
		if err := regSetDWordFn(k, "ProxyEnable", enableVal); err != nil {
			return fmt.Errorf("sysproxy: restore ProxyEnable: %w", err)
		}
		clearOriginalMarker()
		clearMarker()
		notifyWinINETSettingsChanged()
		return nil
	}

	if err := regSetDWordFn(k, "ProxyEnable", 0); err != nil {
		return fmt.Errorf("sysproxy: disable proxy: %w", err)
	}
	clearMarker()
	notifyWinINETSettingsChanged()
	return nil
}

// RecoverStale — самолечение после нечистого завершения прошлой сессии (см. marker.go).
// Вызывается один раз при старте движка (engine.New), раньше любого действия
// пользователя. Барьер hostguard тот же, что у SetHTTPProxy/Disable — под `go test`
// гарантированный no-op (см. TestRecoverStale_BlockedByHostguard).
func RecoverStale() {
	if !hostguard.Allow("sysproxy.RecoverStale") {
		return
	}
	recoverStale()
}

// recoverStale — тело операции без стража (см. setHTTPProxy/disable). Метка сверяется с
// ТЕКУЩИМ значением ProxyServer в реестре: если пользователь сам успел перенастроить
// системный прокси на что-то другое в промежутке между сессиями APF, это уже не наше
// состояние — не трогаем.
//
// P0-6 (аудит 2026-09-01): метка стирается ТОЛЬКО там, где вопрос решён — «прокси наш и
// снят» либо «прокси чужой, нас не касается». На путях «не смогли проверить» она СОХРАНЯЕТСЯ.
//
// Раньше здесь стоял `defer clearMarker()` сразу после чтения метки, то есть она удалялась
// на любом раннем выходе. Самый вредный случай — служба apf-svc стартует до логина
// пользователя: targetHive() возвращает «нет интерактивной сессии», функция выходит, метка
// уничтожена. Комментарий тут же обещал повторную попытку «при следующем Engine.New()», но
// повторять было уже не по чему: пользователь логинился, в его HKCU оставался прокси на
// мёртвый порт, интернета нет, и самолечение больше не срабатывало никогда.
func recoverStale() {
	host, port, ok := readMarker()
	if !ok {
		return
	}

	base, prefix, err := targetHive()
	if err != nil {
		// Служба стартовала раньше, чем кто-либо залогинился (нет консольной сессии) —
		// восстанавливать пока нечего, а угадывать куст небезопасно. Метку НЕ трогаем:
		// RecoverStale() зовётся снова при следующем Engine.New() (например, при реальном
		// подключении пользователя), и тогда попытка повторится.
		return
	}
	k, err := regOpenKeyFn(base, prefix+inetKey, registry.QUERY_VALUE)
	if err != nil {
		// Реестр не открылся — состояние неизвестно, метку сохраняем.
		return
	}
	defer k.Close()
	current, err := regGetStringFn(k, "ProxyServer")
	if err != nil {
		// Значение не прочиталось — состояние неизвестно, метку сохраняем.
		return
	}
	if current != fmt.Sprintf("%s:%d", host, port) {
		// Прокси в реестре не наш (пользователь перенастроил сам либо уже почищено) —
		// вопрос решён, метка больше не нужна.
		clearMarker()
		return
	}
	_ = disable()
	// disable() сам вызывает clearMarker() при успехе; повторный вызов идемпотентен и
	// страхует случай, когда disable() отработал частично.
	clearMarker()
}
