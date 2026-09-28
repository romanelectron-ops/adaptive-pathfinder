// Package netguard — барьер ВЫХОДА В ИНТЕРНЕТ из тестовых прогонов.
//
// ЗАЧЕМ. internal/hostguard закрывает мутации состояния ОС, но ничего не говорит про сеть,
// и `go test ./internal/...` ходил наружу по-настоящему: качал каталоги узлов у четырёх
// сторонних поставщиков (наблюдалось 4830 узлов за прогон), тянул sing-box с GitHub,
// проверял здоровье через 1.1.1.1. Три следствия, и каждое портит испытание:
//
//   - время прогона зависит от сети, а не от кода;
//   - падение стороннего поставщика превращается в красный прогон, который выглядит как
//     дефект кода и заставляет искать его там, где его нет;
//   - рабочая машина ходит в интернет от имени тестов, и увидеть это неоткуда.
//
// ПРАВИЛО. Всякий исходящий сетевой вызов production-кода обязан идти через DialContext
// этого пакета. Под `go test` разрешается только петля (127.0.0.0/8, ::1, localhost) —
// на ней стоят httptest-серверы и локальный SOCKS самого APF. Всё остальное отвергается
// с внятной ошибкой и учитывается в счётчике.
//
// ПОЧЕМУ ПЕТЛЯ РАЗРЕШЕНА. Половина клиентов APF по замыслу ходит на 127.0.0.1: проверка
// здоровья через собственный SOCKS, watchdog, canary. Запретить петлю значило бы запретить
// тестировать сам продукт.
//
// ИНВАРИАНТ: `go test ./...` не открывает ни одного соединения за пределы петли.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// forceEnv — переменная окружения, снимающая барьер. Значение намеренно длинное и
// неудобное, чтобы его нельзя было выставить случайно.
//
// Законных сценариев два: ручная проверка живых поставщиков каталога и диагностика на
// изолированном стенде. В обычном прогоне барьер снимать нельзя — иначе он бесполезен.
const (
	forceEnv   = "APF_ALLOW_TEST_NETWORK"
	forceValue = "i-know-this-goes-to-the-internet"
)

var (
	mu           sync.Mutex
	blockedAddrs []string

	testMode   = detectTestBinary()
	overridden = os.Getenv(forceEnv) == forceValue
)

// detectTestBinary — по имени исполняемого файла, как в hostguard: надёжно уже на этапе
// init(), в отличие от flag.Lookup("test.v"), который тогда ещё не зарегистрирован.
func detectTestBinary() bool {
	a0 := strings.ToLower(os.Args[0])
	return strings.HasSuffix(a0, ".test") || strings.HasSuffix(a0, ".test.exe")
}

// UnderTest сообщает, что процесс запущен как тестовый бинарник.
func UnderTest() bool { return testMode }

// Overridden сообщает, что барьер снят переменной окружения.
func Overridden() bool { return overridden }

// Blocking сообщает, действует ли барьер прямо сейчас.
func Blocking() bool { return testMode && !overridden }

// IsLoopback отвечает, ведёт ли адрес на эту же машину.
//
// Разбирается ИМЕННО адрес вида "host:port", а не URL: сюда приходит то, что получает
// DialContext. Имя "localhost" проверяется отдельно — резолвить его через сеть на пути
// барьера было бы и медленно, и по кругу.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ErrBlocked — отказ барьера. Отдельный тип, чтобы тест мог отличить «сеть запрещена»
// от «сеть недоступна»: это разные диагнозы, и путать их нельзя.
type ErrBlocked struct{ Addr string }

func (e *ErrBlocked) Error() string {
	return fmt.Sprintf(
		"netguard: выход в интернет запрещён в тестовом прогоне (%s). "+
			"Поднимите httptest-сервер или задайте %s=%s для намеренно живого прогона",
		e.Addr, forceEnv, forceValue)
}

// Guard оборачивает функцию набора соединения барьером.
//
// Вход:  base — как соединение набиралось бы без барьера (свой таймаут, свой Dialer).
// Тело:  вне тестов — вызов base без изменений; под тестами — отказ на всё, кроме петли.
// Выход: соединение либо *ErrBlocked.
// Инвариант: барьер НЕ меняет поведение вне тестового бинарника ни в одном случае.
func Guard(base func(ctx context.Context, network, addr string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if base == nil {
		base = (&net.Dialer{Timeout: 30 * time.Second}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !Blocking() || IsLoopback(addr) {
			return base(ctx, network, addr)
		}
		mu.Lock()
		blockedAddrs = append(blockedAddrs, addr)
		mu.Unlock()
		return nil, &ErrBlocked{Addr: addr}
	}
}

// DialContext — набор соединения с барьером и настройками по умолчанию.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return Guard(nil)(ctx, network, addr)
}

// Transport возвращает клон http.DefaultTransport с барьером на наборе соединения.
//
// Именно клон, а не свежий &http.Transport{}: у DefaultTransport настроены пул соединений,
// таймауты и чтение прокси из окружения, и терять их ради барьера незачем.
func Transport() *http.Transport {
	var t *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		t = dt.Clone()
	} else {
		t = &http.Transport{}
	}
	t.DialContext = Guard(t.DialContext)
	return t
}

// Client — http.Client с таймаутом и барьером. Замена для `&http.Client{Timeout: …}`.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: Transport()}
}

// init закрывает http.DefaultTransport, а через него — http.DefaultClient, http.Get и
// всякий &http.Client{} без своего транспорта.
//
// Явные вызовы netguard.Client/Transport в production-коде остаются: они самодокументируют
// намерение и не зависят от того, попал ли этот пакет в сборку. Подмена здесь — страховка
// на случай пропущенной точки выхода, а не замена этим вызовам.
//
// Вне тестового бинарника не делает НИЧЕГО: продукт обязан ходить в сеть.
func init() {
	if !Blocking() {
		return
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		c := t.Clone()
		c.DialContext = Guard(t.DialContext)
		http.DefaultTransport = c
	}
}

// BlockedAddrs возвращает адреса, в которые прогон пытался пойти (для guard-тестов).
func BlockedAddrs() []string {
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), blockedAddrs...)
}

// BlockedCount возвращает число отвергнутых соединений.
func BlockedCount() int {
	mu.Lock()
	defer mu.Unlock()
	return len(blockedAddrs)
}

// ResetBlocked очищает счётчик (для тестов).
func ResetBlocked() {
	mu.Lock()
	blockedAddrs = nil
	mu.Unlock()
}
