// Package relay абстрагирует «как роль «Выход» становится видна роли «Вход»»
// (docs/TZ_APF_VHOD_VYHOD_v1.0.md §3, §10 Этап 0). Мастер настройки (ТЗ §5.2) не обязан
// знать, какой из трёх путей сработал (UPnP / ручной проброс порта / relay-посредник) —
// только результат и понятную пользователю фразу без сетевого жаргона.
package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// Method — какой путь доступности сработал (ТЗ §3).
type Method int

const (
	// MethodUnknown — ещё не проверено.
	MethodUnknown Method = iota
	// MethodDirect — устройство уже видно снаружи, ничего делать не нужно.
	MethodDirect
	// MethodUPnP — порт открыт автоматически через UPnP/NAT-PMP.
	MethodUPnP
	// MethodManualPort — нужен ручной проброс порта на роутере.
	MethodManualPort
	// MethodRelay — прямой путь физически недоступен (CGNAT и т.п.), нужен посредник.
	// [TZ_RELAY_HARDENING_2026-08-29.md кластер F] Detect возвращает это значение, когда
	// STUN-наблюдаемый внешний адрес сам оказывается приватным/CGNAT (двойной NAT — признак,
	// что проброс порта на домашнем роутере физически не поможет, находка №13).
	MethodRelay
	// MethodUndetermined — ни один путь (ни UPnP, ни STUN) не дал внешнего адреса.
	// Живой инцидент 2026-09-29: ноутбук выходил в интернет через раздачу с телефона (у неё нет
	// ни роутера, ни UPnP, а STUN на медленной раздаче не успевал в общий 6-секундный бюджет),
	// и Detect молча возвращал MethodManualPort — «нужен проброс порта на роутере», хотя
	// роутера у такой раздачи нет вовсе, а внешнего адреса Detect так и не узнал. Теперь это
	// отдельный честный исход «не удалось определить», без адреса (ExternalAddress().ok=false).
	// ЗНАЧЕНИЕ 5 — в конец iota-блока: значения 0..4 ждут UI и Android как числа
	// (gui/frontend/src/index.html, MainActivity.kt сравнивают method с 1/2/3), менять их нельзя.
	MethodUndetermined
)

// Reachability — интерфейс проверки доступности «Выхода» снаружи (ТЗ §3, §5.2 шаг
// «Проверка»). Detect выполняет сетевые операции с заметной задержкой — вызывающая сторона
// обязана передавать ctx с таймаутом (ТЗ §11: мастер настройки не должен подвисать).
type Reachability interface {
	// Detect определяет путь автоматически: сначала проверяет, не виден ли этот адрес
	// снаружи уже напрямую (публичный IP без NAT), затем ПАРАЛЛЕЛЬНО пробует UPnP-проброс
	// порта на обнаруженном в локальной сети роутере и STUN-запрос к публичным серверам
	// (только определение вероятного внешнего IP, без проброса порта: пользователю всё равно
	// придётся настроить проброс вручную). У каждого пути свой срок, приоритет результата:
	// Direct → UPnP → адрес из STUN. Если адреса нет ни от одного — MethodUndetermined.
	Detect(ctx context.Context, port int) (Method, error)
	// Explain переводит Method в готовую фразу для пользователя (ТЗ §3, §5.2) — без
	// сетевого жаргона (единственное исключение — MethodUndetermined: там «CGNAT» назван
	// в скобках как раз затем, чтобы человек с раздачей от оператора узнал свой случай).
	Explain(m Method) string
	// ExternalAddress — итог последнего успешного Detect: адрес и порт, по которым «Вход»
	// реально сможет достучаться (или вероятный кандидат, если Method == MethodManualPort —
	// STUN-путь не гарантирует, что порт действительно проброшен). ok=false, если Detect
	// ещё не вызывался или ни один путь не дал результата (в т.ч. MethodUndetermined).
	ExternalAddress() (host string, port int, ok bool)
}

// realReachability — реализация поверх UPnP (internal/relay/upnp.go, github.com/tailscale/
// goupnp — уже был в дереве как зависимость sing-tun, отдельно ничего не добавляли) и
// минимального STUN-клиента (internal/relay/stun.go, RFC 5389, без внешних зависимостей).
type realReachability struct {
	mu      sync.Mutex
	extHost string
	extPort int
	have    bool
}

// NewReachability возвращает рабочую реализацию Reachability.
func NewReachability() Reachability { return &realReachability{} }

// Сроки Detect. Раньше UPnP и STUN шли ПОСЛЕДОВАТЕЛЬНО и делили один бюджет в 6 с: на
// медленной раздаче (живой инцидент 2026-09-29, ноутбук за телефоном-хотспотом) SSDP-поиск UPnP
// съедал почти весь бюджет вхолостую, STUN не успевал ответить, и Detect молча возвращал
// «нужен проброс порта на роутере» без адреса. Теперь пути идут параллельно и у каждого свой
// срок — зависший UPnP не отнимает время у STUN и наоборот.
//
// detectTimeout — общий потолок на весь Detect (защита на случай, если чья-то функция не
// смотрит на свой ctx); он больше каждого из сроков и меньше 10 секунд, которые дают Detect
// вызывающие стороны (gui/app.go, mobile/androidbridge) и Kotlin/JS-подписи «до 10с».
//
// Это переменные, а не константы, — по той же причине, что и швы ниже: тесту нужно сжать сроки
// до миллисекунд, не ожидая реальных секунд.
var (
	detectTimeout = 8 * time.Second
	upnpTimeout   = 5 * time.Second
	stunTimeout   = 5 * time.Second
)

// Швы для тестов: настоящие UPnP/STUN бьют в реальную сеть (SSDP-широковещание, UDP к
// публичным серверам) — недопустимо и нежелательно под `go test` (тот же класс проблемы,
// что и hostguard у internal/engine, только не для sing-box, а для сетевого обнаружения).
var (
	upnpAddPortMappingFn = upnpAddPortMapping
	stunDetectFn         = stunDetect
	localIPCandidatesFn  = singbox.LocalIPCandidates
)

// usableCandidateIPv4 возвращает IPv4 кандидата, если ему можно доверять как настоящему адресу
// этого устройства, и nil — если нет. Не годятся: не-IPv4 (UPnP IGD принимает внутренний IPv4),
// 0.0.0.0, link-local 169.254/16 (адрес «DHCP не ответил» — раньше он, будучи «не приватным»,
// принимался за публичный и давал ложный MethodDirect) и адрес виртуального адаптера
// (Hyper-V/WSL/VMware/Docker/туннель — его не видно из сети, к которой подключено устройство).
// LocalIPCandidates сама ставит такие адреса в конец списка, но Detect не полагается на это:
// в списке может остаться ТОЛЬКО виртуальный адрес — тогда брать его нельзя вовсе.
// Исключение — адрес интерфейса маршрута по умолчанию (IsDefaultRoute): если система выходит в
// сеть именно через виртуальный адаптер (внешний виртуальный коммутатор Hyper-V,
// «vEthernet (External)»), этот адрес и есть адрес устройства в его сети; без исключения Detect не
// нашёл бы на таком хосте ни одного «пригодного» адреса и не пробовал бы UPnP (ревью 2026-09-30).
func usableCandidateIPv4(c singbox.LocalIPCandidate) net.IP {
	ip := net.ParseIP(c.IP)
	if ip == nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil || v4.IsUnspecified() || singbox.IsLinkLocalIPv4(v4) ||
		(!c.IsDefaultRoute && singbox.IsVirtualInterfaceName(c.InterfaceName)) {
		return nil
	}
	return v4
}

// awaitResult ждёт значение из ch до окончания ctx. По истечении срока делает ещё одну
// неблокирующую проверку: ответ, пришедший одновременно со сроком, не теряется (select при
// двух готовых ветках выбирает случайную).
func awaitResult[T any](ctx context.Context, ch <-chan T) (T, bool) {
	select {
	case v := <-ch:
		return v, true
	case <-ctx.Done():
		select {
		case v := <-ch:
			return v, true
		default:
			var zero T
			return zero, false
		}
	}
}

// [консилиум, HIGH, находка №10, TZ_RELAY_HARDENING_2026-08-29.md кластер D] UPnP- и
// STUN-зонды внутри Detect на Android НЕ оборачиваются в protect() — сознательно, по итогам
// той же живой проверки 2026-08-30 на Redmi (<test-phone>), что и у ExitClient (см. комментарий
// у типа ExitClient в tunnel_exit_client.go): «Определить автоматически» была нажата при
// полностью активной роли «Вход» (TUN) на том же устройстве, STUN получил реальный внешний
// IP провайдера (не адрес TUN-интерфейса, не таймаут) — addDisallowedApplication(packageName)
// в APFVpnService.kt исключает по UID весь пакет APF из маршрутизации через собственный TUN,
// это покрывает и эти сокеты тоже.
func (r *realReachability) Detect(ctx context.Context, port int) (Method, error) {
	ctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()

	// Внутренний адрес для UPnP — первый пригодный кандидат: LocalIPCandidates теперь ставит
	// впереди адрес интерфейса маршрута по умолчанию, а виртуальные адаптеры — в конец (живой
	// инцидент 2026-09-29: раньше первым шёл адрес вида 172.x.x.1, виртуальный коммутатор Hyper-V, и
	// роутеру предлагали пробросить порт на адрес, которого в его сети нет). Виртуальные и
	// link-local адреса не берём вовсе (см. usableCandidateIPv4).
	candidates := localIPCandidatesFn()
	var internalIP string
	for _, c := range candidates {
		if v4 := usableCandidateIPv4(c); v4 != nil {
			internalIP = v4.String()
			break
		}
	}

	// Путь 1: устройство уже видно снаружи напрямую — редкий, но реальный случай (сервер с
	// настоящим публичным IP на интерфейсе, не за NAT вовсе). Проверяем: если хотя бы один
	// (настоящий, не виртуальный и не link-local) локальный адрес — НЕ приватный диапазон,
	// дальше пробовать нечего.
	for _, c := range candidates {
		v4 := usableCandidateIPv4(c)
		if v4 == nil {
			continue
		}
		if !netutil.IsPrivateIPv4(v4) {
			r.setResult(c.IP, port)
			return MethodDirect, nil
		}
	}

	// Пути 2 и 3 идут ПАРАЛЛЕЛЬНО, каждый со своим сроком (см. комментарий у detectTimeout).
	// Функции-швы читаем в локальные переменные ДО запуска горутин: горутина может ещё работать
	// после возврата Detect (функция, игнорирующая ctx), и чтение пакетной переменной из неё
	// гонялось бы с подменой шва в тесте.
	upnpFn, stunFn := upnpAddPortMappingFn, stunDetectFn

	type upnpResult struct {
		extIP string
		err   error
	}
	type stunResult struct {
		ip  net.IP
		err error
	}

	upnpCtx, cancelUPnP := context.WithTimeout(ctx, upnpTimeout)
	defer cancelUPnP()
	stunCtx, cancelSTUN := context.WithTimeout(ctx, stunTimeout)
	defer cancelSTUN()

	// Буфер 1: горутина, доработавшая после того как Detect уже вернулся, не блокируется на
	// отправке (утечка была бы вечной).
	var upnpCh chan upnpResult
	if internalIP != "" {
		upnpCh = make(chan upnpResult, 1)
		go func() {
			extIP, err := upnpFn(upnpCtx, internalIP, port)
			upnpCh <- upnpResult{extIP, err}
		}()
	}
	stunCh := make(chan stunResult, 1)
	go func() {
		ip, _, err := stunFn(stunCtx)
		stunCh <- stunResult{ip, err}
	}()

	// Путь 2: UPnP — автоматический проброс порта на обнаруженном в LAN роутере. Приоритетнее
	// STUN (порт реально открыт, а не «вероятный адрес»), поэтому ждём его результата ПЕРВЫМ —
	// но не дольше его собственного срока; STUN за это время работает сам по себе.
	if upnpCh != nil {
		if res, ok := awaitResult(upnpCtx, upnpCh); ok && res.err == nil && res.extIP != "" {
			r.setResult(res.extIP, port)
			return MethodUPnP, nil
		}
	}

	// Путь 3: STUN — только определение вероятного внешнего IP, БЕЗ автоматического
	// проброса (см. комментарий у stunDetect в stun.go).
	//
	// Аудит 2026-09-01 (раздел D, тест-закрепитель дефекта reachability_test.go). Раньше
	// здесь сохранялся stunPort — внешний UDP-порт, который STUN-сервер увидел для ЭТОГО
	// эфемерного зондирующего сокета. Он не имеет отношения к порту, который пользователь
	// пробрасывает: это порт, который слушает служба «Выход» (тот самый `port`, переданный
	// в Detect) — TCP, отдельный сокет, и для большинства NAT (тем более symmetric) внешнее
	// отображение эфемерного UDP-порта не предсказывает отображение другого порта/протокола
	// вообще никак. Мастер настройки показывал пользователю "пробросьте порт 55123" вместо
	// реального порта его сервиса — инструкция, следуя которой ничего не заработало бы.
	if res, ok := awaitResult(stunCtx, stunCh); ok && res.err == nil && res.ip != nil {
		ip := res.ip
		r.setResult(ip.String(), port)
		// [консилиум, HIGH, находка №13, TZ_RELAY_HARDENING_2026-08-29.md кластер F] STUN сам
		// по себе не различает типы NAT — но если внешний (по мнению STUN) адрес САМ
		// приватный/CGNAT, это самодостаточный признак двойного NAT: домашний роутер думает,
		// что его "внешний" адрес — это внутренний адрес сети оператора. Проброс порта на
		// ЭТОМ роутере физически не может сработать, сколько ни настраивай — настоящий
		// NAT-слой находится у оператора, вне досягаемости пользователя. Раньше Detect в этом
		// случае всё равно советовал MethodManualPort — невыполнимый совет ровно для того
		// случая (CGNAT), ради которого relay и был сделан (инцидент 2026-08-28). Если
		// STUN-адрес публичный — совет "пробросьте порт" остаётся выполнимым, обычный NAT.
		if v4 := ip.To4(); v4 != nil && netutil.IsPrivateIPv4(v4) {
			return MethodRelay, nil
		}
		return MethodManualPort, nil
	}

	// Ни один путь не дал результата — не выдумываем внешний адрес, честно возвращаем
	// «не определено», не ошибку (Detect по контракту не паникует и не считает это
	// исключительной ситуацией — обычная сеть без UPnP и с STUN, недоступным именно отсюда).
	// Раньше здесь возвращался MethodManualPort — «пробросьте порт на роутере», хотя ни адреса,
	// ни самого роутера мы не видели (раздача с телефона/CGNAT: роутера у пользователя нет, и
	// совет невыполним). Теперь — MethodUndetermined, а Explain объясняет оба случая.
	return MethodUndetermined, nil
}

func (r *realReachability) setResult(host string, port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extHost, r.extPort, r.have = host, port, true
}

func (r *realReachability) ExternalAddress() (string, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.extHost, r.extPort, r.have
}

// Explain — находка консилиума 2026-08-10 (medium): раньше MethodUnknown (легитимное
// «ещё не проверено») и любое невалидное значение Method (программная ошибка — например,
// будущая константа, добавленная в Detect, но забытая здесь) падали в один и тот же
// default и выглядели для пользователя одинаково. Явный case для MethodUnknown отделяет
// «нормальное ожидание» от «непредвиденное значение» — фраза default теперь узнаваема как
// диагностика, а не как обычный статус, не нарушая общий контракт (Explain остаётся
// тотальной функцией без паники — вызывается из UI-потока мастера настройки).
func (*realReachability) Explain(m Method) string {
	switch m {
	case MethodUnknown:
		return "Пока не проверено"
	case MethodDirect:
		return "Ваше устройство видно из интернета напрямую — отлично"
	case MethodUPnP:
		return "Порт открыт автоматически — всё готово"
	case MethodManualPort:
		return "Нужен проброс порта на роутере — вот как"
	case MethodRelay:
		return "Ваш способ подключения к интернету не позволяет принимать соединения напрямую — понадобится посредник"
	case MethodUndetermined:
		return "Не удалось определить внешний адрес автоматически. Если этот компьютер выходит в интернет через " +
			"раздачу с другого телефона или у оператора общий адрес (CGNAT), проброс порта невозможен — нужен " +
			"relay-посредник; если вы за домашним роутером — пробросьте порт вручную (инструкция ниже)."
	default:
		return fmt.Sprintf("внутренняя ошибка: неизвестный Method(%d)", int(m))
	}
}

var _ Reachability = (*realReachability)(nil)
