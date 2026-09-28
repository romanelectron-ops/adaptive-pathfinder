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
)

// Reachability — интерфейс проверки доступности «Выхода» снаружи (ТЗ §3, §5.2 шаг
// «Проверка»). Detect выполняет сетевые операции с заметной задержкой — вызывающая сторона
// обязана передавать ctx с таймаутом (ТЗ §11: мастер настройки не должен подвисать).
type Reachability interface {
	// Detect определяет путь автоматически: сначала проверяет, не виден ли этот адрес
	// снаружи уже напрямую (публичный IP без NAT), затем пробует UPnP-проброс порта на
	// обнаруженном в локальной сети роутере, и в последнюю очередь — STUN-запрос к
	// публичным серверам (только определение вероятного внешнего IP, без проброса порта:
	// пользователю всё равно придётся настроить проброс вручную).
	Detect(ctx context.Context, port int) (Method, error)
	// Explain переводит Method в готовую фразу для пользователя (ТЗ §3, §5.2) — без
	// сетевого жаргона вроде «CGNAT».
	Explain(m Method) string
	// ExternalAddress — итог последнего успешного Detect: адрес и порт, по которым «Вход»
	// реально сможет достучаться (или вероятный кандидат, если Method == MethodManualPort —
	// STUN-путь не гарантирует, что порт действительно проброшен). ok=false, если Detect
	// ещё не вызывался или ни один путь не дал результата.
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

// detectTimeout — общий бюджет на весь Detect (все пути внутри укладываются в него через
// ctx, переданный дальше). SSDP-обнаружение UPnP-устройств и STUN — сетевые операции с
// заметной задержкой, но мастер настройки (ТЗ §11) не должен зависать надолго.
const detectTimeout = 6 * time.Second

// Швы для тестов: настоящие UPnP/STUN бьют в реальную сеть (SSDP-широковещание, UDP к
// публичным серверам) — недопустимо и нежелательно под `go test` (тот же класс проблемы,
// что и hostguard у internal/engine, только не для sing-box, а для сетевого обнаружения).
var (
	upnpAddPortMappingFn = upnpAddPortMapping
	stunDetectFn         = stunDetect
	localIPCandidatesFn  = singbox.LocalIPCandidates
)

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

	candidates := localIPCandidatesFn()
	var internalIP string
	for _, c := range candidates {
		if net.ParseIP(c.IP) != nil {
			internalIP = c.IP
			break
		}
	}

	// Путь 1: устройство уже видно снаружи напрямую — редкий, но реальный случай (сервер с
	// настоящим публичным IP на интерфейсе, не за NAT вовсе). Проверяем: если хотя бы один
	// локальный адрес — НЕ приватный диапазон, дальше пробовать нечего.
	for _, c := range candidates {
		ip := net.ParseIP(c.IP)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if !netutil.IsPrivateIPv4(ip.To4()) {
			r.setResult(c.IP, port)
			return MethodDirect, nil
		}
	}

	// Путь 2: UPnP — автоматический проброс порта на обнаруженном в LAN роутере.
	if internalIP != "" {
		if extIP, err := upnpAddPortMappingFn(ctx, internalIP, port); err == nil {
			r.setResult(extIP, port)
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
	if ip, _, err := stunDetectFn(ctx); err == nil {
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
	return MethodManualPort, nil
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
	default:
		return fmt.Sprintf("внутренняя ошибка: неизвестный Method(%d)", int(m))
	}
}

var _ Reachability = (*realReachability)(nil)
