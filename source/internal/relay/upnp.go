package relay

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
	"github.com/tailscale/goupnp/dcps/internetgateway2"
)

// upnpPortMappingClient — общий интерфейс трёх профилей UPnP IGD (Internet Gateway Device),
// которые реально встречаются у домашних роутеров: WANIPConnection2 (современный, IGD v2),
// WANIPConnection1 (IGD v1, всё ещё массово распространён), WANPPPConnection1 (роутеры с
// PPPoE-подключением, типично DSL). Сигнатуры методов у всех трёх идентичны (сгенерированы
// из одного и того же набора UPnP-действий разными профилями сервиса), поэтому один общий
// интерфейс покрывает все три без дублирования кода вызова.
type upnpPortMappingClient interface {
	AddPortMapping(ctx context.Context, remoteHost string, externalPort uint16, protocol string,
		internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	GetExternalIPAddress(ctx context.Context) (string, error)
	// DeletePortMapping — [консилиум, MEDIUM, находка №20, TZ_RELAY_HARDENING_2026-08-29.md
	// кластер F] интерфейс раньше вообще не имел метода удаления — снять проброс было
	// физически нечем, кроме как ждать истечения upnpLeaseSeconds.
	DeletePortMapping(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
}

// upnpLeaseSeconds — на сколько секунд просим роутер держать проброс. UPnP IGD допускает 0
// как «бессрочно», но часть прошивок трактует 0 как ошибку параметра, а не «навсегда» — берём
// заведомо безопасное большое конечное значение вместо рискованного 0.
//
// [консилиум, MEDIUM, находка №20, TZ_RELAY_HARDENING_2026-08-29.md кластер F] Было 24 часа —
// найдено консилиумом, что проброс никогда явно не снимался (ни при остановке роли, ни если
// пользователь только нажал «Определить автоматически», не запустив роль вовсе), поэтому
// висел бы до истечения этого срока целиком. Теперь есть RemoveUPnPMapping (вызывается из
// StopServerRole на обеих платформах, best-effort), поэтому полагаться на короткий срок как
// на единственную защиту уже не нужно — но час, а не сутки, всё равно разумный запас на
// случай, если процесс роли завершится аварийно (crash, kill -9) и unmap не успеет
// выполниться: блеск-радиус аварийного случая — час, не сутки. На практике многие роутеры
// продлевают действующий маппинг сами при повторном AddPortMapping с тем же (внешний порт,
// клиент, протокол), но гарантии от спецификации на это нет.
const upnpLeaseSeconds = 60 * 60

// discoverUPnPClients — по очереди пробует три профиля (см. upnpPortMappingClient), SSDP-
// обнаружение каждого ограничено переданным ctx. Возвращает клиентов ПЕРВОГО профиля, для
// которого нашлось хотя бы одно устройство в сети — реального роутера с несколькими
// одновременно активными профилями IGD не бывает, дальше пробовать нет смысла.
func discoverUPnPClients(ctx context.Context) ([]upnpPortMappingClient, error) {
	if clients, _, err := internetgateway2.NewWANIPConnection2Clients(ctx); err == nil && len(clients) > 0 {
		out := make([]upnpPortMappingClient, len(clients))
		for i, c := range clients {
			out[i] = c
		}
		return out, nil
	}
	if clients, _, err := internetgateway2.NewWANIPConnection1Clients(ctx); err == nil && len(clients) > 0 {
		out := make([]upnpPortMappingClient, len(clients))
		for i, c := range clients {
			out[i] = c
		}
		return out, nil
	}
	if clients, _, err := internetgateway2.NewWANPPPConnection1Clients(ctx); err == nil && len(clients) > 0 {
		out := make([]upnpPortMappingClient, len(clients))
		for i, c := range clients {
			out[i] = c
		}
		return out, nil
	}
	return nil, errors.New("upnp: ни одного IGD-устройства не найдено в локальной сети " +
		"(роутер не поддерживает UPnP, либо UPnP выключен в его настройках)")
}

// discoverUPnPClientsFn — шов для тестов (тот же приём, что upnpAddPortMappingFn/stunDetectFn в
// reachability.go): настоящий discoverUPnPClients бьёт в реальную сеть (SSDP-широковещание),
// недопустимо под `go test`. upnpAddPortMapping/RemoveUPnPMapping вызывают ЭТУ переменную, не
// функцию напрямую, чтобы тест мог подменить обнаружение на фиктивный клиент с управляемыми
// AddPortMapping/GetExternalIPAddress/DeletePortMapping.
var discoverUPnPClientsFn = discoverUPnPClients

// upnpAddPortMapping находит IGD-роутер на LAN и просит его перебросить internalPort с
// internalIP (это устройство) на такой же внешний порт TCP — роль «Выход» всегда слушает и
// снаружи, и внутри один и тот же номер порта, отдельного выбора внешнего порта не делаем
// (упрощает и ссылку для «Входа», и повторные вызовы этой функции идемпотентными).
//
//	Выход: внешний IP, под которым роутер виден из интернета (GetExternalIPAddress), при
//	       успешном AddPortMapping хотя бы у ОДНОГО обнаруженного клиента.
//	Fail-safe: ошибка первого клиента не считается фатальной, пока есть необойдённые —
//	           у сети может быть несколько IGD-совместимых устройств (редко, но бывает при
//	           двойном NAT/мостовом Wi-Fi расширителе со своим UPnP).
func upnpAddPortMapping(ctx context.Context, internalIP string, port int) (externalIP string, err error) {
	clients, derr := discoverUPnPClientsFn(ctx)
	if derr != nil {
		return "", derr
	}

	var lastErr error
	for _, c := range clients {
		mapErr := c.AddPortMapping(ctx, "", uint16(port), "TCP", uint16(port), internalIP,
			true, "APF Server Role", upnpLeaseSeconds)
		if mapErr != nil {
			lastErr = fmt.Errorf("AddPortMapping: %w", mapErr)
			continue
		}
		ip, ipErr := c.GetExternalIPAddress(ctx)
		if ipErr != nil || ip == "" {
			lastErr = fmt.Errorf("проброс порта прошёл, но не удалось узнать внешний IP: %w", ipErr)
			continue
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			lastErr = fmt.Errorf("проброс порта прошёл, но роутер вернул нераспознаваемый внешний IP %q", ip)
			continue
		}
		// [консилиум, HIGH, находка №12, TZ_RELAY_HARDENING_2026-08-29.md кластер F] Под CGNAT
		// AddPortMapping локально отрабатывает БЕЗ ошибки — но GetExternalIPAddress честно
		// возвращает СВОЙ (то есть тоже приватный/CGNAT) WAN-адрес роутера, потому что
		// настоящий NAT-слой находится ещё дальше, у оператора. Проброс, привязанный к такому
		// адресу, снаружи не виден вообще — не считаем это успехом UPnP, продолжаем как при
		// обычном отказе (следующий клиент, затем STUN-путь в Detect, который теперь умеет
		// распознать именно этот случай — см. reachability.go).
		if v4 := parsedIP.To4(); v4 != nil && netutil.IsPrivateIPv4(v4) {
			lastErr = fmt.Errorf("проброс порта прошёл, но внешний IP роутера (%s) сам приватный/CGNAT — "+
				"провайдер использует NAT ещё на своей стороне, проброс на этом роутере не поможет", ip)
			continue
		}
		return ip, nil
	}
	if lastErr == nil {
		lastErr = errors.New("upnp: не удалось получить результат ни от одного обнаруженного устройства")
	}
	return "", lastErr
}

// RemoveUPnPMapping — [консилиум, MEDIUM, находка №20] снимает проброс, заведённый
// upnpAddPortMapping для того же порта. Best-effort: отсутствие IGD-устройства или
// отсутствие самого маппинга (роутер уже забыл его, истёк срок, роутер перезагрузился) — не
// ошибка вызывающей стороны, только диагностика. Вызывать при остановке роли «Выход»
// независимо от того, каким путём была обнаружена доступность (StopServerRole не хранит,
// использовался ли UPnP — дешевле безусловно попробовать снять, чем нести это состояние через
// границу процессов Go↔Kotlin ради редкого пути очистки).
func RemoveUPnPMapping(ctx context.Context, port int) error {
	clients, derr := discoverUPnPClientsFn(ctx)
	if derr != nil {
		return derr
	}
	var lastErr error
	for _, c := range clients {
		if err := c.DeletePortMapping(ctx, "", uint16(port), "TCP"); err != nil {
			lastErr = fmt.Errorf("DeletePortMapping: %w", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("upnp: не удалось получить результат ни от одного обнаруженного устройства")
	}
	return lastErr
}
