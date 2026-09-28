package relay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// stunMagicCookie — фиксированное значение из RFC 5389 §6, используется и для узнавания
// формата пакета, и для XOR-декодирования XOR-MAPPED-ADDRESS.
const stunMagicCookie = 0x2112A442

// stunServers — публичные STUN-серверы для запасного пути определения внешнего IP:порта,
// когда UPnP недоступен (роутер не поддерживает/выключен) — тот же принцип диверсификации
// целей, что и у checker.HealthCheckFallbackTargets: один сервер может быть недоступен из
// конкретной сети, несколько независимых источников снижают шанс ложного "не определить".
var stunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// stunBindingRequest собирает минимальный STUN Binding Request (RFC 5389 §6) без атрибутов —
// самый простой валидный запрос, ровно то, что нужно для получения XOR-MAPPED-ADDRESS в ответ.
func stunBindingRequest() ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, err
	}
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(buf[2:4], 0)      // Message Length — атрибутов нет
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], txID[:])
	return buf, txID, nil
}

// stunParseXorMappedAddress разбирает ответ Binding Success Response и достаёт
// XOR-MAPPED-ADDRESS (тип атрибута 0x0020, RFC 5389 §15.2) — единственное, что нужно этому
// пакету: внешний IP:порт, каким его видит STUN-сервер. MAPPED-ADDRESS (0x0001, старый формат
// без XOR, RFC 3489) — запасной вариант для серверов, которые ещё не обновились до RFC 5389.
func stunParseXorMappedAddress(resp []byte, txID [12]byte) (net.IP, int, error) {
	if len(resp) < 20 {
		return nil, 0, errors.New("stun: ответ короче заголовка")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 {
		return nil, 0, errors.New("stun: не Binding Success Response")
	}
	if binary.BigEndian.Uint32(resp[4:8]) != stunMagicCookie {
		return nil, 0, errors.New("stun: неверный magic cookie")
	}
	for i := 0; i < 12; i++ {
		if resp[8+i] != txID[i] {
			return nil, 0, errors.New("stun: transaction ID не совпадает — чужой ответ")
		}
	}

	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	body := resp[20:]
	if len(body) > msgLen {
		body = body[:msgLen]
	}

	var mappedIP net.IP
	var mappedPort int
	for len(body) >= 4 {
		attrType := binary.BigEndian.Uint16(body[0:2])
		attrLen := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+attrLen > len(body) {
			break
		}
		val := body[4 : 4+attrLen]

		switch attrType {
		case 0x0020: // XOR-MAPPED-ADDRESS — приоритетный формат
			if ip, port, ok := parseMappedAddressValue(val, true); ok {
				mappedIP, mappedPort = ip, port
			}
		case 0x0001: // MAPPED-ADDRESS — используем, только если XOR-варианта ещё не было
			if mappedIP == nil {
				if ip, port, ok := parseMappedAddressValue(val, false); ok {
					mappedIP, mappedPort = ip, port
				}
			}
		}

		// Атрибуты выровнены по границе 4 байт (RFC 5389 §15).
		padded := attrLen
		if rem := padded % 4; rem != 0 {
			padded += 4 - rem
		}
		if 4+padded > len(body) {
			break
		}
		body = body[4+padded:]
	}

	if mappedIP == nil {
		return nil, 0, errors.New("stun: ответ без (XOR-)MAPPED-ADDRESS")
	}
	return mappedIP, mappedPort, nil
}

func parseMappedAddressValue(val []byte, xored bool) (net.IP, int, bool) {
	if len(val) < 8 || val[1] != 0x01 { // family: 0x01 = IPv4; IPv6 за рамками этой функции
		return nil, 0, false
	}
	port := binary.BigEndian.Uint16(val[2:4])
	var ipBytes [4]byte
	copy(ipBytes[:], val[4:8])
	if xored {
		port ^= uint16(stunMagicCookie >> 16)
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		for i := range ipBytes {
			ipBytes[i] ^= cookie[i]
		}
	}
	return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]), int(port), true
}

// stunDetect опрашивает stunServers по очереди (первый ответивший — победитель), возвращает
// внешний IP и порт, под которым ЭТОТ UDP-сокет виден снаружи. Важная оговорка: это НЕ то же
// самое, что подтверждённо открытый входящий TCP-порт роли «Выход» — симметричный NAT может
// дать разное отображение для разных удалённых адресов/протоколов. Отсюда и Method,
// возвращаемый вызывающей стороной (reachability.go) для результата STUN — MethodManualPort,
// не MethodDirect: «вот твой вероятный внешний IP, но проброс порта подтверди/сделай сам».
func stunDetect(ctx context.Context) (net.IP, int, error) {
	var lastErr error
	for _, server := range stunServers {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}
		ip, port, err := stunDetectOne(ctx, server)
		if err == nil {
			return ip, port, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("stun: нет доступных серверов")
	}
	return nil, 0, lastErr
}

func stunDetectOne(ctx context.Context, server string) (net.IP, int, error) {
	deadline := 3 * time.Second
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining < deadline {
			deadline = remaining
		}
	}
	if deadline <= 0 {
		return nil, 0, ctx.Err()
	}

	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	req, txID, err := stunBindingRequest()
	if err != nil {
		return nil, 0, err
	}
	if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		return nil, 0, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	return stunParseXorMappedAddress(buf[:n], txID)
}
