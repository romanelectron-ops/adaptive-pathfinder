// Package leakguard — вспомогательные функции.
package leakguard

import (
	"context"
	"net"
	"time"
)

// dialSOCKS5 — простой SOCKS5 dialer для DNS leak тестирования через туннель.
// Используется в DNSLeakTester для проверки что DNS идёт через SOCKS5 прокси.
func dialSOCKS5(ctx context.Context, socksAddr, targetAddr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake
	// 1. Приветствие: версия=5, методов=1, метод=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}

	// 2. Ответ сервера: версия=5, метод=0
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, &net.OpError{Op: "socks5", Err: net.UnknownNetworkError("auth required")}
	}

	// 3. Запрос: версия=5, команда=1(CONNECT), rsv=0, тип=3(DOMAINNAME)
	host, port, err := parseAddr(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// 4. Ответ: [ver, rep, rsv, atyp, ...]
	hdr := make([]byte, 4)
	if _, err := readFull(conn, hdr); err != nil {
		conn.Close()
		return nil, err
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, &net.OpError{Op: "socks5 connect", Err: net.UnknownNetworkError("connection refused")}
	}

	// Читаем остаток адреса в ответе (игнорируем)
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 6)
		readFull(conn, addr)
	case 0x03: // domain
		ln := make([]byte, 1)
		readFull(conn, ln)
		addr := make([]byte, int(ln[0])+2)
		readFull(conn, addr)
	case 0x04: // IPv6
		addr := make([]byte, 18)
		readFull(conn, addr)
	}

	return conn, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func parseAddr(addr string) (host string, port int, err error) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return "", 0, e
	}
	host = h
	_, err = net.LookupHost(h) // pre-resolve (игнорируем ошибку для IP)
	_ = err
	var portNum int
	_, err = net.LookupPort("tcp", p)
	_ = err
	// Парсим порт вручную
	for _, c := range p {
		if c < '0' || c > '9' {
			return h, 0, &net.AddrError{Err: "invalid port", Addr: p}
		}
		portNum = portNum*10 + int(c-'0')
	}
	return h, portNum, nil
}
