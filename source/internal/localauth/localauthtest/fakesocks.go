// Package localauthtest - фиктивный SOCKS5-сервер для тестов клиентов, которые ходят на локальный
// вход sing-box (лот L4). Только для тестов: подключается из *_test.go, в рабочие сборки не входит.
package localauthtest

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/localauth"
)

// Server - запущенный фиктивный сервер.
type Server struct {
	Addr string

	mu       sync.Mutex
	connects []string
	authOK   int
	authBad  int
}

// Connects - адреса, к которым успешно прошёл CONNECT.
func (s *Server) Connects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.connects...)
}

// AuthOK - сколько раз клиент прошёл проверку логина/пароля сессии.
func (s *Server) AuthOK() int { s.mu.Lock(); defer s.mu.Unlock(); return s.authOK }

// AuthBad - сколько раз клиент прислал неверные учётные данные.
func (s *Server) AuthBad() int { s.mu.Lock(); defer s.mu.Unlock(); return s.authBad }

// StartSOCKS5 поднимает сервер на петле. requireAuth: true - выбирает метод 0x02 и проверяет
// пароль сессии (как защищённый вход в режиме VPN); false - метод 0x00 (открытый вход).
func StartSOCKS5(t testing.TB, requireAuth bool) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: ln.Addr().String()}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, requireAuth)
		}
	}()
	return s
}

func (s *Server) serve(c net.Conn, requireAuth bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	has := func(m byte) bool {
		for _, x := range methods {
			if x == m {
				return true
			}
		}
		return false
	}
	if requireAuth {
		if !has(0x02) {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return
		}
		_, _ = c.Write([]byte{0x05, 0x02})
		ah := make([]byte, 2)
		if _, err := io.ReadFull(c, ah); err != nil {
			return
		}
		user := make([]byte, ah[1])
		_, _ = io.ReadFull(c, user)
		pl := make([]byte, 1)
		_, _ = io.ReadFull(c, pl)
		pass := make([]byte, pl[0])
		_, _ = io.ReadFull(c, pass)
		u, p := localauth.Credentials()
		if string(user) != u || string(pass) != p {
			s.mu.Lock()
			s.authBad++
			s.mu.Unlock()
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		s.mu.Lock()
		s.authOK++
		s.mu.Unlock()
		_, _ = c.Write([]byte{0x01, 0x00})
	} else {
		if !has(0x00) {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return
		}
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	// CONNECT: VER CMD RSV ATYP ADDR PORT
	rq := make([]byte, 4)
	if _, err := io.ReadFull(c, rq); err != nil || rq[1] != 0x01 {
		return
	}
	var host string
	switch rq[3] {
	case 0x01:
		ip := make([]byte, 4)
		_, _ = io.ReadFull(c, ip)
		host = net.IP(ip).String()
	case 0x03:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		name := make([]byte, l[0])
		_, _ = io.ReadFull(c, name)
		host = string(name)
	default:
		return
	}
	port := make([]byte, 2)
	_, _ = io.ReadFull(c, port)
	s.mu.Lock()
	s.connects = append(s.connects, net.JoinHostPort(host, itoa(int(port[0])<<8|int(port[1]))))
	s.mu.Unlock()
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
