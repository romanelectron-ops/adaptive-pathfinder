// Package localauth - пароль сессии для локальных входов sing-box (лот L4, разбор внешних
// репозиториев 2026-10-21, идея U-05).
//
// Проблема. Локальные входы socks-in и http-in на 127.0.0.1:порт и Clash API (порт+2) раньше не
// имели ни логина, ни секрета. Любое приложение на устройстве (на Android - любое установленное,
// на ПК - любой процесс пользователя) могло выпустить свой трафик через узел пользователя либо
// прочитать из Clash API список соединений, то есть адреса, на которые идёт трафик. В README
// igareck этот класс уязвимости описан отдельно.
//
// Решение. Случайные логин, пароль и секрет Clash API создаются один раз на процесс. Конфигуратор
// sing-box кладёт их в конфиг, а собственные клиенты APF (пробы узлов, сторож, проверка утечек DNS,
// загрузка источников через туннель, менеджер трафика) берут их отсюда же - всё это живёт в одном
// процессе с движком, поэтому передавать пароль через настройки не нужно.
//
// Когда пароль включён. Только когда приложения пользователя в любом случае идут через TUN
// (режим VPN): тогда локальный SOCKS/HTTP нужен лишь самому APF. В режимах «прокси» и «гибрид» вход
// остаётся открытым осознанно: к нему подключаются браузер и приложения пользователя (системный
// прокси, ручная настройка), а они не знают пароля сессии. Секрет Clash API включён всегда.
package localauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var (
	once                    sync.Once
	user, pass, clashSecret string
)

func gen() {
	once.Do(func() {
		user = "apf-" + randHex(4)
		pass = randHex(16)
		clashSecret = randHex(16)
	})
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand не должен отказывать; если отказал - честный отказ лучше слабого пароля.
		panic(fmt.Sprintf("localauth: crypto/rand: %v", err))
	}
	return hex.EncodeToString(b)
}

// Credentials возвращает логин и пароль сессии для SOCKS/HTTP-входов (стабильны в пределах процесса).
func Credentials() (username, password string) {
	gen()
	return user, pass
}

// ClashSecret возвращает секрет Clash API (заголовок Authorization: Bearer <секрет>).
func ClashSecret() string {
	gen()
	return clashSecret
}

// BearerHeader - значение заголовка Authorization для Clash API.
func BearerHeader() string { return "Bearer " + ClashSecret() }

// Greet выполняет приветствие SOCKS5 (RFC 1928) для клиента: предлагает ОБА метода - «без
// авторизации» (0x00) и «логин/пароль» (0x02, RFC 1929); какой выбрать, решает сервер. Если вход
// открыт (режимы прокси/гибрид), сервер выберет 0x00; если защищён (режим VPN) - 0x02, и клиент
// отвечает паролем сессии. Дедлайны на соединении выставляет вызывающий.
func Greet(conn net.Conn) error {
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return fmt.Errorf("read method reply: %w", err)
	}
	if rep[0] != 0x05 {
		return fmt.Errorf("unexpected socks version %d", rep[0])
	}
	switch rep[1] {
	case 0x00:
		return nil
	case 0x02:
		return userPassAuth(conn)
	default:
		return fmt.Errorf("server chose unsupported auth method 0x%02x", rep[1])
	}
}

// userPassAuth - подпереговоры RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD -> VER=1, STATUS=0.
func userPassAuth(conn net.Conn) error {
	u, p := Credentials()
	if len(u) > 255 || len(p) > 255 {
		return errors.New("credentials too long")
	}
	req := make([]byte, 0, 3+len(u)+len(p))
	req = append(req, 0x01, byte(len(u)))
	req = append(req, u...)
	req = append(req, byte(len(p)))
	req = append(req, p...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if rep[0] != 0x01 || rep[1] != 0x00 {
		return errors.New("local proxy rejected the session credentials")
	}
	return nil
}
