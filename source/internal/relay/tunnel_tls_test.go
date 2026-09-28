package relay

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// tlsEchoServer — минимальный TLS-сервер для тестов dialRelayTLS напрямую (не через
// RelayServer) — изолирует тест от протокольной логики выше транспорта.
func tlsEchoServer(t *testing.T) (addr, fingerprint string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cert, fp, err := LoadOrGenerateRelayCert(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateRelayCert: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		conn.Read(buf) // завершить handshake, держать соединение живым немного
		time.Sleep(50 * time.Millisecond)
	}()
	return ln.Addr().String(), fp
}

// [консилиум, CRITICAL, находка №3, TZ_RELAY_HARDENING_2026-08-29.md кластер B] Сердце всей
// защиты: без отпечатка dialRelayTLS обязан отказать ДО попытки подключения — никакого
// молчаливого отката на нешифрованный/непроверенный канал.
func TestDialRelayTLS_EmptyFingerprint_FailsClosed(t *testing.T) {
	addr, _ := tlsEchoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialRelayTLS(ctx, addr, "", time.Second)
	if err == nil {
		t.Fatal("dialRelayTLS с пустым fingerprint должен был отказать")
	}
	if !strings.Contains(err.Error(), "отпечаток") {
		t.Errorf("ошибка = %q, ожидалось упоминание отпечатка", err.Error())
	}
}

// Неверный отпечаток — тот случай, ради которого весь механизм существует: без него
// TLS-соединение к ПОДМЕНЁННОМУ relay (или к настоящему после компрометации его ключа)
// установилось бы неотличимо от легитимного.
func TestDialRelayTLS_WrongFingerprint_Rejected(t *testing.T) {
	addr, _ := tlsEchoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wrongFingerprint := strings.Repeat("ab", 32) // валидный по форме hex(sha256), заведомо не тот
	_, err := dialRelayTLS(ctx, addr, wrongFingerprint, time.Second)
	if err == nil {
		t.Fatal("dialRelayTLS с неверным fingerprint должен был отказать")
	}
}

// Верный отпечаток — счастливый путь: TLS-соединение реально устанавливается и пригодно для
// протокола (readLine/writeLine работают поверх него так же, как поверх обычного net.Conn).
func TestDialRelayTLS_CorrectFingerprint_Succeeds(t *testing.T) {
	addr, fingerprint := tlsEchoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialRelayTLS(ctx, addr, fingerprint, time.Second)
	if err != nil {
		t.Fatalf("dialRelayTLS с верным fingerprint отказал: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Errorf("запись поверх TLS-соединения отказала: %v", err)
	}
}

// Регистр отпечатка (hex в разных регистрах) и случайные пробелы вокруг него (человеческая
// ошибка копирования) не должны ломать легитимное подключение.
func TestDialRelayTLS_FingerprintCaseAndWhitespaceInsensitive(t *testing.T) {
	addr, fingerprint := tlsEchoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	messy := "  " + strings.ToUpper(fingerprint) + "\n"
	conn, err := dialRelayTLS(ctx, addr, messy, time.Second)
	if err != nil {
		t.Fatalf("dialRelayTLS отказал на fingerprint в другом регистре/с пробелами: %v", err)
	}
	conn.Close()
}

// Персистентность: одна и та же пара ключей/сертификата и, соответственно, отпечаток
// переживают перезапуск (повторный вызов LoadOrGenerateRelayCert с тем же dir) — иначе
// оператору пришлось бы заново рассылать отпечаток всем «Выходам»/«Входам» после каждого
// рестарта apf-relay.
func TestLoadOrGenerateRelayCert_PersistsAcrossReloads(t *testing.T) {
	dir := t.TempDir()
	_, fp1, err := LoadOrGenerateRelayCert(dir)
	if err != nil {
		t.Fatalf("первая генерация: %v", err)
	}
	_, fp2, err := LoadOrGenerateRelayCert(dir)
	if err != nil {
		t.Fatalf("повторная загрузка: %v", err)
	}
	if fp1 != fp2 {
		t.Errorf("fingerprint разошёлся между запусками: %q != %q — отпечаток должен быть стабилен", fp1, fp2)
	}
}

// Два независимых relay (разные каталоги) обязаны получить РАЗНЫЕ сертификаты/отпечатки —
// иначе pinning ничего не значил бы.
func TestLoadOrGenerateRelayCert_DifferentDirsDifferentFingerprints(t *testing.T) {
	_, fp1, err := LoadOrGenerateRelayCert(t.TempDir())
	if err != nil {
		t.Fatalf("relay A: %v", err)
	}
	_, fp2, err := LoadOrGenerateRelayCert(t.TempDir())
	if err != nil {
		t.Fatalf("relay B: %v", err)
	}
	if fp1 == fp2 {
		t.Error("два независимо сгенерированных сертификата совпали по отпечатку — генератор сломан")
	}
}
