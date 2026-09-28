// cmd/apf-relay — самостоятельный процесс relay-посредника (docs/TZ_APF_RELAY_v1.0.md §1,
// §6). Единственный компонент всей схемы «Вход/Выход», которому нужен маршрутизируемый
// адрес (белый IP для реального межсетевого использования, ЛЮБОЙ адрес, до которого
// достучатся оба устройства, для теста в одной сети/на одном ПК — internal/relay.RelayServer
// не различает эти два случая). Библиотека (internal/relay) существовала уже в Фазе B, но не
// имела ни одной точки входа как отдельный запускаемый бинарник — без него пользователь не
// может ни реально поднять свой relay на VPS/Pi (ТЗ §6), ни (что нужно прямо сейчас) проверить
// протокол на живом оборудовании без публичного хоста: relay, «Выход» и «Вход» вполне могут
// быть тремя процессами на ПК+двух телефонах в одной Wi-Fi сети — с точки зрения протокола
// это неотличимо от «настоящего» межсетевого relay, разница только в маршрутизируемости адреса.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/relay"
)

func main() {
	addr := flag.String("addr", ":9443", "адрес, на котором слушать (например :9443 или 0.0.0.0:9443)")
	maxExits := flag.Int("max-exits", 0, "макс. число одновременно зарегистрированных «Выходов» (0 = дефолт)")
	maxConnsPerIP := flag.Int("max-conns-per-ip", 0, "макс. одновременных соединений с одного IP (0 = дефолт)")
	certDir := flag.String("cert-dir", ".", "каталог для самоподписанного TLS-сертификата relay (relay_cert.pem/relay_key.pem) — создаётся при первом запуске")
	shutdownGrace := flag.Duration("shutdown-grace", 5*time.Second,
		"сколько ждать естественного завершения активных сессий (Вход↔Выход) при остановке/деплое, прежде чем закрыть их принудительно")
	flag.Parse()

	cfg := relay.DefaultRelayServerConfig()
	if *maxExits > 0 {
		cfg.MaxRegisteredExits = *maxExits
	}
	if *maxConnsPerIP > 0 {
		cfg.MaxConnsPerIP = *maxConnsPerIP
	}
	cfg.OnLog = func(msg string) { log.Println(msg) }

	// [TZ_RELAY_HARDENING_2026-08-29.md кластер B] Весь relay-протокол (включая relay-token —
	// единственный секрет, защищающий его) теперь ОБЯЗАН идти внутри TLS с закреплённым
	// отпечатком сертификата (pinned-fingerprint, не CA — см. tunnel_tls.go): ни ExitClient,
	// ни EntryBridge больше не умеют подключаться без него (fail-closed).
	cert, fingerprint, err := relay.LoadOrGenerateRelayCert(*certDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apf-relay: не удалось подготовить TLS-сертификат: %v\n", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apf-relay: не удалось слушать %s: %v\n", *addr, err)
		os.Exit(1)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	log.Printf("apf-relay: слушаю %s по TLS (лимит «Выходов»: %d, лимит соединений/IP: %d)",
		ln.Addr(), cfg.MaxRegisteredExits, cfg.MaxConnsPerIP)
	log.Printf("apf-relay: ОТПЕЧАТОК TLS-СЕРТИФИКАТА (сообщите его владельцам «Выходов»/«Входов», он идёт в конфиг/ссылку): %s", fingerprint)

	srv := relay.NewRelayServer(tlsLn, cfg)

	// Graceful shutdown по Ctrl+C/SIGTERM — закрывает listener, Serve() возвращается сам.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		log.Println("apf-relay: получен сигнал остановки, закрываю listener")
		ln.Close()
	}()

	serveErr := srv.Serve()

	// [консилиум, MEDIUM, находка №22, TZ_RELAY_HARDENING_2026-08-29.md кластер G] Раньше
	// "graceful shutdown" останавливался на закрытии listener'а — уже идущие ENTRY↔STREAM
	// сессии (включая активные splice()-передачи) обрывались одномоментно (RST вместо FIN)
	// вместе с завершением процесса, несмотря на комментарий выше, называющий это "graceful".
	// Shutdown() ждёт их естественного завершения до -shutdown-grace, затем закрывает
	// принудительно — Serve() уже вернулся (listener закрыт), поэтому новые сессии сюда не
	// попадают, ждём только то, что было принято ДО сигнала остановки.
	log.Printf("apf-relay: дожидаюсь завершения активных сессий (до %s)...", *shutdownGrace)
	srv.Shutdown(*shutdownGrace)

	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
		log.Printf("apf-relay: Serve завершился с ошибкой: %v", serveErr)
	} else {
		log.Println("apf-relay: остановлен")
	}
}
