// tunnel_entry_bridge.go — EntryBridge: работает НА устройстве «Вход». Локальный
// TCP-listener, на который sing-box outbound настраивается подключаться ВМЕСТО реального
// адреса партнёра (docs/TZ_APF_RELAY_v1.0.md §1, §2.3, §4).
package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
)

const entryBridgeDialTimeout = exitClientDialTimeout

// EntryBridge слушает 127.0.0.1:<эфемерный порт>, на каждое новое локальное соединение
// открывает соединение к RelayServer, делает ENTRY-handshake (с ретраем на "no such exit",
// докс §2.3 — основной сценарий: партнёр только что включил роль «Выход») и сшивает байты.
type EntryBridge struct {
	relayAddr string
	exitID    string
	// relayFingerprint — отпечаток TLS-сертификата relay-сервера (TZ_RELAY_HARDENING_2026-08-29.md
	// кластер B, tunnel_tls.go), взятый из ссылки партнёра (apf_relayfp) — обязателен, тот же
	// fail-closed принцип, что у ExitClient.RelayFingerprint.
	relayFingerprint string
	OnLog            func(string)

	mu       sync.Mutex
	ln       net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup // только сама acceptLoop-горутина — за проксируемые сессии отвечает registry
	registry *connRegistry
}

// NewEntryBridge — конструктор; сам listener поднимается в Start. relayFingerprint приходит
// из ссылки партнёра (apf_relayfp, singbox.BuildServerRelayLink) — та же строка, что партнёр
// («Выход») получил при настройке своего relay-fallback.
func NewEntryBridge(relayAddr, exitID, relayFingerprint string) *EntryBridge {
	return &EntryBridge{
		relayAddr:        relayAddr,
		exitID:           exitID,
		relayFingerprint: relayFingerprint,
		registry:         newConnRegistry(),
	}
}

func (b *EntryBridge) log(format string, args ...interface{}) {
	if b.OnLog != nil {
		b.OnLog(fmt.Sprintf(format, args...))
	}
}

// Start поднимает локальный listener и возвращает его адрес ("127.0.0.1:PORT") — этот адрес
// вызывающая сторона (AddChainPartnerFromLink) подставляет вместо Node.Address/Node.Port
// ПЕРЕД передачей узла в connectNode/Builder (докс §3) — sing-box outbound не отличает эту
// ситуацию от обычного узла. Безопасно вызывать повторно ПОСЛЕ Stop() — новый listener на
// новом порту.
func (b *EntryBridge) Start(ctx context.Context) (localAddr string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ln != nil {
		return "", fmt.Errorf("relay: EntryBridge уже запущен — вызовите Stop() перед повторным Start()")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("relay: EntryBridge listen: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	b.ln = ln
	b.cancel = cancel

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.acceptLoop(runCtx, ln)
	}()

	return ln.Addr().String(), nil
}

// Stop останавливает listener и ждёт завершения всех активных соединений/горутин.
// [консилиум, HIGH] Обязателен к вызову при переподключении/удалении узла-партнёра —
// без него на каждое переподключение утекает listener-горутина и локальный порт.
//
// [консилиум, HIGH, находка №6, TZ_RELAY_HARDENING_2026-08-29.md кластер G] Раньше здесь стоял
// голый b.wg.Wait() — если удалённая сторона держала активное соединение и не закрывала канал
// сама (обрыв мобильной сети без FIN/RST, обычное дело), Stop() мог виснуть НАВСЕГДА, блокируя
// весь вызывающий поток отключения узла. registry.shutdown() ждёт естественного завершения до
// connShutdownGrace, затем закрывает зависшие соединения принудительно — Stop() гарантированно
// возвращается за ограниченное время.
func (b *EntryBridge) Stop() {
	b.mu.Lock()
	ln := b.ln
	cancel := b.cancel
	b.ln = nil
	b.cancel = nil
	b.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ln != nil {
		ln.Close()
	}
	b.wg.Wait() // сама acceptLoop-горутина — завершается сразу, как только Accept() увидел закрытие ln
	b.registry.shutdown(connShutdownGrace)
}

func (b *EntryBridge) acceptLoop(ctx context.Context, ln net.Listener) {
	// Реагируем и на отмену ctx (например, Engine.Stop()/Disconnect() отменяет свой e.ctx,
	// от которого этот bridge унаследован через Start(e.ctx)), не только на явный Stop() —
	// без этого отмена родительского контекста НЕ закрыла бы listener сама по себе (Accept()
	// не context-aware), и горутина/порт пережили бы остановку движка.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener закрыт (Stop() или отмена ctx) — штатное завершение
		}
		// Регистрация в registry (не в b.wg) начинается только после успешного дозвона до
		// relay — окно между Accept() и dial'ом ограничено ctx (Stop() отменяет его и тем
		// самым прерывает зависший dialEntryWithRetry без ожидания grace), поэтому отдельного
		// учёта здесь не нужно (см. комментарий у registry в Stop()).
		go b.handleLocalConn(ctx, conn)
	}
}

func (b *EntryBridge) handleLocalConn(ctx context.Context, localConn net.Conn) {
	relayConn, err := b.dialEntryWithRetry(ctx)
	if err != nil {
		b.log("relay: не удалось подключиться к партнёру через relay: %v", err)
		localConn.Close()
		return
	}
	done := b.registry.add(localConn, relayConn)
	defer done()
	splice(localConn, relayConn)
}

// dialEntryWithRetry — ENTRY-handshake с ретраем на "no such exit" (докс §2.3): партнёр мог
// только что включить роль «Выход», а его ExitClient ещё не успел зарегистрироваться —
// без ретрая этот обычный сценарий старта выглядел бы как постоянный отказ.
func (b *EntryBridge) dialEntryWithRetry(ctx context.Context) (net.Conn, error) {
	var lastErr error
	for attempt := 1; attempt <= entryRetryAttempts; attempt++ {
		conn, err := b.dialEntryOnce(ctx)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if attempt < entryRetryAttempts {
			if !sleepCtx(ctx, entryRetryDelay) {
				return nil, ctx.Err()
			}
		}
	}
	return nil, fmt.Errorf("relay: ENTRY не удался после %d попыток: %w", entryRetryAttempts, lastErr)
}

func (b *EntryBridge) dialEntryOnce(ctx context.Context) (net.Conn, error) {
	conn, err := dialRelayTLS(ctx, b.relayAddr, b.relayFingerprint, entryBridgeDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial relay: %w", err)
	}
	if err := writeLine(conn, cmdEntry+" "+b.exitID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write ENTRY: %w", err)
	}
	resp, err := readLine(conn, streamDialTimeout())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read ENTRY response: %w", err)
	}
	if resp != cmdOK {
		conn.Close()
		return nil, fmt.Errorf("relay: %s", resp)
	}
	return conn, nil
}
