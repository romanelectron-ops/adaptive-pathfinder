// tunnel_exit_client.go — ExitClient: работает НА устройстве «Выход», держит control-канал
// к RelayServer и по запросу (NEWSTREAM) проксирует новый поток в локальный sing-box inbound
// (docs/TZ_APF_RELAY_v1.0.md §1, §2.2, §4).
package relay

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

const (
	exitClientInitialBackoff = 1 * time.Second
	exitClientMaxBackoff     = 30 * time.Second
	exitClientBackoffFactor  = 2.0
	exitClientDialTimeout    = 8 * time.Second
)

// ExitClient — держит control-соединение к RelayServer от имени одного exit-id и обслуживает
// запросы NEWSTREAM, проксируя каждый в локальный адрес (обычно 127.0.0.1:<internal-порт
// sing-box или admission-control прокси>, см. docs/PLAN_APF_RELAY_v1.0.md фаза D.1).
//
// [консилиум, HIGH, находка №9, TZ_RELAY_HARDENING_2026-08-29.md кластер D] Сокеты этого типа
// (control-канал к relay, включая переподключения) на Android НЕ оборачиваются в protect() —
// сознательно, по итогам живой проверки 2026-08-30 на Redmi (<test-phone>): роль «Вход» (TUN,
// addDisallowedApplication(packageName) в APFVpnService.kt) и роль «Выход» с этим самым
// ExitClient были подняты ОДНОВРЕМЕННО на одном устройстве; принудительный реконнект
// control-канала (рестарт apf-relay на удалённой стороне) породил НОВОЕ TCP-соединение уже
// при полностью активном TUN, и оно успешно зарегистрировалось на relay с реального Wi-Fi IP
// устройства (не потеряно и не зациклено туннелем). addDisallowedApplication исключает
// UID всего пакета APF из маршрутизации через собственный TUN, а не отдельные сокеты — этого
// достаточно, protect() был бы избыточен. Пересматривать это решение, если появится сценарий
// исключения по UID, отличный от addDisallowedApplication (другая VPN-реализация,
// per-app-профиль ОС и т.п.).
type ExitClient struct {
	RelayAddr   string
	ExitID      string
	RelayToken  string
	LocalTarget string
	// RelayFingerprint — hex(sha256(DER-сертификата)) relay-сервера (TZ_RELAY_HARDENING_2026-08-29.md
	// кластер B, tunnel_tls.go) — обязателен: пустое значение делает Run/runOnce
	// fail-closed (ни один dial к relay не пройдёт мимо TLS с проверкой отпечатка).
	RelayFingerprint string
	OnLog            func(string)

	// DialLocal — необязательный «умный» путь к локальной цели: вместо обычного звонка на
	// LocalTarget получает адрес настоящего «Входа» (sourceIP; пусто — relay не передал его) и
	// сам решает, пускать ли (лимит устройств роли «Выход») и куда звонить. Обычно это
	// AdmissionProxy.AdmitAndDial. nil — прежнее поведение: net.Dial на LocalTarget.
	// Когда задан, ExitClient сообщает relay «CAPS src», чтобы получать адрес «Входа».
	DialLocal func(ctx context.Context, sourceIP string) (net.Conn, error)

	mu       sync.Mutex
	running  bool
	// connected — [консилиум, HIGH, находка №11, TZ_RELAY_HARDENING_2026-08-29.md кластер H]
	// в отличие от running (горутина Run жива — true и во время backoff-паузы между
	// попытками, когда control-канал в этот момент фактически НЕ существует), connected
	// отражает реальный факт: control-канал сейчас установлен И EXIT принят relay (получен
	// OK). false с самого начала, false сразу при любом обрыве и весь backoff перед
	// следующей попыткой — см. setConnected/IsConnected и точки её выставления в runOnce.
	connected bool
	registry  *connRegistry
}

// NewExitClient — конструктор с обязательными полями; RelayToken/ExitID должны быть уже
// сгенерированы вызывающей стороной (см. GenerateExitCredentials) и сохранены рядом с
// server-identity, ДО первого вызова Run. relayFingerprint — отпечаток TLS-сертификата
// relay-сервера (см. RelayFingerprint) — тоже обязателен, вызывающая сторона получает его
// от оператора relay вместе с relayAddr.
func NewExitClient(relayAddr, exitID, relayToken, localTarget, relayFingerprint string) *ExitClient {
	return &ExitClient{
		RelayAddr:        relayAddr,
		ExitID:           exitID,
		RelayToken:       relayToken,
		LocalTarget:      localTarget,
		RelayFingerprint: relayFingerprint,
		registry:         newConnRegistry(),
	}
}

// GenerateExitCredentials создаёт новую пару (exit-id, relay-token) — вызывается ОДИН раз
// при первом включении relay-fallback для identity (докс §2.1, §3): exit-id — публичный
// маршрутный идентификатор (идёт в ссылку), relay-token — секрет (НИКОГДА не идёт в ссылку).
// [консилиум] Намеренно НЕ равны identity.UUID — раньше совпадение публичного routing-id и
// VLESS-секрета создавало риск: relay неизбежно логирует exit-id в открытом протоколе.
func GenerateExitCredentials() (exitID, relayToken string, err error) {
	exitID, err = newRandomHex(exitIDSize)
	if err != nil {
		return "", "", err
	}
	relayToken, err = newRandomHex(relayTokenSize)
	if err != nil {
		return "", "", err
	}
	return exitID, relayToken, nil
}

func (c *ExitClient) log(format string, args ...interface{}) {
	if c.OnLog != nil {
		c.OnLog(fmt.Sprintf(format, args...))
	}
}

// Run держит control-канал, переподключаясь с экспоненциальным backoff+джиттером при обрыве
// (докс §4: «конкретные цифры: старт 1с, макс 30с, ×2, джиттер ±20%»). Блокирует вызывающую
// горутину до отмены ctx — вызывающая сторона запускает это через свой обычный
// go-tracked-паттерн (тот же, что остальные фоновые задачи Engine).
func (c *ExitClient) Run(ctx context.Context) {
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()
	defer func() {
		// [консилиум, MEDIUM, находка №14, TZ_RELAY_HARDENING_2026-08-29.md кластер G] Раньше
		// handleNewStream-горутины не отслеживались вообще — Run() возвращался (и running
		// становился false) немедленно по отмене ctx, пока уже открытые splice()-пары
		// продолжали жить в фоне неучитываемо. registry.shutdown() ждёт их естественного
		// завершения до connShutdownGrace, затем закрывает принудительно — running=false
		// теперь честно означает «ни одной активной горутины этого ExitClient не осталось».
		c.registry.shutdown(connShutdownGrace)
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	backoff := exitClientInitialBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		connected, err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if connected {
			// Соединение хотя бы установилось и было принято (OK) — сбрасываем backoff,
			// обрыв после этого момента не должен штрафоваться как повторный неудачный старт.
			backoff = exitClientInitialBackoff
		}
		if err != nil {
			c.log("relay: control-канал прервался (%v), переподключение через %v", err, backoff)
		}
		if !sleepCtx(ctx, jitter(backoff)) {
			return
		}
		backoff = time.Duration(float64(backoff) * exitClientBackoffFactor)
		if backoff > exitClientMaxBackoff {
			backoff = exitClientMaxBackoff
		}
	}
}

// runOnce — одна попытка: dial, EXIT-handshake, затем обслуживание NEWSTREAM/PING до обрыва.
// connected=true, если handshake завершился успешно (получили OK) — используется вызывающей
// Run для решения о сбросе backoff, даже если сама сессия потом прервалась быстро.
func (c *ExitClient) runOnce(ctx context.Context) (connected bool, err error) {
	conn, err := dialRelayTLS(ctx, c.RelayAddr, c.RelayFingerprint, exitClientDialTimeout)
	if err != nil {
		return false, fmt.Errorf("dial relay: %w", err)
	}
	defer conn.Close()

	if err := writeLine(conn, fmt.Sprintf("%s %s %s", cmdExit, c.ExitID, c.RelayToken)); err != nil {
		return false, fmt.Errorf("write EXIT: %w", err)
	}
	resp, err := readLine(conn, handshakeReadTimeout)
	if err != nil {
		return false, fmt.Errorf("read EXIT response: %w", err)
	}
	if resp != cmdOK {
		// ERR (например, "exit-id занят другим владельцем") — ретраить с тем же backoff
		// бессмысленно менять код, ошибка конфигурации, не сетевая, но и не паниковать —
		// пользователь увидит её в логе и разберётся (честная ошибка, не тихий сбой).
		return false, fmt.Errorf("relay отказал: %s", resp)
	}
	c.log("relay: EXIT %s зарегистрирован на %s", c.ExitID, c.RelayAddr)

	// Сообщаем relay, что умеем принимать адрес источника (см. cmdCaps). Пишем ДО serve —
	// пока PONG-ответы (единственные другие записи в conn) ещё не начались, писатель один.
	// Ошибка записи не фатальна для протокола, но control-канал после неё всё равно мёртв.
	if c.DialLocal != nil {
		if err := writeLine(conn, cmdCaps+" "+capSrc); err != nil {
			return false, fmt.Errorf("write CAPS: %w", err)
		}
	}

	c.setConnected(true)
	defer c.setConnected(false)

	return true, c.serve(ctx, conn)
}

func (c *ExitClient) serve(ctx context.Context, conn net.Conn) error {
	writeMu := &sync.Mutex{}
	for {
		line, err := readLine(conn, pingInterval+pongTimeout)
		if err != nil {
			return fmt.Errorf("control-канал: %w", err)
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case cmdPing:
			writeMu.Lock()
			werr := writeLine(conn, cmdPong)
			writeMu.Unlock()
			if werr != nil {
				return fmt.Errorf("write PONG: %w", werr)
			}
		case cmdNewStream:
			// Два поля — relay без адреса источника (старая версия либо «Выход» не просил
			// CAPS); три — «NEWSTREAM <sid> <ip-входа>» (см. cmdCaps).
			if len(fields) != 2 && len(fields) != 3 {
				continue
			}
			sessionID := fields[1]
			sourceIP := ""
			if len(fields) == 3 {
				sourceIP = fields[2]
			}
			go c.handleNewStream(ctx, sessionID, sourceIP)
		}
	}
}

// handleNewStream — по запросу NEWSTREAM открывает НОВОЕ соединение к relay (не переиспользует
// control-канал — тот же приём, что ngrok/frp/rathole, докс §1.1), представляется STREAM,
// затем сшивает его с локальным dial (обычно admission-control прокси на стороне «Выход»,
// см. docs/TZ_APF_RELAY_v1.0.md §10.2 — relay-путь обязан проходить через тот же лимит
// подключений, что и прямой).
func (c *ExitClient) handleNewStream(ctx context.Context, sessionID, sourceIP string) {
	relayConn, err := dialRelayTLS(ctx, c.RelayAddr, c.RelayFingerprint, exitClientDialTimeout)
	if err != nil {
		c.log("relay: не удалось открыть STREAM-соединение для сессии %s: %v", sessionID, err)
		return
	}

	if err := writeLine(relayConn, fmt.Sprintf("%s %s %s", cmdStream, sessionID, c.RelayToken)); err != nil {
		relayConn.Close()
		return
	}
	resp, err := readLine(relayConn, handshakeReadTimeout)
	if err != nil || resp != cmdOK {
		relayConn.Close()
		return
	}

	// LocalTarget — loopback до admission-control/sing-box НА ЭТОМ ЖЕ устройстве, не relay:
	// TLS здесь не нужен (тот же принцип, что и у AdmissionProxy→sing-box, ГЛАВА про
	// 127.0.0.1-only биндинг, TZ_APF_RELAY_v1.0.md §10.2).
	var localConn net.Conn
	if c.DialLocal != nil {
		// Лимит устройств и звонок во внутреннюю цель — одним шагом (AdmissionProxy.AdmitAndDial):
		// отказ по лимиту приходит сюда ошибкой и закрывает relay-сторону, как раньше делал
		// AdmissionProxy закрытием принятого соединения.
		localConn, err = c.DialLocal(ctx, sourceIP)
	} else {
		dialer := net.Dialer{Timeout: exitClientDialTimeout}
		localConn, err = dialer.DialContext(ctx, "tcp", c.LocalTarget)
	}
	if err != nil {
		switch {
		case c.DialLocal != nil && singbox.IsAdmissionRejection(err):
			// [ревью 1.1.10, C3/F4] Отказ по лимиту устройств — штатная работа лимита, а не сбой
			// «локальной цели»: AdmissionProxy уже записал его в журнал (не чаще раза в минуту на
			// устройство). Раньше здесь шла ещё одна строка на КАЖДЫЙ отказ, да ещё с текстом
			// «цель недоступна» — она и забивала журнал, и путала диагноз (цель-то в порядке).
		case c.DialLocal != nil:
			// LocalTarget при DialLocal — не то, куда реально звонили (адрес выбирает сам
			// DialLocal), поэтому его в тексте нет: причина — в err.
			c.log("relay: не удалось соединиться с внутренней целью роли «Выход» для сессии %s: %v", sessionID, err)
		default:
			c.log("relay: локальная цель %s недоступна для сессии %s: %v", c.LocalTarget, sessionID, err)
		}
		relayConn.Close()
		return
	}

	done := c.registry.add(relayConn, localConn)
	defer done()
	splice(relayConn, localConn)
}

// IsRunning — жива ли горутина Run прямо сейчас (включая время backoff-паузы между попытками
// переподключения, когда никакого реального соединения с relay в этот момент нет).
func (c *ExitClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// IsConnected — [консилиум, HIGH, находка №11, TZ_RELAY_HARDENING_2026-08-29.md кластер H]
// установлен ли control-канал ПРЯМО СЕЙЧАС (EXIT принят relay, OK получен, соединение ещё не
// оборвалось) — то, что реально нужно показать пользователю в статусе роли «Выход», в отличие
// от IsRunning (которое остаётся true и во время backoff, вводя в заблуждение).
func (c *ExitClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *ExitClient) setConnected(v bool) {
	c.mu.Lock()
	c.connected = v
	c.mu.Unlock()
}

func jitter(d time.Duration) time.Duration {
	// ±20% джиттера — не даёт множеству ExitClient (если их вдруг несколько за одним NAT)
	// синхронно долбить relay ровно в один и тот же момент после общего сбоя сети.
	delta := float64(d) * 0.2
	offset := (rand.Float64()*2 - 1) * delta
	return d + time.Duration(offset)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
