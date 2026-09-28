//go:build windows

// Вариант A (D-32/D-33): транспорт управления Kill Switch поверх Windows named pipe.
//
// Сервер (apf-svc, SYSTEM) слушает \\.\pipe\APF-KS и исполняет netsh своими правами; клиент (движок
// трея/CLI, НЕ admin) шлёт JSON-команды (ksproto.go). Так switch узла и disable выполняются
// привилегированно БЕЗ повторного UAC (D-32), а crash-recovery делает служба на своём старте (D-33).
//
// Транспорт — сырые ReadFile/WriteFile поверх хендла пайпа (без os.File, чтобы не завязываться на
// Go-поллер для не-overlapped хендлов). Байтовый режим: один запрос → один ответ на соединение.
package killswitch

import (
	"errors"
	"io"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipeName = `\\.\pipe\APF-KS`

const (
	pipeReadmodeByte = 0x00000000
	pipeWait         = 0x00000000
	pipeBufSize      = 4096
	dialTimeout      = 3 * time.Second
	dialRetryPause   = 50 * time.Millisecond
	pipeConnTimeout  = 5000 // ms, для default-timeout инстанса

	// serveConnTimeout — предел на обслуживание ОДНОГО соединения (B-0403 · R-5.4, C-17).
	// Клиент, подключившийся и ничего не приславший, иначе держал бы экземпляр пайпа и горутину
	// бесконечно. Значение с большим запасом: легитимный обмен — один JSON в обе стороны.
	serveConnTimeout = 10 * time.Second
	// maxPipeConns — предел одновременно обслуживаемых соединений (анти-флуд). Достигнув его,
	// сервер перестаёт принимать новых, но уже принятых дообслуживает.
	maxPipeConns = 8
)

// ErrServiceUnavailable — служебный KS-канал недоступен (служба не установлена/не запущена).
// Движок при этом деградирует на путь одного UAC (windowsKS.EnableWithUAC).
var ErrServiceUnavailable = errors.New("killswitch: служебный канал недоступен")

// pipeConn — io.ReadWriteCloser поверх хендла пайпа (синхронные ReadFile/WriteFile).
type pipeConn struct{ h windows.Handle }

func (p *pipeConn) Read(b []byte) (int, error) {
	var n uint32
	if err := windows.ReadFile(p.h, b, &n, nil); err != nil {
		if n == 0 {
			return 0, io.EOF
		}
		return int(n), err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (p *pipeConn) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(p.h, b, &n, nil)
	return int(n), err
}

func (p *pipeConn) Close() error { return windows.CloseHandle(p.h) }

// pipeSecurityAttributes собирает SECURITY_ATTRIBUTES с DACL, суженным до владельца консольной
// сессии (R-5.2). SID пересчитывается на КАЖДЫЙ экземпляр пайпа — иначе после переключения
// пользователя DACL остался бы от прежнего.
func pipeSecurityAttributes() (*windows.SecurityAttributes, error) {
	sid, err := consoleUserSID()
	if err != nil {
		sid = "" // фолбэк на IU; решающая проверка всё равно на сервере (authorizeClient)
	}
	sd, err := windows.SecurityDescriptorFromString(pipeSDDLFor(sid))
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

// pipeOpenMode — режим создания экземпляра пайпа.
//
// R-5.3 (анти-сквоттинг): на ПЕРВОМ экземпляре ставится FILE_FLAG_FIRST_PIPE_INSTANCE. Без него
// посторонний процесс, успевший создать `\\.\pipe\APF-KS` раньше службы, получил бы поток команд
// управления Kill Switch. С флагом создание в такой ситуации падает — и мы это увидим.
// На последующих экземплярах флаг ставить НЕЛЬЗЯ: они по определению не первые.
func pipeOpenMode(first bool) uint32 {
	mode := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return mode
}

// ServePipe — серверный цикл (запускается в apf-svc под SYSTEM). На каждое подключение читает один
// запрос, авторизует клиента и отвечает. Завершается при закрытии stop (между соединениями).
//
// B-0403 · R-5: соединения обслуживаются в отдельных горутинах с пределом по времени и количеству,
// ответ гарантированно доставляется до разрыва, первый экземпляр защищён от перехвата имени.
func ServePipe(stop <-chan struct{}, ks ksExecutor, logf func(string)) {
	if logf == nil {
		logf = func(string) {}
	}
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		logf("killswitch pipe: name: " + err.Error())
		return
	}

	slots := make(chan struct{}, maxPipeConns)
	first := true
	for {
		select {
		case <-stop:
			return
		default:
		}
		sa, err := pipeSecurityAttributes()
		if err != nil {
			logf("killswitch pipe: security descriptor: " + err.Error())
			time.Sleep(500 * time.Millisecond)
			continue
		}
		h, err := windows.CreateNamedPipe(namePtr,
			pipeOpenMode(first),
			windows.PIPE_TYPE_BYTE|pipeReadmodeByte|pipeWait,
			windows.PIPE_UNLIMITED_INSTANCES,
			pipeBufSize, pipeBufSize, pipeConnTimeout, sa)
		if err != nil {
			if first && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				// R-5.3: имя уже занято ЧУЖИМ процессом. Повторять нельзя — это ровно та ситуация,
				// ради которой флаг и ставится. Канал не поднимаем; движок деградирует на UAC.
				logf("killswitch pipe: имя " + pipeName + " уже занято другим процессом — " +
					"служебный канал НЕ поднят (возможен перехват канала управления)")
				return
			}
			logf("killswitch pipe: create: " + err.Error())
			time.Sleep(500 * time.Millisecond)
			continue
		}
		first = false

		// Ждём подключения клиента. ERROR_PIPE_CONNECTED = клиент успел до ConnectNamedPipe.
		if err := windows.ConnectNamedPipe(h, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(h)
			continue
		}
		select {
		case slots <- struct{}{}:
		case <-stop:
			windows.CloseHandle(h)
			return
		}
		go func(h windows.Handle) {
			defer func() { <-slots }()
			serveOnePipeConn(h, ks, logf)
		}(h)
	}
}

// serveOnePipeConn обслуживает одно соединение и гарантированно освобождает экземпляр пайпа.
func serveOnePipeConn(h windows.Handle, ks ksExecutor, logf func(string)) {
	conn := &pipeConn{h: h}
	defer func() {
		// R-5.1: FlushFileBuffers на серверном хендле ждёт, пока клиент ВЫЧИТАЕТ ответ. Без него
		// DisconnectNamedPipe отбрасывает содержимое буфера, и клиент получает EOF вместо ответа:
		// Enable выглядит как сбой транспорта, движок считает Kill Switch неприменённым и (при
		// fail-closed R-2.1) отменяет подключение, хотя правила уже стоят.
		_ = windows.FlushFileBuffers(h)
		_ = windows.DisconnectNamedPipe(h)
		_ = conn.Close()
	}()

	// R-5.4: сторож против зависшего клиента. CancelIoEx снимает блокирующий ReadFile — пайп
	// создан без OVERLAPPED, поэтому иначе чтение не прервать ничем, кроме закрытия хендла.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-time.After(serveConnTimeout):
			_ = windows.CancelIoEx(h, nil)
			logf("killswitch pipe: клиент не завершил обмен за " + serveConnTimeout.String() +
				" — соединение разорвано")
		}
	}()

	if err := serveConn(conn, ks, func() error { return authorizePipeClient(h) }); err != nil {
		logf("killswitch pipe: " + err.Error())
	}
}

// dialPipe открывает клиентское соединение к служебному пайпу с таймаутом.
// Возвращает ErrServiceUnavailable, если сервер не поднят (нет пайпа).
func dialPipe(timeout time.Duration) (*pipeConn, error) {
	// DEF-08: под `go test` НИКОГДА не обращаемся к реальному служебному пайпу — иначе тест,
	// запущенный на машине с установленной службой APF, изменил бы фаервол хоста.
	if underTest() {
		return nil, ErrServiceUnavailable
	}
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(namePtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			return &pipeConn{h: h}, nil
		}
		if err == windows.ERROR_PIPE_BUSY && time.Now().Before(deadline) {
			time.Sleep(dialRetryPause)
			continue
		}
		// FILE_NOT_FOUND и прочее — сервер недоступен.
		return nil, ErrServiceUnavailable
	}
}

// ServiceAvailable сообщает, поднят ли служебный KS-канал (быстрая проба).
func ServiceAvailable() bool {
	conn, err := dialPipe(300 * time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// serviceClientKS — клиент KS через службу. Реализует KillSwitch + SetVPNEndpoint + EnableWithUAC
// (служба привилегированна, поэтому UAC не нужен). Все операции идут по пайпу.
type serviceClientKS struct {
	vpnIP   string
	port    int
	enabled bool
	// caps — возможности СЕРВЕРНОГО бэкенда, снятые при создании клиента (R-1.1).
	// Служба может быть поднята с netsh- или с WFP-бэкендом (APF_KS_BACKEND), и от этого зависит,
	// защитим ли VPN-режим. Кэшируем: движок спрашивает возможности на каждом подключении.
	caps Capabilities
}

// NewServiceClient возвращает клиента KS через службу, если канал доступен; иначе (false).
// Возможности серверного бэкенда снимаются сразу (op caps); служба старой версии, не знающая
// этот op, трактуется консервативно как proxy-only.
func NewServiceClient() (KillSwitch, bool) {
	if !ServiceAvailable() {
		return nil, false
	}
	c := &serviceClientKS{caps: Capabilities{ProxyMode: true}}
	if resp, err := c.call(Request{Op: OpCaps}); err == nil && resp.OK {
		c.caps = resp.Caps
	}
	return c, true
}

// Capabilities возвращает возможности серверного бэкенда (не свои собственные).
func (c *serviceClientKS) Capabilities() Capabilities { return c.caps }

// Reset выполняет быстрый сброс правил APF ПРАВАМИ СЛУЖБЫ (R-4.1/C-3), а не правами клиента.
func (c *serviceClientKS) Reset() error {
	resp, err := c.call(Request{Op: OpReset})
	if err != nil {
		return err
	}
	c.enabled = resp.Enabled
	if !resp.OK {
		return errors.New("killswitch service: " + resp.Error)
	}
	return nil
}

// ResetAll выполняет ПОЛНЫЙ откат сетевых изменений (включая DNS) правами службы (R-4.1).
func (c *serviceClientKS) ResetAll() error {
	resp, err := c.call(Request{Op: OpReset, Full: true})
	if err != nil {
		return err
	}
	c.enabled = resp.Enabled
	if !resp.OK {
		return errors.New("killswitch service: " + resp.Error)
	}
	return nil
}

// EnsureTunPermit проксирует досоздание permit-tun в службу (R-6.1/C-10).
func (c *serviceClientKS) EnsureTunPermit(tunInterface string) error {
	resp, err := c.call(Request{Op: OpEnsureTun, Tun: tunInterface})
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New("killswitch service: " + resp.Error)
	}
	return nil
}

func (c *serviceClientKS) SetVPNEndpoint(ip string, port int) { c.vpnIP, c.port = ip, port }

// dialConnFn — шов подключения к служебному пайпу (инжектируется в тестах на net.Pipe).
var dialConnFn = func(timeout time.Duration) (io.ReadWriteCloser, error) { return dialPipe(timeout) }

func (c *serviceClientKS) call(req Request) (Response, error) {
	conn, err := dialConnFn(dialTimeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	return sendRequest(conn, req)
}

func (c *serviceClientKS) Enable(tun string, ports []int) error {
	resp, err := c.call(Request{Op: OpEnable, VPNIP: c.vpnIP, Port: c.port, Tun: tun, Ports: ports})
	if err != nil {
		return err
	}
	c.enabled = resp.Enabled
	if !resp.OK {
		return errors.New("killswitch service: " + resp.Error)
	}
	return nil
}

func (c *serviceClientKS) Disable() error {
	resp, err := c.call(Request{Op: OpDisable})
	if err != nil {
		return err
	}
	c.enabled = resp.Enabled
	if !resp.OK {
		return errors.New("killswitch service: " + resp.Error)
	}
	return nil
}

func (c *serviceClientKS) IsEnabled() bool { return c.enabled }

// EnableWithUAC для клиента службы = обычный Enable (служба уже привилегированна, UAC не нужен).
func (c *serviceClientKS) EnableWithUAC(vpnIP string, port int) error {
	c.SetVPNEndpoint(vpnIP, port)
	return c.Enable("apf0", []int{port})
}
