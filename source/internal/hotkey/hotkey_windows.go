//go:build windows

package hotkey

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	procRegisterHotKey     = user32.NewProc("RegisterHotKey")
	procUnregisterHotKey   = user32.NewProc("UnregisterHotKey")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procPostThreadMessageW = user32.NewProc("PostThreadMessageW")

	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentThreadID = kernel32.NewProc("GetCurrentThreadId")
)

// Флаги RegisterHotKey (winuser.h) — x/sys/windows не оборачивает GUI-message-loop API
// user32, поэтому используем сырой syscall, как и остальной Windows-специфичный код проекта
// (см. internal/killswitch/elevate_windows.go).
const (
	modAlt      = 0x0001
	modControl  = 0x0002
	modShift    = 0x0004
	modWin      = 0x0008
	modNoRepeat = 0x4000 // Windows 7+: не повторять WM_HOTKEY, пока клавиша зажата

	wmHotkey = 0x0312

	// hotkeyID — идентификатор регистрации. Один процесс = один аварийный хоткей одновременно,
	// уникальность внутри потока не требуется шире.
	hotkeyID = 1
)

// msg — структура MSG (winuser.h) для GetMessageW. Раскладка ДОЛЖНА побайтово совпадать с
// нативной: HWND(8)+UINT(4)+паддинг(4)+WPARAM(8)+LPARAM(8)+DWORD(4)+POINT(8) на amd64.
type msg struct {
	hwnd    uintptr
	message uint32
	_       uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

type winManager struct {
	mu       sync.Mutex
	threadID uintptr
	stopped  chan struct{}
}

func (m *winManager) Unregister() {
	m.mu.Lock()
	tid := m.threadID
	m.mu.Unlock()
	if tid == 0 {
		return
	}
	// WM_QUIT = 0x0012: снимает GetMessageW-цикл в register(), тот сам вызовет
	// UnregisterHotKey перед выходом (см. ниже) — на том же потоке, что регистрировал, как
	// того требует контракт RegisterHotKey/UnregisterHotKey.
	procPostThreadMessageW.Call(tid, 0x0012, 0, 0)
	<-m.stopped
}

// register — см. hotkey.Register. RegisterHotKey ОБЯЗАН вызываться из того же потока ОС, что
// потом читает WM_HOTKEY через GetMessage (иначе сообщение уйдёт в чужую очередь и никогда не
// будет прочитано) — отсюда выделенный горутина-поток с LockOSThread, а не просто фоновый go.
func register(combo string, onTrigger func()) (Manager, error) {
	mods, vk, err := parseCombo(combo)
	if err != nil {
		return nil, err
	}

	m := &winManager{stopped: make(chan struct{})}
	ready := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		tid, _, _ := procGetCurrentThreadID.Call()
		m.mu.Lock()
		m.threadID = tid
		m.mu.Unlock()

		r, _, callErr := procRegisterHotKey.Call(0, hotkeyID, uintptr(mods|modNoRepeat), uintptr(vk))
		if r == 0 {
			ready <- fmt.Errorf("hotkey: RegisterHotKey отказал (комбинация %q уже занята другим "+
				"приложением?): %v", combo, callErr)
			close(m.stopped)
			return
		}
		ready <- nil

		var m1 msg
		for {
			r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m1)), 0, 0, 0)
			// GetMessage: 0 при WM_QUIT, -1 (переполнение в BOOL) при ошибке — оба останавливают цикл.
			if int32(r) <= 0 {
				break
			}
			if m1.message == wmHotkey && m1.wParam == hotkeyID {
				onTrigger()
			}
		}
		procUnregisterHotKey.Call(0, hotkeyID)
		close(m.stopped)
	}()

	if err := <-ready; err != nil {
		return nil, err
	}
	return m, nil
}

// parseCombo разбирает "ctrl+shift+F12" в модификаторы RegisterHotKey + виртуальный код клавиши.
func parseCombo(combo string) (mods uint32, vk uint32, err error) {
	combo = strings.TrimSpace(combo)
	if combo == "" {
		return 0, 0, fmt.Errorf("hotkey: пустая комбинация")
	}
	parts := strings.Split(combo, "+")
	keyPart := strings.TrimSpace(parts[len(parts)-1])
	for _, p := range parts[:len(parts)-1] {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "ctrl", "control":
			mods |= modControl
		case "shift":
			mods |= modShift
		case "alt":
			mods |= modAlt
		case "win", "meta", "super":
			mods |= modWin
		default:
			return 0, 0, fmt.Errorf("hotkey: неизвестный модификатор %q в комбинации %q", p, combo)
		}
	}
	vk, err = parseVK(keyPart)
	if err != nil {
		return 0, 0, err
	}
	if mods == 0 {
		return 0, 0, fmt.Errorf("hotkey: комбинация %q без модификатора (ctrl/shift/alt/win) — "+
			"слишком легко сработает случайно, откажу в регистрации", combo)
	}
	return mods, vk, nil
}

// parseVK — виртуальные коды клавиш (winuser.h): VK_F1..VK_F24 = 0x70..0x87 последовательно,
// VK_A..VK_Z и VK_0..VK_9 совпадают с ASCII-кодами заглавных букв/цифр.
func parseVK(key string) (uint32, error) {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return 0, fmt.Errorf("hotkey: пустая клавиша")
	}
	if strings.HasPrefix(key, "F") && len(key) > 1 {
		if n, e := strconv.Atoi(key[1:]); e == nil && n >= 1 && n <= 24 {
			return uint32(0x70 + (n - 1)), nil
		}
	}
	if len(key) == 1 {
		c := key[0]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return uint32(c), nil
		}
	}
	return 0, fmt.Errorf("hotkey: неподдерживаемая клавиша %q (поддержаны F1-F24, A-Z, 0-9)", key)
}
