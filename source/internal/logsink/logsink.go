// Package logsink — ТЗ v1.3 F5.1 (консилиум 2026-09-03, GAP-37): постоянный лог-файл на
// десктопе и fan-out строк лога движка нескольким получателям.
//
// До этого на ПК лог жил только в памяти (300 строк в web/GUI-буфере) и терялся при закрытии:
// пользователь не мог показать, что происходило «ночью», а разработчик — прочитать. На Android
// файл давно есть (ApfFileLogger, Kotlin) — здесь тот же контракт: ротация по размеру и
// возрасту, фильтр секретов ДО записи.
package logsink

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Multi — fan-out: одна строка уходит всем получателям по порядку; nil пропускаются.
func Multi(sinks ...func(string)) func(string) {
	return func(msg string) {
		for _, s := range sinks {
			if s != nil {
				s(msg)
			}
		}
	}
}

// Секреты в логе (P1-8): пароли/токены/ключи в парах key=value и key: value, учётные данные в
// ссылках узлов (vless://UUID@host, trojan://pw@host, ss://base64@host), base64-тело vmess://,
// а также password=/pbk=/key= в query-строках.
var (
	reKeyValue = regexp.MustCompile(`(?i)\b(password|passwd|passwort|pwd|token|secret|api[_-]?key|apikey|psk|private[_-]?key|master[_-]?password)\b("?\s*[=:]\s*"?)([^\s",;&)]+)`)
	reLinkCred = regexp.MustCompile(`(?i)\b(vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|socks5?|https?)://([^@\s/]+)@`)
	reVmessB64 = regexp.MustCompile(`(?i)\b(vmess)://([A-Za-z0-9+/=_-]{16,})`)
	reQuery    = regexp.MustCompile(`(?i)\b((?:pbk|pass|key|auth)=)([^&\s#]+)`)
)

// Redact маскирует секреты в строке лога. Имена ключей и хосты остаются — по ним лог читается,
// значения заменяются на ***.
func Redact(msg string) string {
	out := reKeyValue.ReplaceAllString(msg, "${1}${2}***")
	out = reLinkCred.ReplaceAllString(out, "${1}://***@")
	out = reVmessB64.ReplaceAllString(out, "${1}://***")
	out = reQuery.ReplaceAllString(out, "${1}***")
	return out
}

// Options — параметры файла лога. Нули → значения по умолчанию.
type Options struct {
	MaxSize    int64         // байт на файл, по умолчанию 2 МБ
	MaxFiles   int           // сколько ротированных файлов хранить (.1….N), по умолчанию 5
	MaxAge     time.Duration // старше — удаляются при ротации/открытии, по умолчанию 72 ч
	FlushEvery time.Duration // сброс bufio по таймеру, по умолчанию 1 с
	Redact     func(string) string
	Now        func() time.Time // для тестов
}

// FileSink — потокобезопасный писатель лог-файла с ротацией.
type FileSink struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	w      *bufio.Writer
	size   int64
	closed bool
	opt    Options
	stop   chan struct{}
	done   chan struct{}
}

// NewFileSink открывает (дописывает) файл path, чистит устаревшие ротации, запускает таймер сброса.
func NewFileSink(path string, opt Options) (*FileSink, error) {
	if opt.MaxSize <= 0 {
		opt.MaxSize = 2 * 1024 * 1024
	}
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = 5
	}
	if opt.MaxAge <= 0 {
		opt.MaxAge = 72 * time.Hour
	}
	if opt.FlushEvery <= 0 {
		opt.FlushEvery = time.Second
	}
	if opt.Redact == nil {
		opt.Redact = Redact
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &FileSink{path: path, opt: opt, stop: make(chan struct{}), done: make(chan struct{})}
	if err := s.openLocked(); err != nil {
		return nil, err
	}
	s.pruneOldLocked()
	go s.flushLoop()
	return s, nil
}

func (s *FileSink) openLocked() error {
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.w, s.size = f, bufio.NewWriterSize(f, 32*1024), st.Size()
	return nil
}

// Write — строка лога с меткой времени; секреты маскируются до записи.
func (s *FileSink) Write(msg string) {
	line := s.opt.Now().Format("2006-01-02 15:04:05.000") + " " + s.opt.Redact(msg) + "\n"
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.w == nil {
		return
	}
	if s.size+int64(len(line)) > s.opt.MaxSize && s.size > 0 {
		if err := s.rotateLocked(); err != nil {
			// Ротация не удалась — продолжаем писать в текущий файл, лог важнее лимита.
			fmt.Fprintf(os.Stderr, "logsink: rotate: %v\n", err)
		}
	}
	n, _ := s.w.WriteString(line)
	s.size += int64(n)
}

// rotateLocked: path → path.1 → … → path.N (старейший удаляется), затем новый пустой path.
func (s *FileSink) rotateLocked() error {
	if s.w != nil {
		s.w.Flush()
	}
	if s.f != nil {
		s.f.Close()
		s.f, s.w = nil, nil
	}
	oldest := s.rotatedName(s.opt.MaxFiles)
	os.Remove(oldest)
	for i := s.opt.MaxFiles - 1; i >= 1; i-- {
		from := s.rotatedName(i)
		if _, err := os.Stat(from); err == nil {
			os.Rename(from, s.rotatedName(i+1))
		}
	}
	if err := os.Rename(s.path, s.rotatedName(1)); err != nil && !os.IsNotExist(err) {
		// Не переименовался (занят?) — усечём на месте, чтобы не расти бесконечно.
		os.Truncate(s.path, 0)
	}
	s.pruneOldLocked()
	return s.openLocked()
}

func (s *FileSink) rotatedName(i int) string { return fmt.Sprintf("%s.%d", s.path, i) }

// pruneOldLocked удаляет ротированные файлы старше MaxAge.
func (s *FileSink) pruneOldLocked() {
	cutoff := s.opt.Now().Add(-s.opt.MaxAge)
	for i := 1; i <= s.opt.MaxFiles+1; i++ {
		name := s.rotatedName(i)
		st, err := os.Stat(name)
		if err != nil {
			continue
		}
		if st.ModTime().Before(cutoff) {
			os.Remove(name)
		}
	}
}

func (s *FileSink) flushLoop() {
	defer close(s.done)
	t := time.NewTicker(s.opt.FlushEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.Flush()
		}
	}
}

// Flush сбрасывает буфер на диск.
func (s *FileSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	return s.w.Flush()
}

// Close останавливает таймер, сбрасывает и закрывает файл. Повторный вызов безопасен.
func (s *FileSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	var err error
	if s.w != nil {
		err = s.w.Flush()
	}
	if s.f != nil {
		if cerr := s.f.Close(); err == nil {
			err = cerr
		}
	}
	s.f, s.w = nil, nil
	s.mu.Unlock()
	<-s.done
	return err
}

// Path — путь текущего файла лога.
func (s *FileSink) Path() string { return s.path }

// Size — текущий размер (с учётом ещё не сброшенного буфера).
func (s *FileSink) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}
