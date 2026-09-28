// logsink_test.go — ТЗ v1.3 F5.1: ротация по размеру/возрасту, секреты не попадают в файл,
// fan-out, сброс при закрытии, конкурентная запись (-race).
package logsink

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRedact_Table(t *testing.T) {
	cases := map[string]string{
		"password=s3cr3t rest":                    "password=*** rest",
		`ShadowTLS: {"password":"abc","sni":"x"}`: `ShadowTLS: {"password":"***","sni":"x"}`,
		"token: eyJhbGciOi.xxx":                   "token: ***",
		"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls#N": "vless://***@1.2.3.4:443?security=tls#N",
		"trojan://mypw@host.example:443":                                          "trojan://***@host.example:443",
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@10.0.0.1:8388":                         "ss://***@10.0.0.1:8388",
		"vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCJ9":                                    "vmess://***",
		"reality pbk=abcdef123456&sid=12 ok":                                      "reality pbk=***&sid=12 ok",
		"api_key=XYZ; psk: 123":                                                   "api_key=***; psk: ***",
		"bypass rule for gosuslugi.ru":                                            "bypass rule for gosuslugi.ru", // «pass» внутри слова — не секрет
		"Node connected latency=120ms":                                            "Node connected latency=120ms",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}

func TestMulti_FanOut(t *testing.T) {
	var a, b []string
	m := Multi(func(s string) { a = append(a, s) }, nil, func(s string) { b = append(b, s) })
	m("x")
	m("y")
	if len(a) != 2 || len(b) != 2 || a[1] != "y" {
		t.Errorf("fan-out: a=%v b=%v", a, b)
	}
}

func TestFileSink_RotatesBySizeAndKeepsMaxFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apf.log")
	s, err := NewFileSink(path, Options{MaxSize: 300, MaxFiles: 3, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		s.Write(strings.Repeat("x", 40) + " line")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"apf.log", "apf.log.1", "apf.log.2", "apf.log.3"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s должен существовать: %v", name, err)
			continue
		}
		if st.Size() > 400 {
			t.Errorf("%s больше лимита: %d", name, st.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "apf.log.4")); err == nil {
		t.Error("apf.log.4 не должен существовать (MaxFiles=3)")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), " line") || !strings.Contains(string(data), "20") {
		t.Errorf("текущий файл должен содержать строки с меткой времени: %q", string(data))
	}
}

func TestFileSink_PrunesOldRotationsOnOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apf.log")
	old := path + ".1"
	os.WriteFile(old, []byte("old"), 0600)
	oldTime := time.Now().Add(-100 * time.Hour)
	os.Chtimes(old, oldTime, oldTime)
	fresh := path + ".2"
	os.WriteFile(fresh, []byte("fresh"), 0600)

	s, err := NewFileSink(path, Options{MaxAge: 72 * time.Hour, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(old); err == nil {
		t.Error("ротация старше 72 ч должна удаляться при открытии")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("свежая ротация должна остаться")
	}
}

func TestFileSink_FlushOnCloseAndSecretsNotOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apf.log")
	s, err := NewFileSink(path, Options{FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.Write("connecting vless://deadbeef-uuid@srv.example:443 password=hunter2")
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("до Flush/Close буфер не должен быть на диске (bufio), got %q", data)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	if strings.Contains(text, "deadbeef-uuid") || strings.Contains(text, "hunter2") {
		t.Errorf("секреты попали в файл: %q", text)
	}
	if !strings.Contains(text, "vless://***@srv.example:443") || !strings.Contains(text, "password=***") {
		t.Errorf("ожидалась маскированная строка: %q", text)
	}
	s.Write("after close") // no-op, без паники
	if err := s.Close(); err != nil {
		t.Errorf("повторный Close: %v", err)
	}
}

func TestFileSink_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSink(filepath.Join(dir, "apf.log"), Options{MaxSize: 2000, MaxFiles: 2, FlushEvery: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.Write("goroutine " + string(rune('a'+g)) + " message with some padding text")
			}
		}(g)
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Size() < 0 {
		t.Error("size")
	}
}
