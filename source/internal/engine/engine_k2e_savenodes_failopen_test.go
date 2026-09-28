// engine_k2e_savenodes_failopen_test.go — К2-E П11 (свод C, трек 1 №11; B1 #2, A3).
//
// Дефект: saveNodes при ошибке шифрования молча писал ПЛАЙНТЕКСТ — fail-open. Пользователь
// задал мастер-пароль именно затем, чтобы пул узлов (адреса, UUID, пароли протоколов) не
// лежал на диске открытым; одна ошибка Encrypt — и файл переписывается незашифрованным, без
// единого сигнала наружу (только строка в логе).
package engine

import (
	"os"
	"path/filepath"
	"testing"

	apfcrypto "github.com/apf/adaptive-pathfinder/internal/crypto"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestK2E_SaveNodes_EncryptError_NoPlaintextFallback — при ошибке Encrypt файл не создаётся и
// не перезаписывается, ошибка возвращается вызывающему.
//
// Ошибка шифрования воспроизводится без моков: apfcrypto.New("") — непустой Store с пустым
// паролем, его Encrypt всегда возвращает «master password is empty» (crypto/store.go:78).
func TestK2E_SaveNodes_EncryptError_NoPlaintextFallback(t *testing.T) {
	dir := withTempDataDir(t)
	path := filepath.Join(dir, "nodes_cache.json")

	// В каталоге уже лежит прошлый (корректный) кэш — его нельзя ни затереть, ни подменить
	// плайнтекстом.
	const sentinel = "APFENC1:previous-encrypted-cache"
	if err := os.WriteFile(path, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}

	e := newTestEngine()
	e.cryptoStore = apfcrypto.New("") // Encrypt всегда с ошибкой
	e.mu.Lock()
	e.nodes = []*models.Node{{
		ID: "secret-1", Name: "Секретный", Address: "203.0.113.9", Port: 443,
		Protocol: models.ProtoVLESS, UUID: "11111111-2222-3333-4444-555555555555",
	}}
	e.mu.Unlock()

	err := e.saveNodes()
	if err == nil {
		t.Fatal("saveNodes вернул nil при неудачном шифровании — ошибка не поднята наверх")
	}

	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("прошлый кэш исчез: %v", rerr)
	}
	if string(got) != sentinel {
		t.Fatalf("файл перезаписан при неудачном шифровании (fail-open), содержимое: %q", string(got))
	}
	t.Logf("OK: файл не тронут, ошибка поднята: %v", err)
}

// TestK2E_SaveNodes_EncryptError_NoFileCreated — тот же инвариант, когда кэша ещё нет:
// плайнтекстовый файл не должен появиться вовсе.
func TestK2E_SaveNodes_EncryptError_NoFileCreated(t *testing.T) {
	dir := withTempDataDir(t)
	path := filepath.Join(dir, "nodes_cache.json")

	e := newTestEngine()
	e.cryptoStore = apfcrypto.New("")
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "secret-2", Name: "Секретный-2", Address: "203.0.113.10", Port: 443}}
	e.mu.Unlock()

	if err := e.saveNodes(); err == nil {
		t.Fatal("saveNodes вернул nil при неудачном шифровании")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		data, _ := os.ReadFile(path)
		t.Fatalf("создан незашифрованный кэш вместо отказа: %q (stat err=%v)", string(data), err)
	}
	t.Log("OK: незашифрованный кэш не создан")
}

// TestK2E_SaveNodes_OK_StillWrites — контроль, что фикс не сломал нормальный путь.
func TestK2E_SaveNodes_OK_StillWrites(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "plain-1", Name: "Обычный", Address: "127.0.0.1", Port: 1080}}
	e.mu.Unlock()

	if err := e.saveNodes(); err != nil {
		t.Fatalf("saveNodes без шифрования вернул ошибку: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nodes_cache.json")); err != nil {
		t.Fatalf("кэш не записан: %v", err)
	}
	t.Log("OK: обычный путь сохранения работает")
}
