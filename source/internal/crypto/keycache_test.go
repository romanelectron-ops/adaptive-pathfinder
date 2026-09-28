package crypto

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
)

// keycache_test.go — P1 (аудит 2026-09-01, security-раздел, LOW находка №24): PBKDF2
// (600 000 итераций) раньше пересчитывался на КАЖДЫЙ Encrypt/Decrypt. Store живёт всю сессию
// движка и вызывается многократно (saveNodes — на каждое изменение пула узлов) — кэшируем
// производный ключ на время жизни Store. Эти тесты проверяют, что кэш не меняет НАБЛЮДАЕМОЕ
// поведение (корректность шифрования/дешифрования), только его скорость.

func extractSalt(t *testing.T, enc []byte) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(string(enc[len(encMagic):]))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) < 16 {
		t.Fatalf("payload too short for salt: %d bytes", len(decoded))
	}
	return decoded[:16]
}

// Один Store, много Encrypt — соль стабильна (кэш сработал), но каждый шифртекст всё равно
// уникален благодаря свежему GCM-нонсу на каждый вызов (randFillFn(nonce) не тронут этой
// правкой) — TestEncrypt_Deterministic_False рядом уже проверяет это свойство отдельно.
func TestEncrypt_SameStore_ReusesSaltAcrossCalls(t *testing.T) {
	s := New("cache-test-password")
	plain := []byte("payload")

	enc1, err := s.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	enc2, err := s.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	salt1 := extractSalt(t, enc1)
	salt2 := extractSalt(t, enc2)
	if string(salt1) != string(salt2) {
		t.Error("соль должна быть одинаковой для повторных Encrypt на ОДНОМ Store " +
			"(кэш ключа) — вместо этого сгенерирована заново")
	}

	// И оба шифртекста всё равно корректно расшифровываются тем же Store.
	dec1, err := s.Decrypt(enc1)
	if err != nil || string(dec1) != string(plain) {
		t.Errorf("Decrypt(enc1) = %q, %v — round-trip сломан", dec1, err)
	}
	dec2, err := s.Decrypt(enc2)
	if err != nil || string(dec2) != string(plain) {
		t.Errorf("Decrypt(enc2) = %q, %v — round-trip сломан", dec2, err)
	}
}

// Разные Store (как при перезапуске приложения — engine.SetMasterPassword создаёт новый
// apfcrypto.Store) — соль обязана быть РАЗНОЙ, кэш не должен ничего разделять между
// независимыми экземплярами.
func TestEncrypt_DifferentStores_DifferentSalt(t *testing.T) {
	s1 := New("same-password")
	s2 := New("same-password")

	enc1, err := s1.Encrypt([]byte("x"))
	if err != nil {
		t.Fatalf("Encrypt s1: %v", err)
	}
	enc2, err := s2.Encrypt([]byte("x"))
	if err != nil {
		t.Fatalf("Encrypt s2: %v", err)
	}

	if string(extractSalt(t, enc1)) == string(extractSalt(t, enc2)) {
		t.Error("два независимых Store совпали по соли — вероятность коллизии " +
			"16-байтной случайной соли пренебрежимо мала, это баг генерации, не совпадение")
	}
}

// Decrypt читает соль ИЗ ШИФРТЕКСТА, а не из своего кэша шифрования — Store, который
// расшифровывает файл, зашифрованный ДРУГИМ Store (другая соль), обязан пересчитать ключ
// для этой соли, а не ошибочно переиспользовать кэш от собственного Encrypt.
func TestDecrypt_DifferentSaltThanOwnEncryptCache_StillWorks(t *testing.T) {
	writer := New("shared-password")
	enc, err := writer.Encrypt([]byte("written by a different Store"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	reader := New("shared-password")
	// Прогреваем ЧУЖОЙ кэш шифрования reader'а собственным Encrypt — своя соль ТОЧНО не
	// совпадёт с той, что использовал writer (см. предыдущий тест).
	if _, err := reader.Encrypt([]byte("reader's own data, unrelated")); err != nil {
		t.Fatalf("reader.Encrypt: %v", err)
	}

	dec, err := reader.Decrypt(enc)
	if err != nil {
		t.Fatalf("reader.Decrypt(writer's blob): %v — decryptionKey не должен был "+
			"путать соль записи с собственным кэшем шифрования reader'а", err)
	}
	if string(dec) != "written by a different Store" {
		t.Errorf("Decrypt = %q, ожидался исходный текст", dec)
	}
}

// Повторный Decrypt ОДНОГО И ТОГО ЖЕ шифртекста — однослотовый кэш дешифрования должен
// сработать (та же соль дважды подряд), результат при этом обязан остаться корректным.
func TestDecrypt_SameBlobTwice_CacheHit_StillCorrect(t *testing.T) {
	s := New("repeat-decrypt-password")
	enc, err := s.Encrypt([]byte("decrypt me twice"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for i := 0; i < 2; i++ {
		dec, err := s.Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt попытка %d: %v", i+1, err)
		}
		if string(dec) != "decrypt me twice" {
			t.Errorf("Decrypt попытка %d = %q, ожидался исходный текст", i+1, dec)
		}
	}
}

// Неверный пароль остаётся неверным независимо от того, что кэш ключа уже прогрет тем же
// Store для правильного пароля другого экземпляра — то есть кэш не может случайно
// "авторизовать" чужой пароль.
func TestDecrypt_WrongPassword_StillFailsWithCache(t *testing.T) {
	right := New("right-password")
	enc, err := right.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrong := New("wrong-password")
	if _, err := wrong.Decrypt(enc); err == nil {
		t.Error("Decrypt с неверным паролем должен провалиться (GCM authentication tag)")
	}
}

// engine.cryptoStore — общий *Store, к которому обращаются несколько горутин
// (saveNodes на изменение пула узлов, конкурентные чтения конфига). Кэш ключа
// (encKey/decKey/encSalt/decSalt) защищён s.mu — проверяем -race, что
// одновременные Encrypt/Decrypt на одном Store не гонятся за этими полями и
// каждый round-trip остаётся корректным.
func TestStore_ConcurrentEncryptDecrypt_NoRace(t *testing.T) {
	s := New("concurrent-password")
	const n = 20

	var wg sync.WaitGroup
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			plain := []byte("payload-" + string(rune('a'+i%26)))
			enc, err := s.Encrypt(plain)
			if err != nil {
				errs <- err
				return
			}
			dec, err := s.Decrypt(enc)
			if err != nil {
				errs <- err
				return
			}
			if string(dec) != string(plain) {
				errs <- fmt.Errorf("round-trip mismatch: got %q want %q", dec, plain)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
