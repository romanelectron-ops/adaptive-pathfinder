package crypto

import (
	"bytes"
	"testing"
)

func TestNew_NotNil(t *testing.T) {
	s := New("mypassword123")
	if s == nil {
		t.Fatal("New() returned nil")
	}
}

func TestIsEncrypted_False_PlainData(t *testing.T) {
	plain := []byte(`{"nodes": []}`)
	if IsEncrypted(plain) {
		t.Error("plain JSON should not be detected as encrypted")
	}
}

func TestIsEncrypted_False_EmptyData(t *testing.T) {
	if IsEncrypted([]byte{}) {
		t.Error("empty data should not be detected as encrypted")
	}
	if IsEncrypted(nil) {
		t.Error("nil data should not be detected as encrypted")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	s := New("test-master-password-123")
	plain := []byte(`{"nodes": [{"id": "test", "name": "Test Node"}]}`)

	encrypted, err := s.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encrypted == nil {
		t.Fatal("Encrypt() returned nil")
	}
	if bytes.Equal(plain, encrypted) {
		t.Error("encrypted data should differ from plaintext")
	}

	// Проверяем что IsEncrypted правильно детектирует
	if !IsEncrypted(encrypted) {
		t.Error("encrypted data should be detected by IsEncrypted()")
	}

	// Расшифровываем
	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if !bytes.Equal(plain, decrypted) {
		t.Errorf("decrypted data mismatch:\ngot:  %s\nwant: %s", decrypted, plain)
	}
}

func TestEncrypt_EmptyPassword(t *testing.T) {
	s := New("")
	_, err := s.Encrypt([]byte("some data"))
	if err == nil {
		t.Error("Encrypt with empty password should return error")
	}
}

func TestEncrypt_NilStore(t *testing.T) {
	var s *Store
	_, err := s.Encrypt([]byte("data"))
	if err == nil {
		t.Error("Encrypt on nil Store should return error")
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	s1 := New("correct-password-123")
	plain := []byte("secret data")
	encrypted, err := s1.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Пробуем расшифровать с неправильным паролем
	s2 := New("wrong-password-456")
	_, err = s2.Decrypt(encrypted)
	if err == nil {
		t.Error("Decrypt with wrong password should fail")
	}
}

func TestDecrypt_NotEncrypted(t *testing.T) {
	s := New("password123")
	_, err := s.Decrypt([]byte("not encrypted data"))
	if err == nil {
		t.Error("Decrypt of non-encrypted data should fail")
	}
}

func TestEncrypt_Deterministic_False(t *testing.T) {
	// Каждый вызов Encrypt должен давать разный результат (случайный salt + nonce)
	s := New("same-password-123")
	plain := []byte("same plaintext")

	enc1, err := s.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}
	enc2, err := s.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions of same data should produce different ciphertext (due to random salt/nonce)")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	s := New("password123")
	enc, err := s.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty plaintext failed: %v", err)
	}
	dec, err := s.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt empty plaintext failed: %v", err)
	}
	if len(dec) != 0 {
		t.Errorf("decrypted empty should be empty, got %d bytes", len(dec))
	}
}
