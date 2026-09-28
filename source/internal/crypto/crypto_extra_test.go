package crypto

import (
	"encoding/base64"
	"testing"
)

// TestDecrypt_Base64Error: magic prefix present but non-base64 payload.
func TestDecrypt_Base64Error(t *testing.T) {
	s := New("password")
	raw := append([]byte("APFENC1:"), []byte("not-valid-base64!@#$%^&*()")...)
	_, err := s.Decrypt(raw)
	if err == nil {
		t.Error("expected error: invalid base64 after magic prefix")
	}
	t.Logf("OK: base64 decode error → %v", err)
}

// TestDecrypt_TooShortPayload: decoded payload < 16 bytes (can't hold salt).
func TestDecrypt_TooShortPayload(t *testing.T) {
	s := New("password")
	shortPayload := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	raw := append([]byte("APFENC1:"), []byte(shortPayload)...)
	_, err := s.Decrypt(raw)
	if err == nil {
		t.Error("expected error: payload too short (< 16 bytes)")
	}
	t.Logf("OK: short payload → %v", err)
}

// TestDecrypt_TooShortNonce: exactly 16 bytes (just salt, no room for nonce).
func TestDecrypt_TooShortNonce(t *testing.T) {
	s := New("password")
	justSalt := make([]byte, 16) // salt only, nonce missing
	b64 := base64.StdEncoding.EncodeToString(justSalt)
	raw := append([]byte("APFENC1:"), []byte(b64)...)
	_, err := s.Decrypt(raw)
	if err == nil {
		t.Error("expected error: no room for nonce after 16-byte salt")
	}
	t.Logf("OK: no-nonce error → %v", err)
}

// TestDecrypt_EmptyPassword covers the nil-or-empty-password guard in Decrypt.
func TestDecrypt_EmptyPassword(t *testing.T) {
	s := New("")
	_, err := s.Decrypt([]byte("APFENC1:abc"))
	if err == nil {
		t.Error("expected error for empty password in Decrypt")
	}
}

// TestDecrypt_NilStore covers the nil-Store guard in Decrypt.
func TestDecrypt_NilStore(t *testing.T) {
	var s *Store
	_, err := s.Decrypt([]byte("APFENC1:abc"))
	if err == nil {
		t.Error("expected error for nil Store in Decrypt")
	}
}
