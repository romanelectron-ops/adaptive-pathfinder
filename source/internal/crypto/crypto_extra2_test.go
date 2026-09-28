package crypto

// crypto_extra2_test.go — covers hard-to-reach error branches via injection:
//   Encrypt: randFillFn error (salt), newCipherFn error, newGCMFn error, randFillFn error (nonce)
//   Decrypt: newCipherFn error, newGCMFn error

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

var errInjected = errors.New("injected error")

func resetCryptoHooks(origRand func([]byte) error, origCipher func([]byte) (cipher.Block, error), origGCM func(cipher.Block) (cipher.AEAD, error)) {
	randFillFn = origRand
	newCipherFn = origCipher
	newGCMFn = origGCM
}

// ─── Encrypt error branches ───────────────────────────────────────────────────

func TestEncrypt_RandFillSaltError(t *testing.T) {
	origRand, origCipher, origGCM := randFillFn, newCipherFn, newGCMFn
	defer resetCryptoHooks(origRand, origCipher, origGCM)

	callCount := 0
	randFillFn = func(b []byte) error {
		callCount++
		if callCount == 1 {
			return errInjected // fail on first call (salt)
		}
		return origRand(b)
	}

	s := New("password")
	_, err := s.Encrypt([]byte("plaintext"))
	if err == nil {
		t.Error("expected error from salt randFill injection")
	}
	t.Logf("OK: Encrypt randFill(salt) error → %v", err)
}

func TestEncrypt_NewCipherError(t *testing.T) {
	origRand, origCipher, origGCM := randFillFn, newCipherFn, newGCMFn
	defer resetCryptoHooks(origRand, origCipher, origGCM)

	newCipherFn = func(key []byte) (cipher.Block, error) {
		return nil, errInjected
	}

	s := New("password")
	_, err := s.Encrypt([]byte("plaintext"))
	if err == nil {
		t.Error("expected error from newCipher injection")
	}
	t.Logf("OK: Encrypt newCipher error → %v", err)
}

func TestEncrypt_NewGCMError(t *testing.T) {
	origRand, origCipher, origGCM := randFillFn, newCipherFn, newGCMFn
	defer resetCryptoHooks(origRand, origCipher, origGCM)

	newGCMFn = func(block cipher.Block) (cipher.AEAD, error) {
		return nil, errInjected
	}

	s := New("password")
	_, err := s.Encrypt([]byte("plaintext"))
	if err == nil {
		t.Error("expected error from newGCM injection")
	}
	t.Logf("OK: Encrypt newGCM error → %v", err)
}

func TestEncrypt_RandFillNonceError(t *testing.T) {
	origRand, origCipher, origGCM := randFillFn, newCipherFn, newGCMFn
	defer resetCryptoHooks(origRand, origCipher, origGCM)

	callCount := 0
	randFillFn = func(b []byte) error {
		callCount++
		if callCount == 2 {
			return errInjected // fail on second call (nonce)
		}
		return origRand(b)
	}

	s := New("password")
	_, err := s.Encrypt([]byte("plaintext"))
	if err == nil {
		t.Error("expected error from nonce randFill injection")
	}
	t.Logf("OK: Encrypt randFill(nonce) error → %v", err)
}

// ─── Decrypt error branches ───────────────────────────────────────────────────

func TestDecrypt_NewCipherError(t *testing.T) {
	origRand, origCipher, origGCM := randFillFn, newCipherFn, newGCMFn
	defer resetCryptoHooks(origRand, origCipher, origGCM)

	// First encrypt normally to get valid ciphertext
	s := New("password")
	ct, err := s.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Now inject cipher failure on Decrypt
	newCipherFn = func(key []byte) (cipher.Block, error) {
		return nil, errInjected
	}

	_, err = s.Decrypt(ct)
	if err == nil {
		t.Error("expected error from newCipher injection in Decrypt")
	}
	t.Logf("OK: Decrypt newCipher error → %v", err)
}

func TestDecrypt_NewGCMError(t *testing.T) {
	origRand, origCipher, origGCM := randFillFn, newCipherFn, newGCMFn
	defer resetCryptoHooks(origRand, origCipher, origGCM)

	// Encrypt normally first
	s := New("password")
	ct, err := s.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Restore cipher but inject GCM failure
	newGCMFn = func(block cipher.Block) (cipher.AEAD, error) {
		return nil, errInjected
	}

	_, err = s.Decrypt(ct)
	if err == nil {
		t.Error("expected error from newGCM injection in Decrypt")
	}
	t.Logf("OK: Decrypt newGCM error → %v", err)
}

// ─── Sanity check: real aes.NewCipher and cipher.NewGCM still work ──────────

func TestCryptoHooks_Sanity(t *testing.T) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	_, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	t.Log("OK: real aes+gcm sanity check")
}
