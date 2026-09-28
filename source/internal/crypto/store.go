package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

var (
	encMagic = []byte("APFENC1:")
)

// Injection hooks for testing hard-to-reach error branches.
var (
	randFillFn  = func(b []byte) error { _, err := io.ReadFull(rand.Reader, b); return err }
	newCipherFn = aes.NewCipher
	newGCMFn    = cipher.NewGCM
)

// Store обеспечивает шифрование/дешифрование данных.
type Store struct {
	password string

	// P1 (аудит 2026-09-01, security-раздел, LOW находка №24): PBKDF2 (600 000 итераций,
	// ~0.3-0.5с) раньше пересчитывался на КАЖДЫЙ Encrypt/Decrypt. Store живёт всю сессию
	// движка (engine.cryptoStore) и его Encrypt/Decrypt вызываются многократно за сессию
	// (saveNodes — на каждое изменение пула узлов) — без кэша это заметный, накапливающийся
	// тормоз ради работы, которую достаточно сделать один раз на пароль+соль.
	mu sync.Mutex

	// encSalt/encKey — соль и производный ключ для ШИФРОВАНИЯ, сгенерированные ОДИН РАЗ при
	// первом Encrypt этого Store и переиспользуемые для всех последующих. Криптографически
	// это ничем не отличается от разной соли на каждый вызов: соль в PBKDF2 защищает от
	// радужных таблиц атаки на ПАРОЛЬ, а не действует как nonce — уникальность, которая
	// действительно обязана быть на КАЖДОЕ шифрование, обеспечивает GCM-нонс (randFillFn(nonce)
	// ниже, свежий на каждый Encrypt) и остаётся такой же, как была.
	encSalt []byte
	encKey  []byte

	// decSalt/decKey — однослотовый кэш для ДЕШИФРОВАНИЯ: если очередной Decrypt получает ТУ
	// ЖЕ соль, что и в прошлый раз (типичный случай — повторное чтение того же файла в одной
	// сессии), ключ не пересчитывается. Соль ВСЕГДА берётся из самого шифртекста (см. Decrypt)
	// — кэш не подменяет и не угадывает её, только избегает повторной дорогой деривации ДЛЯ
	// УЖЕ ВИДЕННОЙ соли.
	decSalt []byte
	decKey  []byte
}

// New создаёт хранилище шифрования с мастер-паролем.
func New(password string) *Store {
	return &Store{password: password}
}

// IsEncrypted проверяет сигнатуру зашифрованного контента.
func IsEncrypted(raw []byte) bool {
	if len(raw) < len(encMagic) {
		return false
	}
	for i := range encMagic {
		if raw[i] != encMagic[i] {
			return false
		}
	}
	return true
}

// Encrypt шифрует данные в формат:
// APFENC1:<base64(salt|nonce|ciphertext)>
func (s *Store) Encrypt(plain []byte) ([]byte, error) {
	if s == nil || s.password == "" {
		return nil, errors.New("master password is empty")
	}

	salt, key, err := s.encryptionKey()
	if err != nil {
		return nil, err
	}

	block, err := newCipherFn(key)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCMFn(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if err := randFillFn(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, len(encMagic)+((len(salt)+len(nonce)+len(ciphertext))*2))
	out = append(out, encMagic...)
	payload := append(append(salt, nonce...), ciphertext...)
	out = append(out, []byte(base64.StdEncoding.EncodeToString(payload))...)
	return out, nil
}

// Decrypt расшифровывает формат, созданный Encrypt.
func (s *Store) Decrypt(raw []byte) ([]byte, error) {
	if s == nil || s.password == "" {
		return nil, errors.New("master password is empty")
	}
	if !IsEncrypted(raw) {
		return nil, errors.New("data is not encrypted")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(raw[len(encMagic):]))
	if err != nil {
		return nil, err
	}
	if len(decoded) < 16 {
		return nil, errors.New("invalid encrypted payload")
	}

	salt := decoded[:16]
	key := s.decryptionKey(salt)

	block, err := newCipherFn(key)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCMFn(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(decoded) < 16+nonceSize {
		return nil, errors.New("invalid encrypted nonce")
	}

	nonce := decoded[16 : 16+nonceSize]
	ciphertext := decoded[16+nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// encryptionKey возвращает соль и производный ключ для ШИФРОВАНИЯ — генерирует соль и
// дериватирует ключ ОДИН РАЗ за время жизни Store (см. doc-comment полей encSalt/encKey),
// дальше отдаёт закэшированные значения. Возвращает КОПИЮ соли: Encrypt делает
// append(salt, nonce...), и кэш внутри Store не должен зависеть от того, как вызывающая
// сторона распорядится возвращённым срезом.
func (s *Store) encryptionKey() (salt []byte, key []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.encKey == nil {
		newSalt := make([]byte, 16)
		if err := randFillFn(newSalt); err != nil {
			return nil, nil, err
		}
		s.encSalt = newSalt
		s.encKey = deriveKey(s.password, newSalt)
	}
	saltCopy := make([]byte, len(s.encSalt))
	copy(saltCopy, s.encSalt)
	return saltCopy, s.encKey, nil
}

// decryptionKey возвращает производный ключ для ДЕШИФРОВАНИЯ по соли, прочитанной из
// конкретного шифртекста (см. doc-comment полей decSalt/decKey) — однослотовый кэш: та же
// соль, что и в прошлый вызов, отдаёт закэшированный ключ без повторного PBKDF2; другая
// соль (например, файл был перезашифрован с новым Store в другой сессии — или это первый
// вызов) — пересчитывает и заменяет кэш.
func (s *Store) decryptionKey(salt []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decKey != nil && bytes.Equal(s.decSalt, salt) {
		return s.decKey
	}
	key := deriveKey(s.password, salt)
	s.decSalt = append([]byte(nil), salt...) // копия: salt указывает на буфер вызывающей стороны
	s.decKey = key
	return key
}

func deriveKey(password string, salt []byte) []byte {
	// PBKDF2-600k как заявлено в документации фазы 5.
	return pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
}
