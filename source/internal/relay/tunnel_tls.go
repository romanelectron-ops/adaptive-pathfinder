// tunnel_tls.go — TLS-транспорт relay-протокола (TZ_RELAY_HARDENING_2026-08-29.md кластер B):
// relay-token (credentials.go) — единственный секрет, защищающий весь relay-протокол, раньше
// уходил в сеть открытым текстом при каждом (пере)подключении control-канала и при КАЖДОМ
// новом STREAM. Модель доверия — pinned-fingerprint TLS, не CA: у самостоятельно поднятого
// relay (cmd/apf-relay, ТЗ §6) в общем случае нет ни домена, ни сертификата от публичного CA,
// а платить за то и другое ради личного/семейного relay избыточно. Та же TOFU-логика, что уже
// принята в проекте для остального (Reality-ключ звена «Выход», exit-id при первой
// EXIT-регистрации): оператор relay один раз показывает отпечаток сертификата, он попадает в
// ссылку (apf_relayfp) и в конфиг «Выхода» (RelayServerFingerprint), обе стороны сверяют его
// при КАЖДОМ TLS-подключении.
package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// certValidityYears — сертификат-идентичность relay, не сертификат обычного веб-сайта с
// коротким циклом продления: его отпечаток — то, что операторы «Входа»/«Выхода» один раз
// вручную закрепляют (pinning). Частая ротация была бы им врагом — сломала бы уже закреплённые
// отпечатки без предупреждения.
const certValidityYears = 10

// relayCertFileName/relayKeyFileName — имена файлов сертификата-идентичности relay на диске.
const (
	relayCertFileName = "relay_cert.pem"
	relayKeyFileName  = "relay_key.pem"
)

// LoadOrGenerateRelayCert — самоподписанный TLS-сертификат identity relay-сервера. Если
// relay_cert.pem/relay_key.pem уже есть в dir — загружает их (стабильный отпечаток между
// перезапусками: иначе оператору пришлось бы каждый раз заново сообщать новый отпечаток всем
// «Выходам»/«Входам»); если нет — генерирует и сохраняет. fingerprint —
// hex(sha256(DER-сертификата)) — то самое значение, которое relay обязан показать оператору
// для распространения (apf_relayfp в ссылке, RelayServerFingerprint в конфиге «Выхода»).
func LoadOrGenerateRelayCert(dir string) (cert tls.Certificate, fingerprint string, err error) {
	certPath := filepath.Join(dir, relayCertFileName)
	keyPath := filepath.Join(dir, relayKeyFileName)

	if certPEM, certErr := os.ReadFile(certPath); certErr == nil {
		if keyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil {
			if loaded, loadErr := tls.X509KeyPair(certPEM, keyPEM); loadErr == nil {
				if fp, fpErr := certFingerprint(loaded); fpErr == nil {
					return loaded, fp, nil
				}
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: генерация ключа TLS-сертификата: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: генерация серийного номера сертификата: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "apf-relay"},
		// NotBefore на час раньше "сейчас" — запас на рассинхрон часов между relay и клиентами
		// (мобильные устройства без точного NTP — обычное дело), иначе свежесозданный
		// сертификат мог бы на короткое время оказаться "ещё не действителен" у клиента с
		// отстающими часами.
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:               time.Now().AddDate(certValidityYears, 0, 0),
		KeyUsage:               x509.KeyUsageDigitalSignature,
		ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: создание сертификата: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: сериализация ключа: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: каталог для сертификата: %w", err)
	}
	if err := os.WriteFile(certPath, certPEMBytes, 0644); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: сохранение сертификата: %w", err)
	}
	// Приватный ключ сертификата — секрет уровня relay-token: 0600, тот же принцип, что
	// EnsureExitCredentials (credentials.go).
	if err := os.WriteFile(keyPath, keyPEMBytes, 0600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: сохранение ключа: %w", err)
	}

	loaded, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("relay: сборка TLS-сертификата: %w", err)
	}
	fp, err := certFingerprint(loaded)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return loaded, fp, nil
}

func certFingerprint(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", errors.New("relay: сертификат пуст")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}

// dialRelayTLS — общий TLS-дозвон для ExitClient и EntryBridge. InsecureSkipVerify стоит
// НАМЕРЕННО: сертификат проверяется САМИ через VerifyPeerCertificate по закреплённому
// отпечатку, не через CA-цепочку (см. комментарий пакета — самоподписанный, без домена).
// fingerprint обязателен: relay с неизвестным отпечатком — не тот relay, которому имеет смысл
// доверить чужой секрет (relay-token) — fail-closed, никакого молчаливого отката на cleartext.
func dialRelayTLS(ctx context.Context, addr, fingerprint string, timeout time.Duration) (net.Conn, error) {
	if fingerprint == "" {
		return nil, errors.New("relay: отпечаток TLS-сертификата relay-сервера не задан — соединение отклонено (переход на нешифрованное подключение не допускается)")
	}
	want := strings.ToLower(strings.TrimSpace(fingerprint))
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("relay: сервер не предъявил сертификат")
				}
				sum := sha256.Sum256(rawCerts[0])
				got := hex.EncodeToString(sum[:])
				if got != want {
					return fmt.Errorf("relay: отпечаток сертификата relay не совпадает с ожидаемым (получен %s, ожидался %s) — возможна подмена/не тот relay", got, want)
				}
				return nil
			},
		},
	}
	return dialer.DialContext(ctx, "tcp", addr)
}
