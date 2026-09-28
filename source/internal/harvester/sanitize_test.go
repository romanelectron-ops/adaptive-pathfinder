package harvester

// Тесты санитайзера (AI-5). Критерий приёмки лота: «ни один секрет узла не попадает в
// промпт (тест на подстроки)».

import (
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func knownNodesForTest() []*models.Node {
	return []*models.Node{
		{
			ID: "n1", Protocol: models.ProtoVLESS, Address: "node-a.invalid", Port: 443,
			UUID: "11111111-2222-3333-4444-555555555555",
			TLS: &models.TLSConfig{Enabled: true, ServerName: "addons.mozilla.org",
				Reality: &models.RealityConfig{PublicKey: "TESTPBKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "0123abcd"}},
		},
		{ID: "n2", Protocol: models.ProtoTrojan, Address: "node-b.invalid", Port: 8443, Password: "TROJANPASS0001"},
		{ID: "n3", Protocol: models.ProtoWireGuard, Address: "node-w.invalid", Port: 51820,
			WGPrivateKey: "PRIVATEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		nil, // nil-элемент не должен ронять сборку секретов
		{ID: "n4", Password: "123"}, // слишком короткий — не секрет, иначе резали бы всё подряд
	}
}

// Главный тест приёмки: после санитайзера в тексте, который уйдёт в модель, нет НИ ОДНОЙ
// подстроки-секрета известных узлов.
func TestSanitizeRemovesAllKnownSecrets(t *testing.T) {
	secrets := SecretsFromNodes(knownNodesForTest())
	body := string(readSample(t, "telegram_post.html")) +
		"\nещё раз пароль TROJANPASS0001 и ключ PRIVATEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"

	clean := secrets.Sanitize(body)

	for _, secret := range []string{
		"11111111-2222-3333-4444-555555555555",
		"TROJANPASS0001",
		"PRIVATEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"TESTPBKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if strings.Contains(clean, secret) {
			t.Errorf("секрет %q остался в тексте для модели", secret)
		}
	}
	if leaked, ok := secrets.Leaks(clean); ok {
		t.Errorf("Leaks нашёл утечку после санитайзера: %q", leaked)
	}
	if !strings.Contains(clean, Redacted) {
		t.Error("замена не выполнена вовсе")
	}
	// Полезный текст при этом остаётся: санитайзер не должен превращать страницу в кашу.
	if !strings.Contains(clean, "node-a.invalid") {
		t.Error("санитайзер выбросил безопасный текст (адрес узла)")
	}
}

func TestSanitizeShortAndGenericValuesNotRedacted(t *testing.T) {
	secrets := SecretsFromNodes([]*models.Node{
		{ID: "a", Password: "123"},
		{ID: "b", Password: "password"},
		{ID: "c", Password: "aes-256-gcm"},
		{ID: "d", Method: "chacha20-ietf-poly1305"},
	})
	text := "123 password aes-256-gcm chacha20-ietf-poly1305 и обычный текст"
	if got := secrets.Sanitize(text); got != text {
		t.Errorf("короткие и общеупотребительные значения не должны вырезаться: %q", got)
	}
}

// Длинный секрет обязан заменяться раньше короткого — иначе короткий разорвал бы длинный
// и его остаток утёк бы в промпт.
func TestSanitizeLongestSecretFirst(t *testing.T) {
	secrets := SecretsFromNodes([]*models.Node{
		{ID: "a", Password: "SECRETPART"},
		{ID: "b", Password: "SECRETPARTLONGERTAIL"},
	})
	clean := secrets.Sanitize("значение SECRETPARTLONGERTAIL здесь")
	if strings.Contains(clean, "LONGERTAIL") {
		t.Errorf("остаток длинного секрета утёк: %q", clean)
	}
}

func TestNilSecretsSafe(t *testing.T) {
	var s *Secrets
	if got := s.Sanitize("текст"); got != "текст" {
		t.Errorf("nil-Secrets должен работать как «секретов нет», получено %q", got)
	}
	if _, ok := s.Leaks("текст"); ok {
		t.Error("nil-Secrets не может ничего находить")
	}
	if SecretsFromNodes(nil).Len() != 0 {
		t.Error("из nil-узлов секретов быть не может")
	}
}

// Санитайзер лога режет ЛЮБУЮ ссылку узла, а не только известные секреты: в лог не должно
// попасть и то, что мы ещё не знаем (AI-5, слой «санитайзер логов»).
func TestSanitizeForLogHidesAnyNodeURI(t *testing.T) {
	line := "нашёл vless://11111111-2222-3333-4444-555555555555@h.invalid:443#x и " +
		"ss://YWVzOnBhc3N3b3Jk@h2.invalid:8388#y — всего 2"
	got := SanitizeForLog(line)
	for _, must := range []string{"11111111-2222", "YWVzOnBhc3N3b3Jk", "h.invalid", "h2.invalid"} {
		if strings.Contains(got, must) {
			t.Errorf("в лог утекла часть ссылки %q: %q", must, got)
		}
	}
	if !strings.Contains(got, "всего 2") {
		t.Errorf("счётчики в логе должны сохраняться: %q", got)
	}
}
