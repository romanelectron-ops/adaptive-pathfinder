package harvester

// sanitize.go — санитайзер секретов (AI-5): ни один секрет УЖЕ ИЗВЕСТНОГО узла не имеет права
// уйти в модель, и ни одна ссылка узла (известная или нет) не имеет права осесть в логе.
//
// Два разных потребителя — поэтому два разных механизма:
//   Secrets        — точечная вырезка КОНКРЕТНЫХ значений (UUID/пароль/ключ) перед промптом.
//   SanitizeForLog — грубая вырезка ЛЮБОЙ ссылки узла целиком перед записью в лог/отчёт.

import (
	"sort"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Redacted — чем заменяется вырезанный секрет.
const Redacted = "[REDACTED]"

// minSecretLen — короче этого не считается секретом (иначе "123" резало бы весь текст).
const minSecretLen = 6

// genericValues — публичные, не секретные значения, которые тем не менее длиннее minSecretLen
// (имена алгоритмов, общеупотребительные слова). Без этого списка санитайзер резал бы
// "aes-256-gcm" или "password", встреченные в тексте источника по совершенно другому поводу.
var genericValues = map[string]bool{
	"password": true, "admin": true, "none": true, "auto": true, "default": true,
	"aes-256-gcm": true, "aes-128-gcm": true, "aes-192-gcm": true,
	"chacha20-ietf-poly1305": true, "chacha20-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"rc4-md5": true, "tcp": true, "udp": true, "ws": true, "grpc": true, "tls": true, "http": true,
}

// Secrets — набор известных секретов, отсортированный по убыванию длины (TestSanitizeLongestSecretFirst):
// длинный секрет обязан вырезаться раньше своего же префикса, иначе останется читаемый хвост.
type Secrets struct {
	values []string
}

// SecretsFromNodes собирает секреты из уже известных узлов пула. nil-элементы среза
// пропускаются молча (пул может содержать их после частичной десериализации).
func SecretsFromNodes(nodes []*models.Node) *Secrets {
	seen := map[string]bool{}
	var vals []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if len(v) < minSecretLen {
			return
		}
		if genericValues[strings.ToLower(v)] {
			return
		}
		if seen[v] {
			return
		}
		seen[v] = true
		vals = append(vals, v)
	}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		add(n.UUID)
		add(n.Password)
		add(n.Method)
		add(n.WGPrivateKey)
		add(n.WGPublicKey)
		if n.TLS != nil && n.TLS.Reality != nil {
			add(n.TLS.Reality.PublicKey)
			add(n.TLS.Reality.ShortID)
		}
	}
	sort.SliceStable(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	return &Secrets{values: vals}
}

// Len — сколько секретов собрано. nil-приёмник — валидный вход (секретов нет).
func (s *Secrets) Len() int {
	if s == nil {
		return 0
	}
	return len(s.values)
}

// Sanitize заменяет каждое известное секретное значение на Redacted. Порядок замены —
// от самого длинного секрета к самому короткому (см. комментарий у Secrets).
func (s *Secrets) Sanitize(text string) string {
	if s == nil {
		return text
	}
	for _, v := range s.values {
		if v == "" {
			continue
		}
		text = strings.ReplaceAll(text, v, Redacted)
	}
	return text
}

// Leaks — если в text всё ещё есть подстрока-секрет, возвращает её (для тестов/самопроверки).
func (s *Secrets) Leaks(text string) (string, bool) {
	if s == nil {
		return "", false
	}
	for _, v := range s.values {
		if v != "" && strings.Contains(text, v) {
			return v, true
		}
	}
	return "", false
}

// SanitizeForLog вырезает из строки ЛЮБУЮ ссылку узла целиком — не только известные секреты.
// Нужна для отчётов/логов (AI-5, "санитайзер логов"): туда не должно попасть и то, что мы ещё
// не знаем, а не только то, что уже в пуле.
func SanitizeForLog(line string) string {
	for _, re := range schemeRegexes {
		line = re.ReplaceAllString(line, Redacted)
	}
	return line
}
