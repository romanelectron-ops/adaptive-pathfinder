// Package checker: safety filter для узлов
// Фильтрует узлы которые могут использоваться для нелегальной деятельности
// или несут риск для пользователя
package checker

import (
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// SafetyFilter проверяет узел на безопасность использования
type SafetyFilter struct{}

// NewSafetyFilter создаёт фильтр
func NewSafetyFilter() *SafetyFilter {
	return &SafetyFilter{}
}

// IsSafe возвращает true если узел подходит для безопасного использования
// Цель: только обход географических блокировок (Instagram, Telegram, AI сервисы)
// НЕ для анонимизации преступной деятельности
func (f *SafetyFilter) IsSafe(node *models.Node) bool {
	name := strings.ToLower(node.Name)
	addr := strings.ToLower(node.Address)

	// Блокируем узлы с явными признаками высокорискованного использования
	// (ботнеты, exit-ноды даркнета, скомпрометированные хосты)
	blockedKeywords := []string{
		"tor exit", // Tor exit node - высокий риск
		"botnet",   // ботнет
		"cracked",  // взломанный
		"hacked",   // взломанный
		"spam",     // спам
		"abuse",    // известный abuse
		"ddos",     // DDoS
		"malware",  // малварь
	}
	for _, kw := range blockedKeywords {
		if strings.Contains(name, kw) || strings.Contains(addr, kw) {
			return false
		}
	}

	// Узлы в диапазонах известных дата-центров хостеров - ОК
	// Это Cloudflare, Amazon, Google, Microsoft CDN и т.д.
	// Они НЕ используются как exit nodes для криминала
	trustedPrefixes := []string{
		"cdn", "cloudflare", "amazon", "google", "microsoft",
		"azure", "fastly", "akamai", "hetzner", "vultr",
		"digitalocean", "linode", "ovh",
	}
	for _, prefix := range trustedPrefixes {
		if strings.Contains(addr, prefix) || strings.Contains(name, prefix) {
			return true // явно доверенный
		}
	}

	// Все остальные узлы - пропускаем (не блокируем)
	// У нас нет возможности точно определить "криминальный" узел
	// без чёрного списка IP. Основная защита - не поддерживать анонимность
	// а только обходить географические блокировки через прозрачный прокси.
	return true
}

// FilterSafe возвращает только безопасные узлы из списка
func (f *SafetyFilter) FilterSafe(nodes []*models.Node) []*models.Node {
	var safe []*models.Node
	for _, n := range nodes {
		if f.IsSafe(n) {
			safe = append(safe, n)
		}
	}
	return safe
}

// IsTrustedProtocol проверяет что протокол подходит для обычного использования
// VLESS/VMess/SS/Trojan - нормальные прокси протоколы
// Tor - только как последний резерв (медленный)
func IsTrustedProtocol(p models.Protocol) bool {
	switch p {
	case models.ProtoVLESS, models.ProtoVMess, models.ProtoShadowsocks, models.ProtoTrojan:
		return true
	case models.ProtoWireGuard:
		return true // быстрый и прозрачный
	case models.ProtoTor:
		return false // только как fallback, не для обычного использования
	default:
		return false
	}
}
