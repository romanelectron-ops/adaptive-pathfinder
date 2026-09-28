// Package iprep проверяет репутацию IP-адреса через публичные API.
// Sprint S6: Anti-VPN-Block — определяем residential vs datacenter.
//
// Цель: не быть заблокированным сайтами (Netflix, банки, стриминг),
// которые блокируют datacenter/VPN IP. Решение — использовать узлы
// с residential IP (обычные ISP-адреса, не хостинговые).
package iprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// ipAPIBaseURL and proxyCheckBaseURL are injection hooks for testing.
//
// К2-E П15 (свод C трек 1 №15; B1 #4): ip-api опрашивался по http://. В запросе идёт IP
// ПРОВЕРЯЕМОГО УЗЛА, а в ответе — вердикт о нём; открытым текстом это читает любой на пути,
// включая того самого провайдера, от которого пользователь и прячется, — и получает готовый
// список адресов, которыми тот собирается пользоваться.
//
// Оговорка честности: бесплатный тариф ip-api.com формально HTTPS не обслуживает, поэтому
// запрос может отвечать отказом. Это приемлемо и безопасно: CheckIP при неудаче переходит на
// proxycheck.io, а если и он молчит — возвращает «unknown» без ошибки (репутация IP не
// обязательна для подключения). Утечка списка узлов в открытом виде хуже, чем отсутствие
// метки residential/datacenter.
var ipAPIBaseURL = "https://ip-api.com"
var proxyCheckBaseURL = "https://proxycheck.io"

// bodyLimitBytes — потолок на тело ответа обоих публичных API (К2-E П15). Ответы этих
// сервисов — десятки байт; мегабайт с запасом покрывает любой законный ответ. Раньше
// json.Decoder читал тело чужого сервера без ограничения: одно поле произвольной длины
// превращалось в неограниченное потребление памяти на устройстве пользователя.
const bodyLimitBytes = 1 << 20 // 1 МБ

// anonUserAgent — нейтральный User-Agent для публичных API (К2-E П15). Раньше отправлялся
// version.UserAgent() — "APF/<версия>", то есть уникальная подпись VPN-клиента и его версии
// в каждом запросе к стороннему сервису, по логам которого клиента можно и опознать, и
// пересчитать. Пустой заголовок сам по себе приметен, поэтому берём обычную браузерную строку.
const anonUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

// IPInfo содержит информацию о репутации IP-адреса.
type IPInfo struct {
	IP            string    `json:"ip"`
	IsProxy       bool      `json:"is_proxy"`       // прокси/VPN по данным API
	IsVPN         bool      `json:"is_vpn"`         // явно VPN
	IsDatacenter  bool      `json:"is_datacenter"`  // датацентровый IP
	IsResidential bool      `json:"is_residential"` // residential ISP
	IsHosting     bool      `json:"is_hosting"`     // хостинг провайдер
	RiskScore     int       `json:"risk_score"`     // 0-100 (100 = точно заблокируют)
	ASN           string    `json:"asn"`
	ISP           string    `json:"isp"`
	Org           string    `json:"org"`
	Country       string    `json:"country"`
	Source        string    `json:"source"` // откуда получили данные
	CheckedAt     time.Time `json:"checked_at"`
}

// IsGoodForStreaming возвращает true если IP подходит для стриминговых сервисов.
// Критерии: не датацентр, не прокси, риск-скор < 40.
func (i *IPInfo) IsGoodForStreaming() bool {
	if i == nil {
		return false
	}
	if i.IsDatacenter || i.IsHosting || i.IsProxy {
		return false
	}
	if i.RiskScore > 40 {
		return false
	}
	return true
}

// Label возвращает читаемую метку типа IP.
func (i *IPInfo) Label() string {
	if i == nil {
		return "unknown"
	}
	switch {
	case i.IsResidential:
		return "residential"
	case i.IsDatacenter:
		return "datacenter"
	case i.IsHosting:
		return "hosting"
	case i.IsProxy || i.IsVPN:
		return "proxy/vpn"
	default:
		return "unknown"
	}
}

// cacheEntry — запись в кэше репутации.
type cacheEntry struct {
	info      *IPInfo
	expiresAt time.Time
}

// Checker проверяет репутацию IP через публичные API с кэшированием.
type Checker struct {
	mu     sync.RWMutex
	cache  map[string]*cacheEntry
	ttl    time.Duration
	client *http.Client
	apiKey string // опциональный ключ proxycheck.io
	logFn  func(string)

	// C-12 (ТЗ v1.4): подавление повторного журналирования отказа одного и того же
	// источника. Без этого проверка пула из N узлов при недоступном (например, из-за
	// бесплатного тарифа, отказывающего в https — см. К2-E П15) ip-api.com/proxycheck.io
	// пишет N одинаковых по сути строк вместо одной — лог превращается в шум, а на Android
	// он целиком уходит в поддержку по кнопке «Выгрузить лог».
	logMu      sync.Mutex
	loggedFail map[string]bool // источник ("ip-api.com" / "proxycheck.io") -> уже залогирован
}

// NewChecker создаёт Checker.
// apiKey — опциональный ключ proxycheck.io (пустая строка = без ключа, 1000/day).
func NewChecker(logFn func(string)) *Checker {
	if logFn == nil {
		logFn = func(string) {}
	}
	return &Checker{
		cache: make(map[string]*cacheEntry),
		ttl:   24 * time.Hour,
		// netguard: под `go test` выход за пределы петли отвергается (Т-5).
		client:     netguard.Client(8 * time.Second),
		logFn:      logFn,
		loggedFail: make(map[string]bool),
	}
}

// logSourceFailure (C-12) пишет отказ источника в лог один раз — до тех пор, пока источник
// не отдаст успешный ответ (см. clearSourceFailure). Повторные отказы того же источника для
// других проверяемых IP молча подавляются, чтобы недоступный API не превращал лог в N копий
// одной и той же строки.
func (c *Checker) logSourceFailure(source, msg string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if c.loggedFail[source] {
		return
	}
	c.loggedFail[source] = true
	c.logFn(msg)
}

// clearSourceFailure (C-12) сбрасывает подавление после успешного ответа источника, чтобы
// следующий настоящий отказ снова попал в лог.
func (c *Checker) clearSourceFailure(source string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	delete(c.loggedFail, source)
}

// SetAPIKey устанавливает ключ proxycheck.io для увеличения лимита запросов.
func (c *Checker) SetAPIKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = key
}

// CheckIP проверяет репутацию IP-адреса.
// Сначала смотрит кэш (TTL 24ч), затем делает запросы к API.
// Порядок: ip-api.com (бесплатно, нет ключа) → proxycheck.io (fallback).
func (c *Checker) CheckIP(ctx context.Context, ip string) (*IPInfo, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("iprep: empty IP")
	}

	// Кэш
	c.mu.RLock()
	if entry, ok := c.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.info, nil
	}
	c.mu.RUnlock()

	// Попытка 1: ip-api.com — полностью бесплатно, без ключа, до 45 req/min
	info, err := c.checkIPAPI(ctx, ip)
	if err != nil {
		// C-12 (ТЗ v1.4): одна строка в лог на источник, а не на каждый проверяемый узел.
		c.logSourceFailure("ip-api.com", fmt.Sprintf("iprep: ip-api.com failed for %s: %v, trying proxycheck.io (дальнейшие отказы этого источника подавляются до восстановления)", ip, err))
		// Попытка 2: proxycheck.io
		info, err = c.checkProxyCheck(ctx, ip)
		if err != nil {
			c.logSourceFailure("proxycheck.io", fmt.Sprintf("iprep: all APIs failed for %s: %v", ip, err))
			// C-12: отказ источника — это "репутация неизвестна", а не "узел плохой".
			// Поле репутации остаётся пустым (IsProxy/IsDatacenter/IsResidential = false,
			// RiskScore = 0), узел не штрафуется и не теряет свой обычный Score.
			info = &IPInfo{
				IP:        ip,
				Source:    "unavailable",
				CheckedAt: time.Now(),
			}
		} else {
			c.clearSourceFailure("proxycheck.io")
		}
	} else {
		c.clearSourceFailure("ip-api.com")
	}

	// Кэшируем
	c.mu.Lock()
	c.cache[ip] = &cacheEntry{info: info, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()

	c.logFn(fmt.Sprintf("iprep: %s → %s (risk=%d, src=%s)", ip, info.Label(), info.RiskScore, info.Source))
	return info, nil
}

// checkIPAPI использует ip-api.com.
// Возвращает: proxy, hosting, isp, org, asname, countryCode.
func (c *Checker) checkIPAPI(ctx context.Context, ip string) (*IPInfo, error) {
	url := fmt.Sprintf("%s/json/%s?fields=status,proxy,hosting,isp,org,asname,countryCode,query", ipAPIBaseURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", anonUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status  string `json:"status"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
		ISP     string `json:"isp"`
		Org     string `json:"org"`
		ASName  string `json:"asname"`
		Country string `json:"countryCode"`
		Query   string `json:"query"`
	}
	// К2-E П15: тело читается с потолком (см. bodyLimitBytes).
	if err := json.NewDecoder(io.LimitReader(resp.Body, bodyLimitBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("ip-api decode: %w", err)
	}
	if result.Status != "success" {
		return nil, fmt.Errorf("ip-api status: %s", result.Status)
	}

	info := &IPInfo{
		IP:           ip,
		IsProxy:      result.Proxy,
		IsVPN:        result.Proxy, // ip-api объединяет proxy+vpn в поле proxy
		IsDatacenter: result.Hosting,
		IsHosting:    result.Hosting,
		ISP:          result.ISP,
		Org:          result.Org,
		ASN:          result.ASName,
		Country:      result.Country,
		Source:       "ip-api.com",
		CheckedAt:    time.Now(),
	}

	// Определяем residential: не датацентр и не прокси
	info.IsResidential = !info.IsDatacenter && !info.IsProxy

	// Вычисляем риск-скор
	info.RiskScore = c.calcRiskScore(info)

	return info, nil
}

// netErrKind сводит сетевую ошибку к безопасному для лога классу, без URL и параметров
// запроса. P1-8: тексты ошибок HTTP-клиента содержат полный URL, а в URL proxycheck.io и
// Hiddify лежат секреты (ключ API / токен подписки).
func netErrKind(err error) string {
	if err == nil {
		return "ok"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "таймаут"
	case errors.Is(err, context.Canceled):
		return "отменён"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "таймаут"
	}
	return "сетевая ошибка"
}

// checkProxyCheck использует proxycheck.io.
func (c *Checker) checkProxyCheck(ctx context.Context, ip string) (*IPInfo, error) {
	// P1-8 (аудит 2026-09-01): apiKey читается под блокировкой — SetAPIKey пишет его под
	// c.mu, а здесь он читался напрямую (гонка данных, ловится -race).
	c.mu.RLock()
	key := c.apiKey
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/v2/%s?vpn=1&asn=1", proxyCheckBaseURL, ip)
	if key != "" {
		url += "&key=" + key
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		// P1-8: ошибка построения запроса тоже содержит URL — не отдаём её наружу как есть.
		return nil, fmt.Errorf("proxycheck: не удалось построить запрос")
	}
	req.Header.Set("User-Agent", anonUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		// P1-8: НЕ возвращаем исходную ошибку. http.Client отдаёт *url.Error, чей Error()
		// содержит ПОЛНЫЙ URL — вместе с "&key=<ключ proxycheck.io>". Выше по стеку эта
		// ошибка попадает в c.logFn ("iprep: all APIs failed for %s: %v"), а на Android лог
		// пишется в постоянный файл, который пользователь отправляет в поддержку кнопкой
		// «Выгрузить лог». Сохраняем только класс ошибки.
		return nil, fmt.Errorf("proxycheck: запрос не выполнен (%s)", netErrKind(err))
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	// К2-E П15: тело читается с потолком (см. bodyLimitBytes).
	if err := json.NewDecoder(io.LimitReader(resp.Body, bodyLimitBytes)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("proxycheck decode: %w", err)
	}

	// Структура ответа: {"status":"ok", "<ip>": {...}}
	status, _ := raw["status"].(string)
	if status != "ok" {
		return nil, fmt.Errorf("proxycheck status: %s", status)
	}

	data, ok := raw[ip].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("proxycheck: no data for IP %s", ip)
	}

	proxyStr, _ := data["proxy"].(string)
	vpnStr, _ := data["vpn"].(string)
	typeStr, _ := data["type"].(string)
	isp, _ := data["isp"].(string)
	asn, _ := data["asn"].(string)
	country, _ := data["country"].(string)
	org, _ := data["organisation"].(string)

	info := &IPInfo{
		IP:        ip,
		IsProxy:   proxyStr == "yes",
		IsVPN:     vpnStr == "yes" || proxyStr == "yes",
		ISP:       isp,
		Org:       org,
		ASN:       asn,
		Country:   country,
		Source:    "proxycheck.io",
		CheckedAt: time.Now(),
	}

	// Тип: Datacenter / Business / Residential
	typeStrLow := strings.ToLower(typeStr)
	switch {
	case strings.Contains(typeStrLow, "datacenter"), strings.Contains(typeStrLow, "hosting"):
		info.IsDatacenter = true
		info.IsHosting = true
	case strings.Contains(typeStrLow, "residential"):
		info.IsResidential = true
	case strings.Contains(typeStrLow, "business"):
		// Business ISP — не совсем residential, но лучше datacenter
		info.IsResidential = false
		info.IsDatacenter = false
	}

	if !info.IsDatacenter && !info.IsProxy {
		info.IsResidential = true
	}

	info.RiskScore = c.calcRiskScore(info)
	return info, nil
}

// calcRiskScore вычисляет риск-скор 0-100.
// 0 = чистый residential, 100 = явный VPN/datacenter, заблокируют точно.
func (c *Checker) calcRiskScore(info *IPInfo) int {
	score := 0
	if info.IsProxy || info.IsVPN {
		score += 50
	}
	if info.IsDatacenter || info.IsHosting {
		score += 40
	}
	// Ключевые слова в org/ASN часто используются для детекции
	hostingKeywords := []string{
		"digitalocean", "linode", "vultr", "aws", "amazon", "hetzner",
		"ovh", "scaleway", "cloudflare", "choopa", "as-choopa",
		"serverius", "leaseweb", "pnap", "datacamp", "frantech",
	}
	orgLow := strings.ToLower(info.Org + " " + info.ASN + " " + info.ISP)
	for _, kw := range hostingKeywords {
		if strings.Contains(orgLow, kw) {
			score += 20
			break
		}
	}
	if info.IsResidential && !info.IsProxy {
		score -= 20 // бонус за residential
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// ClearCache очищает весь кэш репутации.
func (c *Checker) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cacheEntry)
}

// CacheSize возвращает количество записей в кэше.
func (c *Checker) CacheSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// GetCached возвращает кэшированный результат без запроса к API.
// Возвращает nil если нет в кэше или истёк TTL.
func (c *Checker) GetCached(ip string) *IPInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		return entry.info
	}
	return nil
}
