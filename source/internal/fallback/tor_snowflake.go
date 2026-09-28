// Package fallback — последний рубеж обороны APF.
// Фаза 7: Tor Snowflake и Psiphon как аварийные туннели когда все остальное заблокировано.
//
// Tor Snowflake:
//   - Маскирует трафик под WebRTC (браузерный протокол)
//   - Практически невозможно заблокировать без отключения всего WebRTC
//   - Использует добровольных пользователей как точки входа (Snowflake proxies)
//   - sing-box поддерживает Tor нативно + Snowflake транспорт через pluggable transport
//
// Psiphon:
//   - Канадская некоммерческая VPN-система
//   - Автоматически выбирает лучший протокол из 10+ вариантов
//   - Встроенные серверы — не нужно своих
//   - Поддерживает Go SDK через эмбеддинг
package fallback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// ─── Tor Snowflake ────────────────────────────────────────────────────────────

// SnowflakeStatus — текущее состояние Snowflake туннеля
type SnowflakeStatus struct {
	Available    bool   `json:"available"`
	Connected    bool   `json:"connected"`
	SOCKSAddr    string `json:"socks_addr,omitempty"`
	BootstrapURL string `json:"bootstrap_url"`
	BrokerURL    string `json:"broker_url"`
	ErrorMsg     string `json:"error,omitempty"`
}

// TorSnowflakeConfig — настройки Snowflake
type TorSnowflakeConfig struct {
	// BrokerURL — брокер который раздаёт Snowflake прокси клиентам
	// Дефолт: официальный брокер Tor Project
	BrokerURL string `json:"broker_url"`

	// FrontDomain — домен для domain fronting брокера
	// Дефолт: snowflake-broker.torproject.net.global.prod.fastly.net
	FrontDomain string `json:"front_domain"`

	// STUNServer — STUN сервер для WebRTC (Snowflake использует WebRTC под капотом)
	STUNServer string `json:"stun_server"`

	// DataDir — директория для Tor данных (ключи, дескрипторы)
	DataDir string `json:"data_dir"`

	// SOCKSPort — порт локального SOCKS5 прокси от Tor
	SOCKSPort int `json:"socks_port"`

	// ConnectTimeout — максимальное время установки Snowflake соединения
	ConnectTimeout time.Duration `json:"connect_timeout"`
}

// DefaultSnowflakeConfig — рекомендуемые настройки
func DefaultSnowflakeConfig(dataDir string) *TorSnowflakeConfig {
	return &TorSnowflakeConfig{
		BrokerURL:      "https://snowflake-broker.torproject.net/",
		FrontDomain:    "snowflake-broker.torproject.net.global.prod.fastly.net",
		STUNServer:     "stun:stun.l.google.com:19302",
		DataDir:        filepath.Join(dataDir, "tor"),
		SOCKSPort:      19050, // используем другой порт чтобы не конфликтовать с основным
		ConnectTimeout: 60 * time.Second,
	}
}

// TorSnowflakeManager управляет Tor+Snowflake туннелем.
//
// Архитектура:
//
//	APF → SOCKS5:19050 → Tor → Snowflake Transport → WebRTC → Snowflake Proxy → Tor Network
//
// sing-box генерирует конфиг с type:tor и snowflake транспортом.
// Tor процесс запускается отдельно (torrc с ClientTransportPlugin).
type TorSnowflakeManager struct {
	mu     sync.RWMutex
	cfg    *TorSnowflakeConfig
	status SnowflakeStatus
	log    func(string)
}

// NewTorSnowflakeManager создаёт менеджер
func NewTorSnowflakeManager(cfg *TorSnowflakeConfig, logFn func(string)) *TorSnowflakeManager {
	if cfg == nil {
		cfg = DefaultSnowflakeConfig(os.TempDir())
	}
	if logFn == nil {
		logFn = func(s string) {}
	}
	return &TorSnowflakeManager{
		cfg: cfg,
		log: logFn,
		status: SnowflakeStatus{
			BrokerURL: cfg.BrokerURL,
		},
	}
}

// IsAvailable проверяет что Tor бинарник доступен в системе или в binDir
func (m *TorSnowflakeManager) IsAvailable(binDir string) bool {
	// Ищем tor в системе
	if _, err := exec.LookPath("tor"); err == nil {
		return true
	}
	// Ищем в binDir APF
	torBin := filepath.Join(binDir, "tor")
	if runtime.GOOS == "windows" {
		torBin += ".exe"
	}
	_, err := os.Stat(torBin)
	return err == nil
}

// GetSingBoxOutbound возвращает sing-box outbound конфиг для Tor.
// sing-box поддерживает Tor нативно через type:"tor".
// Snowflake подключается через pluggable transport (PT) — отдельный процесс.
//
// ВАЖНО: sing-box Tor outbound требует чтобы Tor бинарник был установлен.
// Snowflake PT (lyrebird/snowflake-client) — отдельный бинарник.
func (m *TorSnowflakeManager) GetSingBoxOutbound(useSnowflake bool) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	outbound := map[string]interface{}{
		"type": "tor",
		"tag":  "tor-snowflake",
		"options": map[string]interface{}{
			"DataDirectory": m.cfg.DataDir,
		},
	}

	if useSnowflake {
		// Snowflake pluggable transport
		// Документация: https://tb-manual.torproject.org/circumvention/
		outbound["options"] = map[string]interface{}{
			"DataDirectory": m.cfg.DataDir,
			"ClientTransportPlugin": fmt.Sprintf(
				"snowflake exec %s -broker %s -front %s -stun %s -log /dev/null",
				m.snowflakeBinPath(),
				m.cfg.BrokerURL,
				m.cfg.FrontDomain,
				m.cfg.STUNServer,
			),
			"UseBridges":  "1",
			"Bridge":      "snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72",
			"SocksPort":   fmt.Sprintf("127.0.0.1:%d", m.cfg.SOCKSPort),
			"SocksPolicy": "accept 127.0.0.1",
			"Log":         "notice stdout",
		}
	}

	return outbound
}

// TestConnectivity проверяет доступность Tor сети (без Snowflake — прямое подключение)
func (m *TorSnowflakeManager) TestConnectivity(ctx context.Context) bool {
	// Пробуем достучаться до Tor DirAuth через HTTP
	// Если прямое подключение к Tor заблокировано — нужен Snowflake
	testURLs := []string{
		"https://check.torproject.org/",
		"https://www.torproject.org/",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// netguard.Guard: под `go test` выход за пределы петли отвергается (Т-5).
			DialContext: netguard.Guard((&net.Dialer{Timeout: 5 * time.Second}).DialContext),
		},
	}

	for _, u := range testURLs {
		req, err := http.NewRequestWithContext(ctx, "HEAD", u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
}

// GetStatus возвращает текущий статус
func (m *TorSnowflakeManager) GetStatus() SnowflakeStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *TorSnowflakeManager) snowflakeBinPath() string {
	name := "snowflake-client"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(m.cfg.DataDir), name)
}

// DownloadInstructions возвращает инструкции по загрузке Tor + Snowflake бинарников
func DownloadInstructions() string {
	return `# Установка Tor + Snowflake для APF

## Windows
1. Скачай Tor Expert Bundle:
   https://www.torproject.org/download/tor/
   Распакуй tor.exe в папку APF windows/bin/

2. Snowflake client (pluggable transport):
   https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/releases
   Скачай snowflake-client.exe → windows/bin/

## Linux
   apt install tor obfs4proxy
   # или
   snap install tor

## Проверка
   tor --version
   snowflake-client -version

После установки: APF автоматически обнаружит бинарники.
`
}

// ─── Psiphon ──────────────────────────────────────────────────────────────────

// PsiphonConfig — настройки Psiphon
type PsiphonConfig struct {
	// SOCKSPort — порт куда Psiphon слушает SOCKS5
	SOCKSPort int `json:"socks_port"`

	// HTTPPort — порт HTTP прокси от Psiphon
	HTTPPort int `json:"http_port"`

	// DataDir — директория для кэша Psiphon
	DataDir string `json:"data_dir"`

	// PropagationChannelID — ID канала для получения серверного списка
	// "FFFFFFFFFFFFFFFF" = дефолтный публичный канал
	PropagationChannelID string `json:"propagation_channel_id"`

	// SponsorID — ID спонсора (определяет поведение)
	// "FFFFFFFFFFFFFFFF" = публичный
	SponsorID string `json:"sponsor_id"`

	// EgressRegion — предпочтительная страна выхода ("" = любая)
	EgressRegion string `json:"egress_region"`
}

// DefaultPsiphonConfig — стандартные настройки
func DefaultPsiphonConfig(dataDir string) *PsiphonConfig {
	return &PsiphonConfig{
		SOCKSPort:            19808,
		HTTPPort:             19809,
		DataDir:              filepath.Join(dataDir, "psiphon"),
		PropagationChannelID: "FFFFFFFFFFFFFFFF",
		SponsorID:            "FFFFFFFFFFFFFFFF",
		EgressRegion:         "",
	}
}

// PsiphonStatus — состояние Psiphon
type PsiphonStatus struct {
	Available   bool   `json:"available"`
	Connected   bool   `json:"connected"`
	SOCKSAddr   string `json:"socks_addr,omitempty"`
	Region      string `json:"region,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	ErrorMsg    string `json:"error,omitempty"`
	NoteForUser string `json:"note"`
}

// PsiphonManager управляет Psiphon туннелем.
//
// Psiphon Go SDK (psiphon-tunnel-core) эмбеддится в APF как библиотека.
// При наличии SDK — используем его напрямую без внешних процессов.
// При отсутствии — генерируем конфиг для psiphond бинарника.
//
// Примечание: psiphon-tunnel-core — большая зависимость (~50MB).
// Добавляем её опционально через build tag: go build -tags psiphon
type PsiphonManager struct {
	mu     sync.RWMutex
	cfg    *PsiphonConfig
	status PsiphonStatus
	log    func(string)
}

// NewPsiphonManager создаёт менеджер
func NewPsiphonManager(cfg *PsiphonConfig, logFn func(string)) *PsiphonManager {
	if cfg == nil {
		cfg = DefaultPsiphonConfig(os.TempDir())
	}
	if logFn == nil {
		logFn = func(s string) {}
	}
	return &PsiphonManager{
		cfg: cfg,
		log: logFn,
		status: PsiphonStatus{
			NoteForUser: "Psiphon SDK интегрируется через build tag -tags psiphon. " +
				"Без SDK — запускается как внешний процесс psiphond.",
		},
	}
}

// GenerateConfig генерирует JSON конфиг для psiphond (внешний процесс)
func (m *PsiphonManager) GenerateConfig() string {
	return fmt.Sprintf(`{
  "PropagationChannelId": "%s",
  "SponsorId": "%s",
  "LocalSocksProxyPort": %d,
  "LocalHttpProxyPort": %d,
  "EgressRegion": "%s",
  "DataRootDirectory": "%s",
  "DisableLocalSocksProxy": false,
  "DisableLocalHTTPProxy": false,
  "EmitDiagnosticNotices": true,
  "ClientPlatform": "Windows_10",
  "ClientVersion": "1"
}`,
		m.cfg.PropagationChannelID,
		m.cfg.SponsorID,
		m.cfg.SOCKSPort,
		m.cfg.HTTPPort,
		m.cfg.EgressRegion,
		strings.ReplaceAll(m.cfg.DataDir, "\\", "\\\\"),
	)
}

// GetStatus возвращает статус
func (m *PsiphonManager) GetStatus() PsiphonStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.SOCKSAddr = fmt.Sprintf("127.0.0.1:%d", m.cfg.SOCKSPort)
	return s
}

// IsSDKAvailable проверяет наличие Psiphon SDK (build tag psiphon)
// В текущей реализации — всегда false (SDK подключается отдельно)
func (m *PsiphonManager) IsSDKAvailable() bool {
	return psiphonSDKAvailable()
}

// GetSingBoxOutbound возвращает sing-box outbound для SOCKS5→Psiphon
// После запуска psiphond APF подключается к нему через SOCKS5
func (m *PsiphonManager) GetSingBoxOutbound() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"type":        "socks",
		"tag":         "psiphon-tunnel",
		"server":      "127.0.0.1",
		"server_port": m.cfg.SOCKSPort,
		"version":     "5",
	}
}

// ─── FallbackOrchestrator ─────────────────────────────────────────────────────

// FallbackTunnel — тип аварийного туннеля
type FallbackTunnel string

const (
	FallbackTor       FallbackTunnel = "tor"
	FallbackSnowflake FallbackTunnel = "tor_snowflake"
	FallbackPsiphon   FallbackTunnel = "psiphon"
	FallbackNone      FallbackTunnel = "none"
)

// FallbackOrchestrator управляет всеми аварийными туннелями.
// Используется engine как последний уровень fallback после Reality и CDN.
type FallbackOrchestrator struct {
	mu        sync.RWMutex
	snowflake *TorSnowflakeManager
	psiphon   *PsiphonManager
	active    FallbackTunnel
	binDir    string
	dataDir   string
	log       func(string)
}

// NewFallbackOrchestrator создаёт оркестратор аварийных туннелей
func NewFallbackOrchestrator(binDir, dataDir string, logFn func(string)) *FallbackOrchestrator {
	if logFn == nil {
		logFn = func(s string) {}
	}

	sfCfg := DefaultSnowflakeConfig(dataDir)
	pCfg := DefaultPsiphonConfig(dataDir)

	return &FallbackOrchestrator{
		snowflake: NewTorSnowflakeManager(sfCfg, logFn),
		psiphon:   NewPsiphonManager(pCfg, logFn),
		active:    FallbackNone,
		binDir:    binDir,
		dataDir:   dataDir,
		log:       logFn,
	}
}

// SelectBest выбирает лучший доступный аварийный туннель.
// Приоритет: Tor прямой > Tor+Snowflake > Psiphon
// TorAvailable — есть ли на этой машине чем исполнить Tor (дефект D-A29).
//
// Вход:      каталог бинарей APF и системный PATH.
// Тело:      делегируется TorSnowflakeManager.IsAvailable.
// Выход:     true, только если файл tor реально найден.
// Fail-safe: неизвестность = false; лучше честный отказ, чем конфигурация, которую
//
//	sing-box отвергнет уже на старте.
//
// Зачем отдельный экспортированный метод, если есть SelectBest. SelectBest обязан вернуть
// хоть какой-то туннель и при полном отсутствии бинарей отдаёт ветку Psiphon, которая в
// движке разворачивается в Tor. Движку нужен прямой ответ на вопрос «а запускается ли он
// вообще», иначе он строит конфигурацию с outbound type:"tor" вслепую.
//
// Почему одного встроенного Tor недостаточно и нужен внешний файл: в официальных сборках
// sing-box тега with_embedded_tor нет (проверено на устройстве: `sing-box version` →
// Tags: with_gvisor,with_quic,with_dhcp,with_wireguard,...). Outbound type:"tor" там просто
// запускает внешний процесс tor, и без него падает: exec: "tor": executable file not found.
func (o *FallbackOrchestrator) TorAvailable() bool {
	if o == nil || o.snowflake == nil {
		return false
	}
	return o.snowflake.IsAvailable(o.binDir)
}

func (o *FallbackOrchestrator) SelectBest(ctx context.Context) FallbackTunnel {
	o.log("Fallback: selecting emergency tunnel...")

	// Проверяем доступность Tor
	torAvail := o.snowflake.IsAvailable(o.binDir)

	if torAvail {
		// Tor есть — проверяем нужен ли Snowflake
		if o.snowflake.TestConnectivity(ctx) {
			o.log("Fallback: Tor direct connectivity — no Snowflake needed")
			return FallbackTor
		}
		o.log("Fallback: Tor direct blocked — trying Snowflake")
		return FallbackSnowflake
	}

	// Tor нет — пробуем Psiphon, если psiphond реально установлен.
	if o.psiphon != nil && o.psiphon.IsAvailable(o.binDir) {
		o.log("Fallback: Tor not found — trying Psiphon (psiphond present)")
		return FallbackPsiphon
	}
	// Ни Tor, ни psiphond недоступны: честно возвращаем Psiphon-ветку, которая в движке
	// прозрачно переключится на Tor с явным сообщением (T-16б) — без маскировки.
	o.log("Fallback: ни Tor, ни psiphond не найдены — будет использован Tor (резерв)")
	return FallbackPsiphon
}

// GetStatus возвращает статус всех аварийных туннелей
func (o *FallbackOrchestrator) GetStatus(ctx context.Context) map[string]interface{} {
	o.mu.RLock()
	active := o.active
	o.mu.RUnlock()

	torAvail := o.snowflake.IsAvailable(o.binDir)
	sfStatus := o.snowflake.GetStatus()
	psStatus := o.psiphon.GetStatus()

	return map[string]interface{}{
		"active_tunnel":    string(active),
		"tor_available":    torAvail,
		"snowflake_status": sfStatus,
		"psiphon_status":   psStatus,
		"psiphon_sdk":      o.psiphon.IsSDKAvailable(),
		"install_guide":    DownloadInstructions(),
	}
}

// ErrSnowflakeNotApplicable — Snowflake нельзя применить: конфигурация, которую строит
// GetSingBoxOutbound(true), физически не доходит до sing-box (К2-E П7, свод C, опоры B3).
//
// Почему это не «пока не реализовано, скоро будет», а именно отказ:
//   - результат GetSingBoxConfig нигде не применяется — движок строит свою конфигурацию
//     через singbox.Builder.BuildTor(), а это голый outbound {type:"tor"} без опций;
//   - ключи Snowflake (torrc: ClientTransportPlugin/UseBridges/Bridge) невыразимы в
//     singbox.Outbound и не совпадают с вендорной схемой (vendor option/tor.go ждёт "torrc",
//     здесь — "options");
//   - на Android уровней L3/L4 нет структурно, а бинарников tor и snowflake-client там нет
//     вовсе.
//
// Молчаливая подмена Snowflake чистым Tor — худший исход: пользователь включает «резерв,
// который работает через WebRTC браузеров», получает ровно тот прямой Tor, который у него и
// так заблокирован, и не понимает, почему «самый стойкий режим» не помогает.
var ErrSnowflakeNotApplicable = errors.New(
	"Резервный туннель Snowflake недоступен: APF не умеет передать конфигурацию Snowflake в sing-box " +
		"(нужны torrc-опции pluggable transport и бинарник snowflake-client, которых нет ни в " +
		"сборке, ни на Android). Включение Snowflake сейчас означало бы обычный прямой Tor — " +
		"выберите его явно, если он у вас не заблокирован")

// SnowflakeApplicable — можно ли реально применить Snowflake. Всегда false, см.
// ErrSnowflakeNotApplicable. Отдельный предикат нужен движку, чтобы отказ был ОДИН и в одном
// месте: и ручная активация, и авто-выбор резерва спрашивают тут, а не гадают по строкам.
func (o *FallbackOrchestrator) SnowflakeApplicable() bool { return false }

// GetSingBoxConfig возвращает sing-box outbound для выбранного аварийного туннеля
func (o *FallbackOrchestrator) GetSingBoxConfig(tunnel FallbackTunnel) map[string]interface{} {
	switch tunnel {
	case FallbackTor:
		return o.snowflake.GetSingBoxOutbound(false)
	case FallbackSnowflake:
		return o.snowflake.GetSingBoxOutbound(true)
	case FallbackPsiphon:
		return o.psiphon.GetSingBoxOutbound()
	default:
		return nil
	}
}

// SetActive устанавливает активный аварийный туннель
func (o *FallbackOrchestrator) SetActive(t FallbackTunnel) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.active = t
}

func (o *FallbackOrchestrator) GetActive() FallbackTunnel {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.active
}

// psiphonSDKAvailable — заглушка. При сборке с -tags psiphon заменяется на реальную проверку.
func psiphonSDKAvailable() bool {
	return false
}
