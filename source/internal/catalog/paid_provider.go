// paid_provider.go — фабрика платных провайдеров для APF.
// NewPaidProvider диспетчеризует по полю cfg.Type.
package catalog

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// PaidProviderConfig — конфигурация платного провайдера.
// Поля зеркалируют models.PaidProviderEntry.
type PaidProviderConfig struct {
	ID              string
	Name            string
	Type            string // "3xui", "marzban", "hiddify", "subscription"
	URL             string
	Username        string
	Password        string
	Token           string
	SubscriptionURL string
	Enabled         bool
	InsecureTLS     bool
}

// NewPaidProvider создаёт провайдер нужного типа по cfg.Type.
// Поддерживаемые типы: "3xui", "marzban", "hiddify", "subscription".
// Возвращает ошибку для неизвестного типа или если не задан URL.
func NewPaidProvider(cfg PaidProviderConfig) (Provider, error) {
	client := newHTTPClient(cfg.InsecureTLS)

	switch cfg.Type {
	case "3xui":
		if cfg.URL == "" {
			return nil, fmt.Errorf("провайдер 3x-ui «%s»: не указан URL панели", cfg.Name)
		}
		return &ThreeXUIProvider{cfg: cfg, client: client, meta: panelMeta(cfg), enabled: cfg.Enabled}, nil

	case "marzban":
		if cfg.URL == "" {
			return nil, fmt.Errorf("провайдер Marzban «%s»: не указан URL панели", cfg.Name)
		}
		return &MarzbanProvider{cfg: cfg, client: client, meta: panelMeta(cfg), enabled: cfg.Enabled}, nil

	case "hiddify":
		if cfg.URL == "" && cfg.Token == "" && cfg.SubscriptionURL == "" {
			return nil, fmt.Errorf("провайдер Hiddify «%s»: нужен URL или токен", cfg.Name)
		}
		return &HiddifyProvider{cfg: cfg, client: client, meta: panelMeta(cfg), enabled: cfg.Enabled}, nil

	case "subscription", "":
		subURL := cfg.SubscriptionURL
		if subURL == "" {
			subURL = cfg.URL
		}
		if subURL == "" {
			return nil, fmt.Errorf("провайдер-подписка «%s»: не указана ссылка подписки", cfg.Name)
		}
		id := cfg.ID
		if id == "" {
			id = "sub-" + cfg.Name
		}
		return NewFreeProvider(id, cfg.Name, subURL), nil

	default:
		return nil, fmt.Errorf("неизвестный тип платного провайдера: «%s»", cfg.Type)
	}
}

// PaidSourceTag — ЕДИНСТВЕННЫЙ источник истины для Node.Source узлов платного провайдера.
//
// P1-7 (аудит 2026-09-01). Раньше конвенций было три и ни одна не совпадала с той, по которой
// движок ищет узлы при удалении провайдера:
//   - 3X-UI и Marzban ставили Source = cfg.Name (человекочитаемое имя панели);
//   - Hiddify ставил Source = cfg.ID (голый идентификатор);
//   - Engine.RemovePaidProvider фильтровал по "paid:"+id.
//
// Совпадения не случалось никогда, поэтому узлы удалённого провайдера оставались в пуле
// навсегда — и продолжали участвовать в выборе, хотя в UI провайдера уже не было.
func PaidSourceTag(id string) string { return "paid:" + id }

// newHTTPClient создаёт http.Client с опциональным отключением проверки TLS.
func newHTTPClient(insecure bool) *http.Client {
	transport := netguard.Transport()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{
		Timeout:   45 * time.Second,
		Transport: transport,
	}
}

// panelMeta возвращает базовые метаданные для панельного провайдера.
func panelMeta(cfg PaidProviderConfig) ProviderMeta {
	return ProviderMeta{
		Region:     "global",
		SpeedClass: "high",
		TrustScore: 0.9,
		Free:       false,
		Price:      "paid",
	}
}
