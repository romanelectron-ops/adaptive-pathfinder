// multihop.go — Multi-hop туннель: VPN→Proxy→Exit. Фаза 6.
// tunnel-architect: каждый узел знает только соседей, максимальная анонимизация.
package dpi

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// HopType — тип узла в цепочке
type HopType string

const (
	HopEntry  HopType = "entry"  // первый узел (ближайший к клиенту)
	HopMiddle HopType = "middle" // промежуточный
	HopExit   HopType = "exit"   // выходной (видит реальный destination)
)

// Hop — один узел в multi-hop цепочке
type Hop struct {
	Node    *models.Node `json:"node"`
	Type    HopType      `json:"type"`
	Latency int64        `json:"latency_ms"` // измеренная задержка
}

// MultiHopChain — описание multi-hop цепочки
type MultiHopChain struct {
	Hops           []*Hop `json:"hops"`
	TotalRTT       int64  `json:"total_rtt_ms"`
	Topology       string `json:"topology"`        // "vless→wireguard→exit", etc.
	AnonymityLevel int    `json:"anonymity_level"` // 1-3
}

// MultiHopBuilder строит multi-hop конфигурации для sing-box.
// tunnel-architect: detour-цепочка в sing-box outbounds.
type MultiHopBuilder struct {
	builder *singbox.Builder
}

// NewMultiHopBuilder создаёт builder
func NewMultiHopBuilder(socksPort int) *MultiHopBuilder {
	return &MultiHopBuilder{
		builder: singbox.NewBuilder(socksPort, false),
	}
}

// BuildViaProxy строит конфиг: VPN через прокси-узел.
// tunnel-architect: VPN over Proxy — прокси снаружи.
// Схема: Клиент → [entry proxy] → [exit VPN] → Интернет
func (b *MultiHopBuilder) BuildViaProxy(proxy, exit *models.Node) (*singbox.Config, error) {
	if proxy == nil || exit == nil {
		return nil, fmt.Errorf("multihop: both proxy and exit nodes required")
	}

	// Строим chain из двух узлов: exit идёт через proxy
	chain := &models.Chain{
		Nodes: []*models.Node{exit, proxy},
	}
	return b.builder.BuildChain(chain)
}

// BuildThreeHop строит трёхузловую цепочку: Entry → Middle → Exit.
// tunnel-architect: максимальная анонимность — каждый узел знает только соседей.
// Схема: Клиент → [entry] → [middle] → [exit] → Интернет
func (b *MultiHopBuilder) BuildThreeHop(entry, middle, exit *models.Node) (*singbox.Config, error) {
	if entry == nil || middle == nil || exit == nil {
		return nil, fmt.Errorf("multihop: three nodes required for 3-hop chain")
	}

	chain := &models.Chain{
		Nodes: []*models.Node{entry, middle, exit},
	}
	return b.builder.BuildChain(chain)
}

// MultiHopSelector — выбирает оптимальную multi-hop топологию из пула узлов.
// tunnel-architect: выбираем узлы с разными AS/странами для максимальной анонимности.
type MultiHopSelector struct {
	padder *TrafficPadder
}

// NewMultiHopSelector создаёт selector
func NewMultiHopSelector() *MultiHopSelector {
	return &MultiHopSelector{
		padder: NewTrafficPadder(DefaultPaddingConfig()),
	}
}

// SelectBestChain выбирает оптимальную пару/тройку узлов из пула.
// tunnel-architect: приоритет — разные протоколы на каждом хопе.
func (s *MultiHopSelector) SelectBestChain(nodes []*models.Node, hops int) *MultiHopChain {
	if len(nodes) < hops {
		return nil
	}

	// Сортируем по score (уже отсортированы в engine), берём лучших
	// Стараемся выбрать узлы с разными протоколами
	selected := s.selectDiverseNodes(nodes, hops)
	if len(selected) < hops {
		return nil
	}

	chain := &MultiHopChain{
		Hops: make([]*Hop, len(selected)),
	}

	var totalRTT int64
	var protoNames []string
	for i, n := range selected {
		hopType := HopMiddle
		if i == 0 {
			hopType = HopEntry
		} else if i == len(selected)-1 {
			hopType = HopExit
		}
		chain.Hops[i] = &Hop{
			Node:    n,
			Type:    hopType,
			Latency: n.Latency,
		}
		totalRTT += n.Latency
		protoNames = append(protoNames, string(n.Protocol))
	}

	chain.TotalRTT = totalRTT
	chain.Topology = buildTopologyString(protoNames)
	chain.AnonymityLevel = hops // 2-hop = уровень 2, 3-hop = уровень 3

	return chain
}

// selectDiverseNodes выбирает N узлов с предпочтением разных протоколов.
func (s *MultiHopSelector) selectDiverseNodes(nodes []*models.Node, n int) []*models.Node {
	if len(nodes) <= n {
		// Верификация 2026-09-05 (100-300 сценариев, DPI/leakguard-доля): раньше этот путь
		// отдавал nodes как есть, вообще не глядя на IsBlacklisted() — узел, недавно
		// провалившийся и попавший в бан, мог стать хопом multi-hop цепочки только потому,
		// что кандидатов было не больше, чем нужно хопов. Тот же принцип, что и в основном
		// пути ниже: заведомо небодный узел нельзя отдавать в цепочку, даже когда выбирать
		// не из чего — лучше вернуть цепочку короче/пустую, чем с гарантированно мёртвым хопом.
		out := make([]*models.Node, 0, len(nodes))
		for _, node := range nodes {
			if !node.IsBlacklisted() {
				out = append(out, node)
			}
		}
		return out
	}

	// Группируем по протоколам
	byProto := make(map[models.Protocol][]*models.Node)
	for _, node := range nodes {
		if node.Score > 0 && !node.IsBlacklisted() {
			byProto[node.Protocol] = append(byProto[node.Protocol], node)
		}
	}

	selected := make([]*models.Node, 0, n)
	seen := make(map[string]bool)

	// Сначала берём по одному из каждого протокола
	protos := []models.Protocol{
		models.ProtoVLESS,
		models.ProtoTrojan,
		models.ProtoVMess,
		models.ProtoShadowsocks,
		models.ProtoWireGuard,
	}
	for _, proto := range protos {
		if len(selected) >= n {
			break
		}
		nodeList := byProto[proto]
		for _, node := range nodeList {
			if !seen[node.Address] {
				selected = append(selected, node)
				seen[node.Address] = true
				break
			}
		}
	}

	// Если не хватает узлов — добираем из оставшихся.
	//
	// БАГ (верификация 2026-09-05): цикл проверял только node.Score > 0, но НЕ
	// node.IsBlacklisted() — в отличие от byProto-фильтра выше (строка с "node.Score > 0 &&
	// !node.IsBlacklisted()"). Итог: если diverse-by-protocol проход не набирал n узлов (все
	// кандидаты одного протокола, или блэклист вычистил все альтернативы), этот добор мог
	// подсунуть в multi-hop цепочку узел, который сам же byProto-фильтр строкой выше
	// отбраковал как заблокированный. Цепочка получала заведомо неработающий хоп, хотя весь
	// смысл первого фильтра — не подпускать такие узлы к отбору вообще.
	for _, node := range nodes {
		if len(selected) >= n {
			break
		}
		if !seen[node.Address] && node.Score > 0 && !node.IsBlacklisted() {
			selected = append(selected, node)
			seen[node.Address] = true
		}
	}

	return selected
}

// buildTopologyString формирует строку топологии для отображения в UI
func buildTopologyString(protos []string) string {
	result := ""
	for i, p := range protos {
		if i > 0 {
			result += "→"
		}
		result += p
	}
	return result
}

// ProbeHopLatency измеряет задержку до узла (без подключения через него).
// Используется для выбора оптимальных узлов в цепочке.
func ProbeHopLatency(ctx context.Context, node *models.Node) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", node.Address, node.Port)
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return time.Since(start).Milliseconds(), nil
}

// MultiHopStatus — статус активной multi-hop цепочки
type MultiHopStatus struct {
	Active   bool           `json:"active"`
	Chain    *MultiHopChain `json:"chain,omitempty"`
	HopCount int            `json:"hop_count"`
}
