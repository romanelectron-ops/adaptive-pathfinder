// Package residential отбирает и ранжирует VPN-узлы по типу IP.
// Sprint S6: Anti-VPN-Block — приоритет residential узлам.
//
// Residential IP — это обычные домашние/ISP адреса.
// Сайты-стриминги и банки их не блокируют, в отличие от datacenter IP.
package residential

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/iprep"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// NodeScore — узел с вычисленным Anti-Block score.
type NodeScore struct {
	Node           *models.Node
	IPInfo         *iprep.IPInfo
	AntiBlockScore float64 // -100..+100: чем выше, тем лучше для стриминга
	Checked        bool
}

// Label читаемый тип IP.
func (ns *NodeScore) Label() string {
	if ns.IPInfo == nil {
		return "unknown"
	}
	return ns.IPInfo.Label()
}

// Selector отбирает residential узлы и ранжирует по Anti-Block score.
type Selector struct {
	checker *iprep.Checker
	mu      sync.RWMutex
	scores  map[string]*NodeScore // node.ID → score
	logFn   func(string)
}

// NewSelector создаёт Selector.
func NewSelector(checker *iprep.Checker, logFn func(string)) *Selector {
	if logFn == nil {
		logFn = func(string) {}
	}
	return &Selector{
		checker: checker,
		scores:  make(map[string]*NodeScore),
		logFn:   logFn,
	}
}

// CheckNode проверяет репутацию IP конкретного узла.
// Результат кэшируется в iprep.Checker (24ч TTL).
func (s *Selector) CheckNode(ctx context.Context, node *models.Node) (*NodeScore, error) {
	// Сначала смотрим свой кэш score
	s.mu.RLock()
	if sc, ok := s.scores[node.ID]; ok && sc.Checked {
		s.mu.RUnlock()
		return sc, nil
	}
	s.mu.RUnlock()

	info, err := s.checker.CheckIP(ctx, node.Address)
	if err != nil {
		return nil, err
	}

	ns := &NodeScore{
		Node:           node,
		IPInfo:         info,
		AntiBlockScore: calcAntiBlockScore(info, node),
		Checked:        true,
	}

	s.mu.Lock()
	s.scores[node.ID] = ns
	s.mu.Unlock()

	return ns, nil
}

// FilterAndRank возвращает узлы, отсортированные по Anti-Block score (лучшие первые).
// Если requireResidential=true — возвращает только residential узлы.
// Проверяет IP через iprep.Checker (использует кэш).
func (s *Selector) FilterAndRank(ctx context.Context, nodes []*models.Node, requireResidential bool) []*models.Node {
	if len(nodes) == 0 {
		return nil
	}

	type entry struct {
		node  *models.Node
		score float64
	}

	var (
		mu      sync.Mutex
		entries []entry
		wg      sync.WaitGroup
	)

	// Проверяем узлы параллельно, но с лимитом
	sem := make(chan struct{}, 5) // max 5 параллельных запросов
	for _, n := range nodes {
		wg.Add(1)
		go func(node *models.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx2, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()

			ns, err := s.CheckNode(ctx2, node)
			if err != nil {
				// Не можем проверить — включаем с нейтральным score
				mu.Lock()
				entries = append(entries, entry{node, 0})
				mu.Unlock()
				return
			}

			if requireResidential && !ns.IPInfo.IsResidential {
				return // пропускаем non-residential
			}

			mu.Lock()
			entries = append(entries, entry{node, ns.AntiBlockScore})
			mu.Unlock()
		}(n)
	}
	wg.Wait()

	if len(entries) == 0 {
		if requireResidential {
			// Если strict residential — ничего не нашли, возвращаем оригинальный список
			s.logFn("residential: no residential nodes found, falling back to all nodes")
			return nodes
		}
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].score > entries[j].score
	})

	result := make([]*models.Node, len(entries))
	for i, e := range entries {
		result[i] = e.node
	}
	return result
}

// BestForStreaming возвращает лучший узел для стриминга из переданного пула.
// Если residential узлов нет — возвращает лучший из имеющихся (не nil).
func (s *Selector) BestForStreaming(ctx context.Context, nodes []*models.Node) *models.Node {
	ranked := s.FilterAndRank(ctx, nodes, false) // сначала без фильтра
	if len(ranked) == 0 {
		return nil
	}

	// Пробуем найти residential
	for _, n := range ranked {
		s.mu.RLock()
		sc, ok := s.scores[n.ID]
		s.mu.RUnlock()
		if ok && sc.IPInfo != nil && sc.IPInfo.IsResidential {
			return n
		}
	}

	// Нет residential — возвращаем лучший по общему score
	return ranked[0]
}

// GetScores возвращает все сохранённые scores для UI.
func (s *Selector) GetScores() []*NodeScore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*NodeScore, 0, len(s.scores))
	for _, sc := range s.scores {
		result = append(result, sc)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].AntiBlockScore > result[j].AntiBlockScore
	})
	return result
}

// Stats возвращает статистику пула по типам IP.
func (s *Selector) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := map[string]int{
		"total":       len(s.scores),
		"residential": 0,
		"datacenter":  0,
		"proxy_vpn":   0,
		"unknown":     0,
	}
	for _, sc := range s.scores {
		if sc.IPInfo == nil {
			stats["unknown"]++
			continue
		}
		switch {
		case sc.IPInfo.IsResidential:
			stats["residential"]++
		case sc.IPInfo.IsDatacenter || sc.IPInfo.IsHosting:
			stats["datacenter"]++
		case sc.IPInfo.IsProxy || sc.IPInfo.IsVPN:
			stats["proxy_vpn"]++
		default:
			stats["unknown"]++
		}
	}
	return stats
}

// InvalidateNode удаляет score для узла (при смене IP или ошибке).
func (s *Selector) InvalidateNode(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.scores, nodeID)
}

// calcAntiBlockScore вычисляет Anti-Block score узла: чем выше, тем лучше.
//
// Компоненты:
//
//	+80  residential ISP
//	+40  не datacenter + не proxy
//	-60  datacenter/hosting
//	-80  proxy/VPN flag
//	-20  известный хостинговый org/ASN
//	+20  хороший нативный score узла (latency-based)
func calcAntiBlockScore(info *iprep.IPInfo, node *models.Node) float64 {
	score := 0.0

	if info != nil {
		if info.IsResidential {
			score += 80
		}
		if !info.IsDatacenter && !info.IsProxy {
			score += 40
		}
		if info.IsDatacenter || info.IsHosting {
			score -= 60
		}
		if info.IsProxy || info.IsVPN {
			score -= 80
		}
		// Штраф за hosting ключевые слова в org
		orgLow := strings.ToLower(info.Org + " " + info.ASN)
		hostingKWs := []string{"digitalocean", "linode", "vultr", "hetzner", "ovh", "aws", "amazon"}
		for _, kw := range hostingKWs {
			if strings.Contains(orgLow, kw) {
				score -= 20
				break
			}
		}
		// Бонус за хороший risk score
		if info.RiskScore < 20 {
			score += 15
		}
	}

	// Бонус за хорошую задержку узла (уже проверенные узлы)
	if node != nil && node.Latency > 0 && node.Latency < 200 {
		score += 10
	}
	if node != nil && node.Score > 5 {
		score += 10
	}

	return score
}
