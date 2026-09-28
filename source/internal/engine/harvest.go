package engine

// harvest.go — L5-ENG (ТЗ v1.4 §5 «ИИ-подбор узлов»): движковая обвязка харвестера.
//
// Конвейер (AI-6):
//
//	sources.Manager.FetchRawBodies → тела → harvester.Run → []Candidate
//	  → parser.Parse* (в recover-обёртке) → mergeFetchedNodes (граница доверия) → пул
//	  → очередь проверки (существующий скан/StartNodeCheck: узлы входят Score-0, не автоконнектятся)
//
// Границы ответственности (инварианты пакета harvester):
//   - I-1: харвестер сам в сеть не ходит. Сырые тела приносит движок (FetchRawBodies) — с теми же
//     hardened do()+10 МБ cap, что и боевой FetchAll; источники ТОЛЬКО из конфигурации (SSRF-поле
//     не растёт). Ссылки-подписки (KindSubscriptionURL) движок из харвестера НЕ качает — отдаёт их
//     в UI, пользователь добавит источником сам.
//   - Разбор ссылок — parser (не харвестер). Каждый parser.Parse* обёрнут в recover: одна
//     вредоносная/битая строка не имеет права уронить весь проход (defense-in-depth поверх того,
//     что в проде parser не паникует).
//   - Запись в пул — ТОЛЬКО mergeFetchedNodes (ValidateNode + надгробия + дедуп). Узлы входят
//     непроверенными; «рабочим» узел делает лишь TUN-проба движка, не харвест.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/harvester"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
	"github.com/apf/adaptive-pathfinder/internal/sources"
)

// HarvestResult — итог одного ручного прохода для UI. Report несёт сырые счётчики харвестера
// (Found/ModelOnly/NotSubstring/Rejected/Stopped/Candidates), остальные поля заполняет движок.
type HarvestResult struct {
	Report harvester.Report `json:"report"`

	// Parsed — сколько кандидатов parser.Parse* превратил в узлы (до слияния/валидации пула).
	Parsed int `json:"parsed"`
	// ParseFailed — кандидатов парсер не осилил (в т.ч. пойманные recover паники).
	ParseFailed int `json:"parse_failed"`
	// Merged — сколько НОВЫХ узлов добавлено в пул (после ValidateNode/надгробий/дедупа).
	Merged int `json:"merged"`
	// SubscriptionURLs — найдено ссылок-подписок (движок их НЕ качает — I-1/дизайн). Сами ссылки
	// остаются в Report.Candidates (Kind=subscription_url) для показа в UI.
	SubscriptionURLs int `json:"subscription_urls"`

	Elapsed time.Duration `json:"elapsed"`
}

// ErrHarvestBusy — предыдущий проход харвеста ещё идёт (single-flight, harvestActive).
var ErrHarvestBusy = fmt.Errorf("харвест уже идёт")

// HarvestNow — ручной проход харвестера по настроенным источникам (кнопка «Обновить узлы»).
// Синхронный: вызывающий (web/gui-обработчик) обязан запускать в своей горутине и управлять
// таймаутом через ctx; внутренний бюджет харвестера — дополнительный потолок (Budget.Timeout).
func (e *Engine) HarvestNow(ctx context.Context) (*HarvestResult, error) {
	if !e.harvestActive.CompareAndSwap(false, true) {
		return nil, ErrHarvestBusy
	}
	defer e.harvestActive.Store(false)

	start := time.Now()

	e.mu.RLock()
	cfg := e.cfg
	// Снимок пула для санитайзера секретов харвестера (SecretsFromNodes): секреты УЖЕ известных
	// узлов не должны утечь в модель/лог. В v1.4 модели нет, но передаём для корректности.
	known := make([]*models.Node, len(e.nodes))
	copy(known, e.nodes)
	e.mu.RUnlock()

	if cfg == nil {
		return nil, fmt.Errorf("харвест: конфигурация недоступна")
	}

	// SourceID → имя, для провенанса добавленных узлов (models.Node.Source).
	srcName := make(map[string]string, len(cfg.Sources))
	for _, s := range cfg.Sources {
		srcName[s.ID] = s.Name
	}

	// I-1: тела источников приносит движок (та же связка, что боевой FetchAll — hardened do()+cap).
	mgr := sources.New(cfg)
	bodies, err := mgr.FetchRawBodies(ctx)
	if err != nil {
		return nil, fmt.Errorf("харвест: загрузка источников: %w", err)
	}

	h := harvester.New(harvester.Options{KnownNodes: known})
	in := harvester.RunInput{
		Sources:  cfg.Sources,
		Bodies:   bodies,
		UseModel: false, // v1.4: модельного рантайма нет; детерминированный экстрактор самодостаточен
		Budget:   harvester.DefaultBudget(),
	}

	var progress func(harvester.Progress)
	if e.OnHarvestProgress != nil {
		progress = e.OnHarvestProgress
	}

	rep, err := h.Run(ctx, in, progress)
	if err != nil {
		return nil, fmt.Errorf("харвест: проход по источникам: %w", err)
	}

	nodes, parsed, parseFailed, subURLs := harvestCandidatesToNodes(rep.Candidates, srcName)
	merged := e.mergeFetchedNodes(nodes, "Харвест источников")

	res := &HarvestResult{
		Report:           rep,
		Parsed:           parsed,
		ParseFailed:      parseFailed,
		Merged:           merged,
		SubscriptionURLs: subURLs,
		Elapsed:          time.Since(start),
	}

	e.log(fmt.Sprintf(
		"Харвест: источников обработано %d/%d, кандидатов %d, распознано узлов %d, добавлено новых %d, ссылок-подписок %d%s",
		rep.SourcesProcessed, rep.SourcesTotal, rep.Found, parsed, merged, subURLs, harvestStoppedSuffix(rep.Stopped)))

	return res, nil
}

// HarvestFromText — детерминированный разбор ПРОИЗВОЛЬНОГО текста, вставленного пользователем
// (кнопка «Извлечь узлы из текста»): несколько ссылок сразу, дамп из Telegram/страницы, base64-
// или Clash-подписка. В отличие от HarvestNow, тело приносит не sources.Manager, а сам пользователь,
// поэтому I-1 (харвестер не ходит в сеть) соблюдён тривиально: ни одного сетевого запроса здесь нет,
// ссылки-подписки (KindSubscriptionURL) не качаются — как и в HarvestNow, лишь считаются.
//
// Синтетический источник {ID:"paste"} нужен только чтобы harvester.Run сопоставил тело с включённым
// источником (см. active-фильтр в run.go); в конфиг/пул источников он НЕ попадает. Узлы получают
// Source="Вставленный текст" для провенанса, а запись в пул идёт через ту же границу доверия, что и
// у HarvestNow (mergeFetchedNodes: ValidateNode + надгробия + дедуп). «Рабочим» узел делает только
// TUN-проба движка, не харвест.
func (e *Engine) HarvestFromText(ctx context.Context, text string) (*HarvestResult, error) {
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("харвест из текста: пустой ввод")
	}
	if !e.harvestActive.CompareAndSwap(false, true) {
		return nil, ErrHarvestBusy
	}
	defer e.harvestActive.Store(false)

	start := time.Now()

	// Снимок пула для санитайзера секретов (как в HarvestNow): секреты известных узлов не должны
	// утечь в отчёт/лог.
	e.mu.RLock()
	known := make([]*models.Node, len(e.nodes))
	copy(known, e.nodes)
	e.mu.RUnlock()

	const pasteID = "paste"
	const pasteName = "Вставленный текст"
	pasteSrc := models.SourceConfig{ID: pasteID, Name: pasteName, Type: "manual", Enabled: true}
	srcName := map[string]string{pasteID: pasteName}
	bodies := map[string][]byte{pasteID: []byte(text)}

	h := harvester.New(harvester.Options{KnownNodes: known})
	in := harvester.RunInput{
		Sources:  []models.SourceConfig{pasteSrc},
		Bodies:   bodies,
		UseModel: false, // детерминированный экстрактор самодостаточен (модели в сборке нет)
		Budget:   harvester.DefaultBudget(),
	}

	var progress func(harvester.Progress)
	if e.OnHarvestProgress != nil {
		progress = e.OnHarvestProgress
	}

	rep, err := h.Run(ctx, in, progress)
	if err != nil {
		return nil, fmt.Errorf("харвест из текста: разбор: %w", err)
	}

	nodes, parsed, parseFailed, subURLs := harvestCandidatesToNodes(rep.Candidates, srcName)
	merged := e.mergeFetchedNodes(nodes, pasteName)

	res := &HarvestResult{
		Report:           rep,
		Parsed:           parsed,
		ParseFailed:      parseFailed,
		Merged:           merged,
		SubscriptionURLs: subURLs,
		Elapsed:          time.Since(start),
	}

	e.log(fmt.Sprintf(
		"Харвест из текста: кандидатов %d, распознано узлов %d, добавлено новых %d, ссылок-подписок %d%s",
		rep.Found, parsed, merged, subURLs, harvestStoppedSuffix(rep.Stopped)))

	return res, nil
}

// harvestCandidatesToNodes — чистое (тестируемое без сети) превращение кандидатов харвестера в
// узлы пула. Диспетчеризация по Kind; каждый parser.Parse* — в recover-обёртке. Ссылки-подписки
// НЕ качаются (I-1/дизайн), только считаются.
func harvestCandidatesToNodes(cands []harvester.Candidate, srcName map[string]string) (nodes []*models.Node, parsed, parseFailed, subURLs int) {
	for _, c := range cands {
		switch c.Kind {
		case harvester.KindNodeURI:
			n, err := safeParseLink(c.Normalized)
			if err != nil || n == nil {
				parseFailed++
				continue
			}
			if name := srcName[c.SourceID]; name != "" {
				n.Source = name
			}
			nodes = append(nodes, n)
			parsed++

		case harvester.KindConfigBlob:
			blobNodes, err := safeParseBlob(c.Normalized)
			if err != nil || len(blobNodes) == 0 {
				parseFailed++
				continue
			}
			for _, n := range blobNodes {
				if n == nil {
					continue
				}
				if name := srcName[c.SourceID]; name != "" {
					n.Source = name
				}
				nodes = append(nodes, n)
				parsed++
			}

		case harvester.KindSubscriptionURL:
			// Движок НЕ качает URL из харвестера (I-1/дизайн): ссылка остаётся в Report.Candidates
			// для UI, пользователь добавит её источником сам.
			subURLs++
		}
	}
	return nodes, parsed, parseFailed, subURLs
}

// safeParseLink — parser.ParseLink в recover-обёртке (defense-in-depth L5-ENG). В проде парсер не
// паникует (проверено), но одна вредоносная строка из недоверенного источника не имеет права
// уронить весь проход харвеста — паника превращается в обычную ошибку разбора.
func safeParseLink(raw string) (n *models.Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = nil, fmt.Errorf("паника разбора ссылки узла: %v", r)
		}
	}()
	return parser.ParseLink(raw)
}

// safeParseBlob — разбор конфигурационного блоба в recover-обёртке. Секция Clash YAML (начинается
// с «proxies:») → ParseClashYAML; иначе base64/построчная подписка → ParseSubscription.
func safeParseBlob(raw string) (nodes []*models.Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			nodes, err = nil, fmt.Errorf("паника разбора конфиг-блоба: %v", r)
		}
	}()
	if strings.Contains(raw, "proxies:") {
		return parser.ParseClashYAML([]byte(raw))
	}
	return parser.ParseSubscription([]byte(raw))
}

// harvestStoppedSuffix — человеческий хвост к строке лога, если проход не дошёл до конца.
func harvestStoppedSuffix(stopped string) string {
	switch stopped {
	case "":
		return ""
	case "timeout":
		return " (остановлено по таймауту)"
	case "canceled":
		return " (отменено)"
	case "budget":
		return " (достигнут лимит кандидатов)"
	default:
		return " (остановлено: " + stopped + ")"
	}
}
