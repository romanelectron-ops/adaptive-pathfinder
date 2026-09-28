package harvester

// run.go — оркестрация одного прохода (AI-2): бюджеты, отмена, деградация без модели,
// порядок очереди (I-5). Сам поиск кандидатов здесь не делается — только вызов экстракторов и
// сведение их результатов в один Report.

import (
	"context"
	"errors"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Options — настройки одного Harvester. Собирается один раз (например, при старте движка),
// Run можно звать многократно с разными RunInput.
type Options struct {
	// MemProbe — замер свободной памяти для порога модельного пути (AI-10). nil ⇒ SystemMemAvailable.
	MemProbe MemProbe
	// Deterministic — детерминированный экстрактор. nil ⇒ NewDeterministicExtractor().
	// Точка подмены для тестов оркестрации (медленный/блокирующийся экстрактор).
	Deterministic Extractor
	// Model — модельный путь. nil ⇒ модель не используется вообще, RunInput.UseModel=true
	// в этом случае просто попадает в Report.ModelSkipped, а не в ошибку (AI-10, деградация).
	Model ModelExtractor
	// KnownNodes — узлы, уже известные пулу движка. Их секреты (SecretsFromNodes) вырезаются
	// из тела источника ДО того, как оно уйдёт в модель (AI-5, TestModelNeverSeesKnownSecrets).
	KnownNodes []*models.Node
}

// harvesterImpl — реализация контракта Harvester. Ровно два метода — I-3/I-4 требуют, чтобы
// других не было вовсе (см. invariants_test.go), поэтому вся остальная логика вынесена в
// пакетные функции, а не в методы этого типа.
type harvesterImpl struct {
	opts Options
}

// New — единственный конструктор Harvester.
func New(opts Options) Harvester {
	if opts.MemProbe == nil {
		opts.MemProbe = SystemMemAvailable
	}
	if opts.Deterministic == nil {
		opts.Deterministic = NewDeterministicExtractor()
	}
	return &harvesterImpl{opts: opts}
}

// Available — AI-2/AI-10: сколько памяти есть, сколько нужно модели, и есть ли модель вообще.
func (h *harvesterImpl) Available() Availability {
	avail, known := h.opts.MemProbe()
	if h.opts.Model == nil {
		return Availability{
			ModelPresent:      false,
			DeterministicOnly: true,
			RequiredMemBytes:  MinFreeMemForModel,
			AvailableMemBytes: avail,
			MemKnown:          known,
			Reason:            "модельного рантайма нет в этой сборке (v1.4); поиск по источникам работает без него",
		}
	}
	av := h.opts.Model.Availability()
	av.AvailableMemBytes = avail
	av.MemKnown = known
	if av.RequiredMemBytes == 0 {
		av.RequiredMemBytes = MinFreeMemForModel
	}
	return av
}

// rejectingExtractor — экстракторы, которые вдобавок к Extract умеют объяснить отказы
// (сейчас — только DeterministicExtractor). Подставные экстракторы тестов оркестрации этого
// не умеют — для них Run довольствуется одним Extract, без записи в Report.Rejected.
type rejectingExtractor interface {
	extractWithRejects(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, []RejectedItem, error)
}

func runExtract(ctx context.Context, ex Extractor, body []byte, src SourceMeta) ([]Candidate, []RejectedItem, error) {
	if re, ok := ex.(rejectingExtractor); ok {
		return re.extractWithRejects(ctx, body, src)
	}
	cands, err := ex.Extract(ctx, body, src)
	return cands, nil, err
}

// stopReasonFor — Report.Stopped из ошибки контекста. "" для любой другой ошибки: Run её и
// так вернёт вызывающему, отдельная причина остановки тут не нужна.
func stopReasonFor(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return ""
	}
}

// Run — контракт Harvester (AI-2). Подробное поведение см. в run_test.go; в двух словах:
//
//	Bodies == nil            → ошибка (I-1: харвестер сам не качает, это дело вызывающего).
//	источник без тела/выключен → тихо пропущен, это не ошибка прохода.
//	MaxBodyBytes/MaxCandidates/Timeout/ctx.Done → частичный отчёт с Report.Stopped, БЕЗ ошибки.
//	UseModel без готовой модели → Report.ModelSkipped, детерминированный путь всё равно полный.
//	кандидаты модели             → guardModelCandidates, потом СТРОГО после детерминированных (I-5).
func (h *harvesterImpl) Run(ctx context.Context, in RunInput, progress func(Progress)) (Report, error) {
	if in.Bodies == nil {
		return Report{}, errors.New("harvester: тела источников не переданы (I-1) — харвестер сам не ходит в сеть, вызывающий обязан их получить")
	}

	budget := in.Budget.Normalize()
	start := time.Now()

	runCtx := ctx
	if budget.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, budget.Timeout)
		defer cancel()
	}

	var active []models.SourceConfig
	for _, s := range in.Sources {
		if !s.Enabled {
			continue
		}
		if _, ok := in.Bodies[s.ID]; !ok {
			continue
		}
		active = append(active, s)
	}
	if len(active) > budget.MaxSources {
		active = active[:budget.MaxSources]
	}

	det := h.opts.Deterministic
	if det == nil {
		det = NewDeterministicExtractor()
	}

	modelSkipped := ""
	useModel := false
	if in.UseModel {
		if h.opts.Model == nil {
			modelSkipped = "модель недоступна: модельного рантайма в этой сборке нет; поиск по источникам работает без него"
		} else if err := CheckModelPreconditions(budget, h.opts.MemProbe); err != nil {
			modelSkipped = err.Error()
		} else {
			useModel = true
		}
	}

	secrets := SecretsFromNodes(h.opts.KnownNodes)

	rep := Report{ByExtractor: map[string]int{}, SourcesTotal: len(active)}
	var detCandidates []Candidate
	var modelCandidates []Candidate
	stopped := ""

	for i, src := range active {
		if err := runCtx.Err(); err != nil {
			stopped = stopReasonFor(err)
			break
		}

		body := in.Bodies[src.ID]
		if int64(len(body)) > budget.MaxBodyBytes {
			body = body[:budget.MaxBodyBytes]
			rep.Truncated++
		}

		meta := MetaFromConfig(src)
		cands, rejs, err := runExtract(runCtx, det, body, meta)
		if err != nil {
			stopped = stopReasonFor(err)
			break
		}

		rep.ByExtractor[det.Name()] += len(cands)
		if len(rejs) > 0 {
			rep.Rejected = append(rep.Rejected, rejs...)
			for _, r := range rejs {
				if r.Reason == ReasonDuplicate {
					rep.Duplicate++
				}
			}
		}
		detCandidates = append(detCandidates, cands...)
		rep.SourcesProcessed++

		if useModel {
			known := make(map[string]bool, len(cands))
			for _, c := range cands {
				known[c.Raw] = true
			}
			cleanBody := secrets.Sanitize(string(body))
			mres, merr := h.opts.Model.Extract(runCtx, []byte(cleanBody), meta)
			if merr != nil {
				if modelSkipped == "" {
					modelSkipped = "модель вернула ошибку, используется детерминированный результат: " + merr.Error()
				}
			} else {
				kept, mrejs, notSub := guardModelCandidates(body, meta, mres, known)
				rep.NotSubstring += notSub
				if len(mrejs) > 0 {
					rep.Rejected = append(rep.Rejected, mrejs...)
					for _, r := range mrejs {
						if r.Reason == ReasonDuplicate {
							rep.Duplicate++
						}
					}
				}
				rep.ModelOnly += len(kept)
				modelCandidates = append(modelCandidates, kept...)
			}
		}

		if progress != nil {
			progress(Progress{
				Phase:       "running",
				SourceIndex: i + 1,
				SourceTotal: len(active),
				SourceID:    src.ID,
				Found:       len(detCandidates) + len(modelCandidates),
				ElapsedSec:  int(time.Since(start).Seconds()),
			})
		}

		if len(detCandidates)+len(modelCandidates) >= budget.MaxCandidates {
			stopped = "budget"
			break
		}
	}

	// I-5: кандидаты модели идут СТРОГО после всех детерминированных, вне зависимости от того,
	// в каком источнике по счёту они найдены.
	all := append(detCandidates, modelCandidates...)
	if len(all) > budget.MaxCandidates {
		all = all[:budget.MaxCandidates]
		if stopped == "" {
			stopped = "budget"
		}
	}

	rep.Candidates = all
	rep.Found = len(all)
	rep.Elapsed = time.Since(start)
	rep.Stopped = stopped
	rep.ModelSkipped = modelSkipped

	if progress != nil {
		phase := "done"
		if stopped == "canceled" {
			phase = "cancelled"
		}
		progress(Progress{
			Phase:       phase,
			SourceIndex: len(active),
			SourceTotal: len(active),
			Found:       rep.Found,
			ElapsedSec:  int(rep.Elapsed.Seconds()),
		})
	}

	return rep, nil
}
