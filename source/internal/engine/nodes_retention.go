// nodes_retention.go — N-5 (ТЗ APF v1.5 §3, C9/C10/C11): политика удержания пула НА ЗАПИСЬ.
//
// DATA-LOSS-CRITICAL (C9/O8, консилиум — BLOCKER): без учёта закреплённого/избранного узла,
// который ещё ни разу не подтвердил трафик, следующая запись на диск потеряла бы его безвозвратно
// — cfg.PinnedNode/cfg.Favorites продолжали бы ссылаться на ID, которого в пуле больше нет
// (pin показывал бы статус "missing", избранное — висело бы на ничто).
//
// Фильтр применяется ТОЛЬКО в saveNodesToDisk (engine.go), ТОЛЬКО на КОПИЮ перед
// json.MarshalIndent/шифрованием. In-memory e.nodes остаётся ПОЛНЫМ всегда — фильтрация на чтение
// сломала бы сканирование/выбор (им нужен весь пул, включая непроверенные и стухшие записи).
// Отфильтрованным узлам НАДГРОБИЕ НЕ СТАВИТСЯ (C11/O10): они просто отсутствуют в следующем
// массиве и ничто не мешает им вернуться из источников при следующем updateSources.
//
// W3 (ТЗ v1.5 §4, TZ_v1.5_NODE_CATALOG_2026-09-14): двухклассовое избранное (models.NodeRef.
// Origin) добавляет ПОТОЛОК, но только для системного класса — favoriteRetentionSet ниже
// разводит переданные ссылки на "без потолка" (user, включая миграционные Origin=="" —
// EffectiveOrigin()) и "top SystemFavoriteCap по качеству" (system). retainNodeForDisk НЕ
// меняется вообще: её контракт/сигнатура/тест (nodes_retention_test.go, TestRetention_
// FilterMatrix) остаются как были — она остаётся тупой OR-функцией одного узла над уже готовым
// множеством "ID, которые в целях удержания считаются избранными", посчитанным ниже.
package engine

import (
	"sort"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// SystemFavoriteCap — потолок числа СИСТЕМНЫХ фаворитов (W3 §2/§4, owner-декрет консилиума
// TZ_v1.5_NODE_CATALOG_2026-09-14: "~30"). Применяется дважды, к одному и тому же множеству по
// одному и тому же правилу (best-by-quality — см. sortSystemFavoriteIDsByQuality): в
// enforceSystemFavoriteCap (engine.go, сразу после реконсиляции runNodeCheck — держит e.favRefs
// в памяти в потолке) и здесь, в favoriteRetentionSet (защита на запись — если по любой причине
// в памяти оказалось системных фаворитов больше потолка, на диск всё равно уйдёт не больше
// SystemFavoriteCap). НЕ применяется к пользовательскому классу и ни к одному другому критерию
// удержания (pin/manual/chain-partner/proven-fresh) — safeguard #2/#6 консилиума.
var SystemFavoriteCap = 30

// retainNodeForDisk — N-5: узел удерживается на диске, если ЛЮБОЕ из:
//
//	(а) IsProven() && !VerifyStale(now)  — подтверждён трафиком, и подтверждение ещё не протухло;
//	(б) IsUserOwned()                    — Source=="manual" || IsChainPartner (N-7): ручной узел
//	                                        или партнёр цепочки Вход-Выход — уникален и
//	                                        невосстановим из публичных источников, удерживается
//	                                        ДАЖЕ мёртвым (manual-dead, консилиум §5);
//	(в) id == pinnedID                   — закреплённый пользователем узел;
//	(г) id ∈ favoriteIDs                 — избранный узел.
//
// K (TargetK у StartNodeCheck, node_check.go) — порог ОСТАНОВКИ пробы, НЕ потолок удержания
// (C10/O11): здесь K вообще не участвует — удерживается любое число proven-fresh узлов.
//
// W3: favoriteIDs, которую эта функция получает, уже ГОТОВОЕ множество — потолок системного
// класса применён ВЫШЕ, в favoriteRetentionSet. Сама retainNodeForDisk класс не знает и не
// обязана знать (сигнатура/тест N-5 не меняются).
func retainNodeForDisk(n *models.Node, nowUnix int64, pinnedID string, favoriteIDs map[string]bool) bool {
	if n == nil {
		return false
	}
	if n.IsProven() && !n.VerifyStale(nowUnix) {
		return true
	}
	if n.IsUserOwned() {
		return true
	}
	if pinnedID != "" && n.ID == pinnedID {
		return true
	}
	if favoriteIDs[n.ID] {
		return true
	}
	return false
}

// filterNodesForRetention строит ОТФИЛЬТРОВАННУЮ КОПИЮ среза узлов для записи на диск (N-5).
// Порядок узлов сохраняется. Пустой результат — ВАЛИДНЫЙ исход (крайний случай §3 N-5): вызывающий
// пишет пустой массив, а не отменяет запись — следующий старт корректно ведёт себя как первый
// (re-fetch, N-6). Возвращает НЕ nil даже для пустого входа/результата, чтобы
// json.MarshalIndent дал "[]", а не "null".
//
// W3: 4-й параметр — снимок ВСЕГО избранного (models.NodeRef, класс включён), а не голые ID —
// favoriteRetentionSet ниже разводит его на "без потолка" (user) и "top SystemFavoriteCap"
// (system) ПЕРЕД тем, как отдать retainNodeForDisk. Вызывающий (saveNodesToDisk) передаёт
// e.FavoriteRefs(), а не e.FavoriteIDs() — тот остаётся для потребителей, которым класс не нужен.
func filterNodesForRetention(nodes []*models.Node, nowUnix int64, pinnedID string, favRefs []models.NodeRef) []*models.Node {
	favSet := favoriteRetentionSet(nodes, favRefs)
	out := make([]*models.Node, 0, len(nodes))
	for _, n := range nodes {
		if retainNodeForDisk(n, nowUnix, pinnedID, favSet) {
			out = append(out, n)
		}
	}
	return out
}

// favoriteRetentionSet — W3 (safeguard #1/#2/#6): единственное место, где потолок системного
// класса применяется НА ЗАПИСЬ. Пользовательский класс (EffectiveOrigin()==OriginUser — это и
// есть миграционные записи с Origin=="", safeguard #1) проходит целиком, без ограничения.
// Системный — только TOP SystemFavoriteCap по качеству (sortSystemFavoriteIDsByQuality);
// остальные системные ID просто не попадают в возвращённое множество — retainNodeForDisk может
// всё равно удержать такой узел по ЛЮБОМУ другому независимому критерию (pin/manual/chain-
// partner/proven-fresh), поэтому "не влез в потолок избранного" НЕ значит "потерян", если узел
// удерживается ещё и по другой причине (safeguard #4/#6 — нет двойного счёта и пин переживает
// вытеснение из фаворитов).
func favoriteRetentionSet(nodes []*models.Node, favRefs []models.NodeRef) map[string]bool {
	out := make(map[string]bool, len(favRefs))
	if len(favRefs) == 0 {
		return out
	}
	byID := make(map[string]*models.Node, len(nodes))
	for _, n := range nodes {
		if n != nil {
			byID[n.ID] = n
		}
	}
	sysIDs := make([]string, 0, len(favRefs))
	for _, r := range favRefs {
		if r.ID == "" {
			continue
		}
		if r.EffectiveOrigin() == models.OriginSystem {
			sysIDs = append(sysIDs, r.ID)
			continue
		}
		out[r.ID] = true // user (в т.ч. миграционные Origin=="") — без потолка
	}
	if len(sysIDs) <= SystemFavoriteCap {
		for _, id := range sysIDs {
			out[id] = true
		}
		return out
	}
	sortSystemFavoriteIDsByQuality(sysIDs, byID)
	for _, id := range sysIDs[:SystemFavoriteCap] {
		out[id] = true
	}
	return out
}

// sortSystemFavoriteIDsByQuality — общий порядок "лучший системный фаворит первым", по которому
// решается, кто остаётся при потолке SystemFavoriteCap: выше Score — лучше, тай-брейк — меньшая
// latency (LastVerifiedLatencyMs, если узел вообще проходил post-connect/пробу, иначе TCP
// Latency). Используется и здесь (favoriteRetentionSet, запись на диск), и в
// enforceSystemFavoriteCap (engine.go, потолок в памяти сразу после реконсиляции) — ОДНО правило
// на оба места, чтобы "кто выжил на диске" и "кто выжил в избранном UI" не расходились.
// Отсутствующий в пуле узел (byID[id]==nil, теоретический край) — худший приоритет, вылетает
// первым, а не паникует.
func sortSystemFavoriteIDsByQuality(ids []string, byID map[string]*models.Node) {
	sort.SliceStable(ids, func(i, j int) bool {
		ni, nj := byID[ids[i]], byID[ids[j]]
		si, sj := nodeRetentionScore(ni), nodeRetentionScore(nj)
		if si != sj {
			return si > sj
		}
		return nodeRetentionLatency(ni) < nodeRetentionLatency(nj)
	})
}

func nodeRetentionScore(n *models.Node) float64 {
	if n == nil {
		return -1
	}
	return n.Score
}

func nodeRetentionLatency(n *models.Node) int64 {
	if n == nil {
		return 1 << 62
	}
	if n.LastVerifiedLatencyMs > 0 {
		return n.LastVerifiedLatencyMs
	}
	return n.Latency
}
