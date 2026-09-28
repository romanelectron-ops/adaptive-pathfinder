// config_normalize.go — ТЗ v1.3 F5.2 (консилиум 2026-09-03, GAP-41/42): одна функция нормализации
// конфига на всех точках входа (cmd/apf run/add, apf-svc Execute/runDirect, gui NewApp,
// androidbridge.Init). Раньше каждый вход доверял config.json как есть: порт 0/70000, режим
// "vpn " с пробелом, selection_mode "auto" (не существует — движок молча брал balanced), URL
// подписки без схемы — всё это доходило до движка и ломалось где-то глубоко и молча.
package models

import (
	"fmt"
	"net/url"
	"strings"
)

// NodeCheckTopNAll — специальное значение node_check_top_n (NodeCheckTopN): режим «Все рабочие» —
// пробовать реальным трафиком ВЕСЬ пул рабочих кандидатов без верхнего среза (запрос владельца
// 2026-09-15: узел с трафиком может ранжироваться ниже числового потолка top-N по TCP-скору и
// тогда не пробуется никогда). Значение выбрано так, чтобы:
//   - пережить нормализацию/валидацию (Normalize ниже и engine.validatePatch сознательно
//     пропускают РОВНО это число мимо клампа 10–300);
//   - в engine/node_check.go никогда не срезать реальный пул: ranked[:TopN] не режет, а
//     Stage-2-виджен TopN×nodeCheckWidenFactor не переполняет int (сборки только 64-битные,
//     arm64-v8a/amd64; но и в int32 1e9×2 ещё влезает — запас двойной);
//   - оставаться безопасным для gomobile (Android Long) и JSON-числа.
// Это не «магическое ограничение сверху», а сигнал «без ограничения»: любое ДРУГОЕ значение
// > 300 по-прежнему клампится к 300 (ручная правка config.json), сигналом служит лишь точное
// совпадение — его шлёт только UI-пункт «Все рабочие».
const NodeCheckTopNAll = 1_000_000_000

// Normalize приводит конфиг к допустимым значениям на месте и возвращает список предупреждений
// (что и на что заменено). Никогда не возвращает ошибку: неверное значение — это дефолт + WARN,
// а не отказ стартовать. Правила согласованы с validatePatch движка (те же диапазоны).
func (c *AppConfig) Normalize() []string {
	if c == nil {
		return nil
	}
	d := DefaultConfig()
	var warns []string
	warn := func(format string, a ...interface{}) { warns = append(warns, fmt.Sprintf(format, a...)) }

	// Порты. WebUIPort=0 — допустимое «выключено» (Android так и делает).
	if c.ListenPort < 1024 || c.ListenPort > 65530 {
		warn("listen_port=%d вне 1024–65530 → %d", c.ListenPort, d.ListenPort)
		c.ListenPort = d.ListenPort
	}
	if c.WebUIPort != 0 && (c.WebUIPort < 1024 || c.WebUIPort > 65535) {
		warn("webui_port=%d вне 1024–65535 → %d", c.WebUIPort, d.WebUIPort)
		c.WebUIPort = d.WebUIPort
	}
	if c.WebUIPort != 0 && c.WebUIPort == c.ListenPort {
		alt := d.WebUIPort
		if alt == c.ListenPort {
			alt = d.WebUIPort + 1
		}
		warn("webui_port=%d совпадает с listen_port → %d", c.WebUIPort, alt)
		c.WebUIPort = alt
	}

	// Интервалы и пороги.
	if c.CheckInterval < 5 || c.CheckInterval > 3600 {
		warn("check_interval_sec=%d вне 5–3600 → %d", c.CheckInterval, d.CheckInterval)
		c.CheckInterval = d.CheckInterval
	}
	if c.MaxLatency < 100 {
		warn("max_latency_ms=%d < 100 → %d", c.MaxLatency, d.MaxLatency)
		c.MaxLatency = d.MaxLatency
	}
	if c.MinUptimeSec < 0 {
		warn("min_uptime_sec=%d < 0 → 0", c.MinUptimeSec)
		c.MinUptimeSec = 0
	}
	if c.DNSLeakTestInterval < 0 {
		warn("dns_leak_test_interval=%d < 0 → 0 (выключено)", c.DNSLeakTestInterval)
		c.DNSLeakTestInterval = 0
	}
	if c.MaxConnectedClients < 0 {
		warn("max_connected_clients=%d < 0 → 0 (дефолт платформы)", c.MaxConnectedClients)
		c.MaxConnectedClients = 0
	}
	if c.MultiHopCount != 0 && c.MultiHopCount != 2 && c.MultiHopCount != 3 {
		warn("multihop_count=%d ∉ {2,3} → 2", c.MultiHopCount)
		c.MultiHopCount = 2
	}
	// NodeCheckTopN (ТЗ v1.7, PROBE-DEPTH-SETTING): 0 остаётся 0 — это «использовать встроенный
	// дефолт движка» (node_check.go, defaultNodeCheckTopN=30), а не значение, которое надо
	// подменять на d.NodeCheckTopN (тот тоже 0). Ненулевое значение клампится в 10–300, тот же
	// диапазон, что и validatePatch движка (engine.go, case "node_check_top_n").
	if c.NodeCheckTopN < 0 {
		warn("node_check_top_n=%d < 0 → 0 (встроенный дефолт)", c.NodeCheckTopN)
		c.NodeCheckTopN = 0
	} else if c.NodeCheckTopN == NodeCheckTopNAll {
		// Режим «Все рабочие» — сознательный проход мимо клампа 10–300, без WARN. См.
		// NodeCheckTopNAll выше: пробуем весь пул, сколько бы узлов в нём ни было.
	} else if c.NodeCheckTopN > 0 && c.NodeCheckTopN < 10 {
		warn("node_check_top_n=%d < 10 → 10", c.NodeCheckTopN)
		c.NodeCheckTopN = 10
	} else if c.NodeCheckTopN > 300 {
		warn("node_check_top_n=%d > 300 → 300", c.NodeCheckTopN)
		c.NodeCheckTopN = 300
	}

	// Перечисления: пробелы/регистр прощаем, неизвестное → дефолт.
	c.ConnectionMode = normEnum("connection_mode", c.ConnectionMode, d.ConnectionMode,
		[]string{ModeProxy, ModeVPN, ModeHybrid}, nil, &warns)
	c.SelectionMode = normEnum("selection_mode", c.SelectionMode, "balanced",
		[]string{"balanced", "speed", "stealth", "streaming"},
		map[string]string{"": "balanced", "auto": "balanced", "fast": "speed"}, &warns)
	c.StickySessionPolicy = normEnum("sticky_session_policy", c.StickySessionPolicy, "",
		[]string{"", "sticky", "free", "timed"}, nil, &warns)
	c.AdBlockProfile = normEnum("adblock_profile", c.AdBlockProfile, "disabled",
		[]string{"", "disabled", "light", "standard", "strict"}, nil, &warns)
	c.Mode = normEnum("mode", c.Mode, d.Mode,
		[]string{"", "auto", "manual", "chain", "tor"}, nil, &warns)

	// C-16 (ТЗ v1.4, замечание C1 живого прогона): источники, которых эта сборка не
	// поддерживает, УДАЛЯЮТСЯ из сохранённого конфига. K2-E убрал фиктивный "tor-snowflake"
	// из дефолтов, но у каждого, кто обновляется поверх старой установки, запись осталась в
	// files/config.json: каталог её не показывает, а она живёт. Механизм общий — список ниже
	// пополняется по мере удаления источников.
	if len(c.Sources) > 0 {
		kept := c.Sources[:0]
		for _, src := range c.Sources {
			if deadSourceIDs[strings.ToLower(strings.TrimSpace(src.ID))] {
				warn("источник %s удалён: не поддерживается этой сборкой", src.ID)
				continue
			}
			kept = append(kept, src)
		}
		c.Sources = kept
	}

	// Источники: URL обязан разбираться и иметь http/https-схему (кроме встроенных типов
	// tor/manual без URL). Неверный источник не удаляется — выключается, чтобы пользователь
	// увидел его в списке и поправил.
	for i := range c.Sources {
		s := &c.Sources[i]
		s.URL = strings.TrimSpace(s.URL)
		if s.UpdateIntervalHours < 0 {
			warn("sources[%s].update_interval_hours=%d < 0 → 0", s.ID, s.UpdateIntervalHours)
			s.UpdateIntervalHours = 0
		}
		if !s.Enabled || s.URL == "" {
			continue
		}
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			warn("sources[%s].url=%q не разбирается как http(s)-URL → источник выключен", s.ID, s.URL)
			s.Enabled = false
		}
	}
	return warns
}

// deadSourceIDs — ID источников, которых в этой сборке нет и не будет (C-16).
//
// "tor-snowflake": фиктивный источник, удалённый из дефолтов лотом K2-E. Реализации у него не
// было никогда — Snowflake APF передать в sing-box нечем (см. fallback.ErrSnowflakeNotApplicable
// и пункт C-6 ТЗ v1.4). Оставлять запись в конфиге пользователя значит обещать источник узлов,
// которого не существует.
var deadSourceIDs = map[string]bool{
	"tor-snowflake": true,
}

// normEnum — значение из allowed (с trim/lower), иначе alias → allowed, иначе def + WARN.
func normEnum(field, val, def string, allowed []string, aliases map[string]string, warns *[]string) string {
	v := strings.ToLower(strings.TrimSpace(val))
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	if aliases != nil {
		if mapped, ok := aliases[v]; ok {
			return mapped
		}
	}
	*warns = append(*warns, fmt.Sprintf("%s=%q не поддерживается → %q", field, val, def))
	return def
}
