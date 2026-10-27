package engine

import "strings"

// routineSingBoxLine — строки INFO sing-box, которые не нужны в ФАЙЛЕ лога: «inbound connection
// from/to» (по две на каждое соединение приложения, ~40 % объёма в живом логе ПК 2026-10-27; адрес
// назначения и исход остаются в строке «outbound connection to») и «dns: cached» (ответ из кэша).
// ERROR/WARN и всё прочее не трогаются. Окно лога в приложении и разбор маршрутов в Web UI читают
// строки напрямую из OnLog и этим фильтром не затронуты.
func routineSingBoxLine(msg string) bool {
	if !strings.Contains(msg, "[sing-box]") {
		return false
	}
	if strings.Contains(msg, "ERROR") || strings.Contains(msg, "WARN") || strings.Contains(msg, "FATAL") {
		return false
	}
	switch {
	case strings.Contains(msg, "]: inbound connection from "),
		strings.Contains(msg, "]: inbound connection to "),
		strings.Contains(msg, "]: inbound packet connection from "),
		strings.Contains(msg, "]: inbound packet connection to "),
		strings.Contains(msg, " dns: cached "):
		return true
	}
	return false
}
