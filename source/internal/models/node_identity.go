// node_identity.go — лоты L1 и L2 из разбора внешних репозиториев (2026-10-21).
//
// L1. Транспорты в ссылках. Современные подписки (igareck и другие) раздают VLESS со
// `type=raw` (это тот же TCP, просто новое имя в Xray) и со `type=xhttp`/`splithttp`/`kcp`,
// которых нет в ядре sing-box этой сборки. Раньше `raw` отвергался как «unknown transport
// type», а xhttp/kcp — тем же невнятным текстом; теперь первое нормализуется, второе
// получает честную причину и считается отдельно.
//
// L2. Идентичность узла без `fp`. Издатели намеренно раздают один и тот же сервер в нескольких
// вариантах uTLS-отпечатка (5-7 строк на сервер). Раньше отпечаток входил в ID, и один сервер
// считался 5-7 разными узлами: пул раздувался, пробы тратились на одно и то же. Теперь ID не
// зависит от `fp`, а все увиденные отпечатки хранятся списком (Node.FPCandidates) как запас.
package models

import "strings"

// unsupportedTransportLabels — транспорты, которые встречаются в ссылках, но которых нет в ядре
// sing-box этой сборки (1.13): ключ — каноническое имя типа, значение — как назвать пользователю.
var unsupportedTransportLabels = map[string]string{
	"xhttp":     "XHTTP",
	"splithttp": "XHTTP (SplitHTTP)",
	"kcp":       "mKCP",
	"mkcp":      "mKCP",
}

// UnsupportedTransport возвращает человекочитаемое имя транспорта узла, если его нет в этой
// сборке, иначе "". Узел с таким транспортом нельзя отдавать ядру: sing-box отвергнет конфиг.
func UnsupportedTransport(n *Node) string {
	if n == nil || n.Transport == nil {
		return ""
	}
	return unsupportedTransportLabels[strings.ToLower(strings.TrimSpace(n.Transport.Type))]
}

// maxFPCandidates - потолок списка отпечатков одного узла. Стандартных имён uTLS меньше десятка;
// без потолка выдача с мусорными fp=junk1..N (тело источника до 10 МБ - десятки тысяч строк) раздувала
// бы список и кэш на диске, а слияние под общей блокировкой становилось квадратичным.
const maxFPCandidates = 12

// normalizeFP приводит отпечаток к виду для сравнения (без регистра и пробелов).
func normalizeFP(fp string) string { return strings.ToLower(strings.TrimSpace(fp)) }

// validFingerprint - имя отпечатка uTLS выглядит как имя: строчные латиница и цифры, «_»,
// не длиннее 24 знаков. Остальное (URL-мусор, пробелы, длинные строки) в список не берётся.
func validFingerprint(fp string) bool {
	if fp == "" || len(fp) > 24 {
		return false
	}
	for i := 0; i < len(fp); i++ {
		c := fp[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// NormalizeFingerprints гарантирует, что в FPCandidates есть собственный отпечаток узла
// (TLS.Fingerprint) и нет повторов. Пустой отпечаток в список не попадает. Порядок: сначала
// собственный отпечаток, затем остальные в порядке появления — так список читается как
// «основной, затем запасные».
func (n *Node) NormalizeFingerprints() {
	if n == nil {
		return
	}
	own := ""
	if n.TLS != nil {
		own = normalizeFP(n.TLS.Fingerprint)
	}
	if own == "" && len(n.FPCandidates) == 0 {
		return
	}
	out := make([]string, 0, minInt(len(n.FPCandidates)+1, maxFPCandidates))
	add := func(fp string) {
		fp = normalizeFP(fp)
		if len(out) >= maxFPCandidates || !validFingerprint(fp) {
			return
		}
		for _, x := range out { // список не длиннее maxFPCandidates - линейный просмотр дешевле map
			if x == fp {
				return
			}
		}
		out = append(out, fp)
	}
	add(own)
	for _, fp := range n.FPCandidates {
		if len(out) >= maxFPCandidates {
			break
		}
		add(fp)
	}
	if len(out) == 0 {
		n.FPCandidates = nil
		return
	}
	n.FPCandidates = out
}

// MergeFingerprints дописывает в n отпечатки, под которыми тот же сервер раздавал other (лот L2).
// Собственный отпечаток n (тот, что уходит ядру) НЕ меняется: запасные варианты только копятся.
// Возвращает true, если список изменился.
func (n *Node) MergeFingerprints(other *Node) bool {
	if n == nil || other == nil {
		return false
	}
	n.NormalizeFingerprints()
	other.NormalizeFingerprints()
	changed := false
	for _, fp := range other.FPCandidates {
		if len(n.FPCandidates) >= maxFPCandidates {
			break
		}
		known := false
		for _, x := range n.FPCandidates {
			if x == fp {
				known = true
				break
			}
		}
		if !known {
			n.FPCandidates = append(n.FPCandidates, fp)
			changed = true
		}
	}
	return changed
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
