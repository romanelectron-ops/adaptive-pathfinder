package models

import "testing"

// Долг-7 (2026-09-21): честность «фактического выхода». CatalogCountry берётся из имени узла и часто
// неканонична (UK/EN/EL), фактический выход (loc= из cdn-cgi/trace) — всегда ISO. Без нормализации
// CountryMismatch давал ложный ⚠ «фактический выход отличается» на честном выходе (UK≡GB).

func TestNormalizeCountryCode(t *testing.T) {
	cases := map[string]string{
		"UK": "GB", "uk": "GB", " uk ": "GB", // самый частый псевдоним в именах VPN-узлов
		"EN": "GB", "EL": "GR",
		"US": "US", "gb": "GB", "": "", "RU": "RU",
	}
	for in, want := range cases {
		if got := normalizeCountryCode(in); got != want {
			t.Errorf("normalizeCountryCode(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestCountryMismatch_AliasesAreNotMismatch(t *testing.T) {
	cases := []struct {
		name          string // имя узла → CatalogCountry
		exitCountry   string // LastVerifiedCountry → ExitCountry
		wantMismatch  bool
		why           string
	}{
		{"UK London Premium", "GB", false, "UK≡GB — псевдоним, НЕ расхождение (был ложный ⚠)"},
		{"EN Manchester", "GB", false, "EN(England)≡GB"},
		{"EL Athens", "GR", false, "EL≡GR"},
		{"US New York", "GB", true, "US и GB — реальное расхождение выхода"},
		{"GB London", "GB", false, "точное совпадение ISO"},
		{"UK London", "", false, "фактический выход неизвестен — не расхождение"},
		{"RU Moscow", "NL", true, "заявлена RU, выход NL — реальное расхождение (K8-LIVE)"},
	}
	for _, c := range cases {
		n := &Node{Name: c.name, LastVerifiedCountry: c.exitCountry}
		if got := n.CountryMismatch(); got != c.wantMismatch {
			t.Errorf("CountryMismatch(name=%q exit=%q)=%v, want %v — %s (catalog=%q exit=%q)",
				c.name, c.exitCountry, got, c.wantMismatch, c.why, n.CatalogCountry(), n.ExitCountry())
		}
	}
}
