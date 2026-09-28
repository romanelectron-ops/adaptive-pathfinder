// config_normalize_v14_test.go — лот L1b-ENG2 ТЗ v1.4: C-16.
//
// Замечание C1 живого прогона K8-LIVE: K2-E удалил фиктивный источник "tor-snowflake" из
// ДЕФОЛТОВ, но у пользователя он остался в СОХРАНЁННОМ files/config.json и будет жить у всех,
// кто обновляется поверх. Каталог его не показывает — а запись есть.
package models

import (
	"strings"
	"testing"
)

func TestV14_C16_Normalize_RemovesDeadSource(t *testing.T) {
	c := DefaultConfig()
	c.Sources = append(c.Sources, SourceConfig{
		ID:      "tor-snowflake",
		Name:    "Tor Snowflake",
		Type:    "tor",
		Enabled: true,
	})
	before := len(c.Sources)

	warns := c.Normalize()

	for _, s := range c.Sources {
		if s.ID == "tor-snowflake" {
			t.Fatal("мёртвый источник tor-snowflake пережил нормализацию: он остаётся в " +
				"config.json у каждого, кто обновляется поверх старой установки")
		}
	}
	if len(c.Sources) != before-1 {
		t.Fatalf("удалён не ровно один источник: было %d, стало %d", before, len(c.Sources))
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "tor-snowflake") {
			found = true
		}
	}
	if !found {
		t.Fatalf("удаление источника прошло молча, предупреждения: %v", warns)
	}
}

func TestV14_C16_Normalize_KeepsLiveSources(t *testing.T) {
	c := DefaultConfig()
	before := len(c.Sources)
	ids := make([]string, 0, before)
	for _, s := range c.Sources {
		ids = append(ids, s.ID)
	}

	c.Normalize()

	if len(c.Sources) != before {
		t.Fatalf("нормализация тронула живые источники: было %d, стало %d", before, len(c.Sources))
	}
	for i, s := range c.Sources {
		if s.ID != ids[i] {
			t.Fatalf("порядок/состав источников изменился: %v", c.Sources)
		}
	}
}
