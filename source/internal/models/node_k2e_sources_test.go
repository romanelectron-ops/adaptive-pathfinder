// node_k2e_sources_test.go — К2-E П7(в) (свод C, трек 1 №7; B3 #3, F1).
//
// Дефект: DefaultConfig().Sources содержал фиктивный источник "tor-snowflake" (Type: "tor").
// Он не мог дать НИ ОДНОГО пригодного узла (обработчик создавал заглушку без адреса и порта,
// которую отвергает ValidateNode — NL-10), зато при каждом обновлении источников помечался
// успешно обновлённым и запускал фоновую перезапись config.json. Побочно это же делало
// плавающими тесты пакета web (LOT-F1, см. комментарий к newTestServer в web/server_test.go).
package models

import "testing"

// TestK2E_DefaultConfig_NoTorSource — в конфигурации по умолчанию нет источника типа "tor".
func TestK2E_DefaultConfig_NoTorSource(t *testing.T) {
	for _, s := range DefaultConfig().Sources {
		if s.Type == "tor" {
			t.Fatalf("фиктивный источник типа \"tor\" остался в конфигурации по умолчанию: %+v", s)
		}
		if s.ID == "tor-snowflake" {
			t.Fatalf("источник tor-snowflake остался в конфигурации по умолчанию: %+v", s)
		}
	}
	t.Log("OK: источников типа \"tor\" в конфигурации по умолчанию нет")
}

// TestK2E_DefaultConfig_SourcesStillUsable — контроль: остальные источники не задеты, у
// каждого есть URL и тип, который менеджер умеет обрабатывать.
func TestK2E_DefaultConfig_SourcesStillUsable(t *testing.T) {
	srcs := DefaultConfig().Sources
	if len(srcs) == 0 {
		t.Fatal("источники вычищены целиком — пул не из чего наполнять")
	}
	for _, s := range srcs {
		switch s.Type {
		case "subscription", "telegram", "manual":
		default:
			t.Errorf("источник %q неизвестного типа %q", s.ID, s.Type)
		}
		if s.Type != "manual" && s.URL == "" {
			t.Errorf("источник %q типа %q без URL", s.ID, s.Type)
		}
	}
	t.Logf("OK: %d рабочих источников", len(srcs))
}
