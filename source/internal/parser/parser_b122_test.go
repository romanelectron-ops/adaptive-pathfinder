package parser

import "testing"

// B-12.2 (T-12) — импорт sing-box config.json.

const singboxJSON = `{
  "outbounds": [
    {"type":"vless","tag":"vl1","server":"1.2.3.4","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111"},
    {"type":"trojan","tag":"tr1","server":"5.6.7.8","server_port":8443,"password":"secret"},
    {"type":"shadowsocks","tag":"ss1","server":"9.9.9.9","server_port":8388,"method":"aes-256-gcm","password":"p"},
    {"type":"direct","tag":"direct"},
    {"type":"block","tag":"block"},
    {"type":"selector","tag":"select","outbounds":["vl1","tr1"]}
  ]
}`

// (1) Позитив: 3 прокси-узла, служебные (direct/block/selector) пропущены.
func TestParseSingBoxJSON_ExtractsProxies(t *testing.T) {
	nodes, err := ParseSingBoxJSON([]byte(singboxJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("ожидалось 3 прокси-узла (без direct/block/selector), got %d", len(nodes))
	}
	// проверяем маппинг полей
	byTag := map[string]*nodeShape{}
	for _, n := range nodes {
		byTag[string(n.Protocol)] = &nodeShape{addr: n.Address, port: n.Port, uuid: n.UUID, pass: n.Password, method: n.Method}
	}
	if v := byTag["vless"]; v == nil || v.addr != "1.2.3.4" || v.port != 443 || v.uuid == "" {
		t.Errorf("vless смаппился неверно: %+v", byTag["vless"])
	}
	if s := byTag["ss"]; s == nil || s.method != "aes-256-gcm" {
		t.Errorf("shadowsocks method потерян: %+v", byTag["ss"])
	}
}

type nodeShape struct {
	addr, uuid, pass, method string
	port                     int
}

// (3) Fail-safe: невалидный JSON → ошибка без узлов.
func TestParseSingBoxJSON_InvalidJSON(t *testing.T) {
	_, err := ParseSingBoxJSON([]byte(`{not json`))
	if err == nil {
		t.Error("ожидалась ошибка на битом JSON")
	}
}

// (4) Стойкость: пустой/без прокси JSON → 0 узлов без ошибки.
func TestParseSingBoxJSON_NoProxies(t *testing.T) {
	nodes, err := ParseSingBoxJSON([]byte(`{"outbounds":[{"type":"direct","tag":"d"}]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("ожидалось 0 узлов, got %d", len(nodes))
	}
}

// Диспетчер: ParseCatalogContent распознаёт sing-box JSON.
func TestParseCatalogContent_SingBoxJSON(t *testing.T) {
	nodes, err := ParseCatalogContent([]byte(singboxJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("диспетчер должен извлечь 3 узла из sing-box JSON, got %d", len(nodes))
	}
}

// looksLikeSingBoxJSON: распознавание формата.
func TestLooksLikeSingBoxJSON(t *testing.T) {
	if !looksLikeSingBoxJSON([]byte(singboxJSON)) {
		t.Error("должен распознать sing-box JSON")
	}
	if looksLikeSingBoxJSON([]byte("vless://abc\n")) {
		t.Error("не должен принимать link-список за JSON")
	}
	if looksLikeSingBoxJSON([]byte("proxies:\n  - name: x")) {
		t.Error("не должен принимать Clash YAML за sing-box JSON")
	}
}
