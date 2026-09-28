package parser

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestParseVLESS(t *testing.T) {
	link := "vless://uuid-1234-5678@example.com:443?security=reality&sni=www.microsoft.com&pbk=pubkey123&sid=abc&flow=xtls-rprx-vision#MyServer"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}
	if node.Protocol != models.ProtoVLESS {
		t.Errorf("expected vless, got %s", node.Protocol)
	}
	if node.Address != "example.com" {
		t.Errorf("expected example.com, got %s", node.Address)
	}
	if node.Port != 443 {
		t.Errorf("expected 443, got %d", node.Port)
	}
	if node.TLS == nil || !node.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	if node.TLS.Reality == nil {
		t.Error("Reality config missing")
	}
	t.Logf("OK: %+v", node.Name)
}

func TestParseVMess(t *testing.T) {
	// vmess://base64({...})
	// Тестируем через base64-кодированный JSON
	import64 := "eyJ2IjoiMiIsInBzIjoiVGVzdCBTZXJ2ZXIiLCJhZGQiOiJ0ZXN0LmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5MDEyIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoidGVzdC5leGFtcGxlLmNvbSIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJ0ZXN0LmV4YW1wbGUuY29tIn0="
	link := "vmess://" + import64
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseVMess failed: %v", err)
	}
	if node.Protocol != models.ProtoVMess {
		t.Errorf("expected vmess, got %s", node.Protocol)
	}
	t.Logf("OK: %s at %s:%d", node.Name, node.Address, node.Port)
}

func TestParseShadowsocks(t *testing.T) {
	// ss://base64(method:password)@host:port#name
	link := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3N3b3Jk@192.168.1.1:8388#TestSS"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseSS failed: %v", err)
	}
	if node.Protocol != models.ProtoShadowsocks {
		t.Errorf("expected ss, got %s", node.Protocol)
	}
	t.Logf("OK: %s method=%s", node.Name, node.Method)
}

func TestParseTrojan(t *testing.T) {
	link := "trojan://mypassword@trojan.example.com:443?sni=trojan.example.com#TrojanTest"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseTrojan failed: %v", err)
	}
	if node.Protocol != models.ProtoTrojan {
		t.Errorf("expected trojan, got %s", node.Protocol)
	}
	if node.Password != "mypassword" {
		t.Errorf("expected mypassword, got %s", node.Password)
	}
	t.Logf("OK: %s", node.Name)
}

func TestParseSubscription(t *testing.T) {
	// Симулируем base64-подписку
	links := "vless://uuid@server1.com:443?security=tls#Server1\nvmess://eyJ2IjoiMiIsInBzIjoiU2VydmVyMiIsImFkZCI6InNlcnZlcjIuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0="
	nodes, err := ParseSubscription([]byte(links))
	if err != nil {
		t.Fatalf("ParseSubscription failed: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected at least one node")
	}
	t.Logf("OK: parsed %d nodes", len(nodes))
}

func TestGenerateID(t *testing.T) {
	n1 := &models.Node{Protocol: models.ProtoVLESS, Address: "test.com", Port: 443}
	n2 := &models.Node{Protocol: models.ProtoVLESS, Address: "test.com", Port: 443}
	n3 := &models.Node{Protocol: models.ProtoVLESS, Address: "test.com", Port: 8443}

	id1 := generateID(n1)
	id2 := generateID(n2)
	id3 := generateID(n3)

	if id1 != id2 {
		t.Error("same node should have same ID")
	}
	if id1 == id3 {
		t.Error("different port should give different ID")
	}
	t.Logf("OK: IDs %s vs %s", id1, id3)
}
