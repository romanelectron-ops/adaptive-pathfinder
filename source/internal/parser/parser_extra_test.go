package parser

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// в”Ђв”Ђв”Ђ parseWireGuard в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseWireGuard_WireguardPrefix(t *testing.T) {
	node, err := ParseLink("wireguard://pubkey@wg.example.com:51820#MyWG")
	if err != nil {
		t.Fatalf("parseWireGuard wireguard://: %v", err)
	}
	if node.Protocol != models.ProtoWireGuard {
		t.Errorf("protocol: want ProtoWireGuard, got %s", node.Protocol)
	}
	if node.Address != "wg.example.com" {
		t.Errorf("address: want wg.example.com, got %s", node.Address)
	}
	if node.Port != 51820 {
		t.Errorf("port: want 51820, got %d", node.Port)
	}
	if node.Name != "MyWG" {
		t.Errorf("name: want MyWG, got %s", node.Name)
	}
	if node.ID == "" {
		t.Error("ID must not be empty")
	}
	t.Logf("OK: %s %s:%d name=%s", node.Protocol, node.Address, node.Port, node.Name)
}

func TestParseWireGuard_WGPrefix(t *testing.T) {
	// wg:// prefix вЂ” no fragment в†’ auto-name "WG host:port"
	node, err := ParseLink("wg://key@vpn.example.com:51820")
	if err != nil {
		t.Fatalf("parseWireGuard wg://: %v", err)
	}
	if node.Protocol != models.ProtoWireGuard {
		t.Errorf("protocol: want ProtoWireGuard, got %s", node.Protocol)
	}
	if node.Address != "vpn.example.com" {
		t.Errorf("address: want vpn.example.com, got %s", node.Address)
	}
	if node.Port != 51820 {
		t.Errorf("port: want 51820, got %d", node.Port)
	}
	if node.Name == "" {
		t.Error("Name must be auto-generated when fragment absent")
	}
	t.Logf("OK: wg:// auto-name=%s", node.Name)
}

// [TZ_TAILS_HARDENING_2026-08-31.md кластер B] Регрессия конкретно на прежний баг: раньше
// извлекались только host/port/имя — приватный ключ, публичный ключ сервера и адрес клиента
// внутри туннеля никогда не читались из ссылки, хотя без них узел не мог пройти validate.go и
// тем более собраться в endpoint-конфигурацию.
func TestParseWireGuard_ExtractsKeysAndAddress(t *testing.T) {
	link := "wireguard://cHJpdmF0ZWtleWJhc2U2NA==@wg.example.com:51820" +
		"?publickey=cHVibGlja2V5YmFzZTY0&address=10.0.0.2/32&reserved=1,2,3&mtu=1420#MyWG"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.WGPrivateKey != "cHJpdmF0ZWtleWJhc2U2NA==" {
		t.Errorf("WGPrivateKey = %q, ожидался ключ из userinfo", node.WGPrivateKey)
	}
	if node.WGPublicKey != "cHVibGlja2V5YmFzZTY0" {
		t.Errorf("WGPublicKey = %q, ожидался ключ из query publickey=", node.WGPublicKey)
	}
	if node.WGLocalAddress != "10.0.0.2/32" {
		t.Errorf("WGLocalAddress = %q, ожидался query address=", node.WGLocalAddress)
	}
	if len(node.WGReserved) != 3 || node.WGReserved[0] != 1 || node.WGReserved[1] != 2 || node.WGReserved[2] != 3 {
		t.Errorf("WGReserved = %v, ожидался [1 2 3]", node.WGReserved)
	}
}

// AmneziaWG: та же ссылка, но со схемой amneziawg:// и Jc/Jmin/Jmax — протокол и джанк-параметры
// сохраняются в модель, даже если текущая сборка sing-box не умеет их использовать (см.
// nodeToOutbound/nodeToEndpoint) — сохранение данных и способность их применить не одно и то же.
func TestParseWireGuard_AmneziaWGPrefix_ExtractsJunkParams(t *testing.T) {
	link := "amneziawg://priv@awg.example.com:51820" +
		"?publickey=pub&address=10.0.0.3/32&jc=5&jmin=50&jmax=1000#MyAWG"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.Protocol != models.ProtoAmneziaWG {
		t.Errorf("Protocol = %q, ожидался ProtoAmneziaWG", node.Protocol)
	}
	if node.AWGJc != 5 || node.AWGJmin != 50 || node.AWGJmax != 1000 {
		t.Errorf("AWG junk = {%d %d %d}, ожидалось {5 50 1000}", node.AWGJc, node.AWGJmin, node.AWGJmax)
	}
}

// Базовая ссылка без query-параметров по-прежнему парсится (регресс на существующее поведение
// TestParseWireGuard_WGPrefix выше) — просто ключевые поля остаются пустыми, а не вызывают
// ошибку разбора самой ссылки.
func TestParseWireGuard_WithoutQueryParams_KeysEmptyNotError(t *testing.T) {
	node, err := ParseLink("wg://onlyuserinfo@vpn.example.com:51820")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.WGPublicKey != "" || node.WGLocalAddress != "" {
		t.Errorf("без query-параметров WGPublicKey/WGLocalAddress должны быть пусты, "+
			"получено %q / %q", node.WGPublicKey, node.WGLocalAddress)
	}
}

// в”Ђв”Ђв”Ђ ParseLink вЂ” default branch в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseLink_UnknownProtocol(t *testing.T) {
	_, err := ParseLink("http://some.server:8080")
	if err == nil {
		t.Error("expected error for unknown protocol")
	}
	t.Logf("OK: unknown protocol в†’ %v", err)
}

func TestParseLink_ShortUnknown(t *testing.T) {
	_, err := ParseLink("xyz")
	if err == nil {
		t.Error("expected error for short unknown string")
	}
}

// в”Ђв”Ђв”Ђ parseVMess вЂ” float64 port and aid в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseVMess_Float64PortAid(t *testing.T) {
	// Port and Aid set as float64 in the vmessConfig struct.
	// json.Marshal в†’ JSON numbers в†’ json.Unmarshal into `any` в†’ float64.
	// This exercises the `case float64:` branches in parseVMess.
	cfg := vmessConfig{
		V:    "2",
		PS:   "FloatPorts",
		Add:  "vmess-float.example.com",
		Port: float64(8443),
		ID:   "aaaabbbb-cccc-dddd-eeee-000000000001",
		Aid:  float64(2),
		Net:  "tcp",
		Type: "none",
		Host: "",
		Path: "",
		TLS:  "",
		SNI:  "",
	}
	raw, _ := json.Marshal(cfg)
	b64 := base64.StdEncoding.EncodeToString(raw)
	node, err := ParseLink("vmess://" + b64)
	if err != nil {
		t.Fatalf("parseVMess float64: %v", err)
	}
	if node.Protocol != models.ProtoVMess {
		t.Errorf("protocol: want vmess, got %s", node.Protocol)
	}
	if node.Port != 8443 {
		t.Errorf("port: want 8443, got %d", node.Port)
	}
	if node.AltID != 2 {
		t.Errorf("altId: want 2, got %d", node.AltID)
	}
	if node.Transport != nil {
		t.Errorf("tcp network must not set Transport")
	}
	if node.TLS != nil {
		t.Errorf("empty tls must not set TLS")
	}
	t.Logf("OK: vmess float64 port=%d aid=%d", node.Port, node.AltID)
}

// в”Ђв”Ђв”Ђ parseVMess вЂ” RawStdEncoding fallback в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseVMess_RawBase64Fallback(t *testing.T) {
	// Strip '=' padding from StdEncoding result to simulate RawStdEncoding input.
	// If StdEncoding already has no padding (json len % 3 == 0), skip.
	cfg := vmessConfig{
		V: "2", PS: "RawB64", Add: "raw.example.com",
		Port: "9090", ID: "aaaabbbb-cccc-dddd-eeee-000000000002", Aid: "0",
		Net: "", Type: "", Host: "", Path: "", TLS: "", SNI: "",
	}
	raw, _ := json.Marshal(cfg)
	stdB64 := base64.StdEncoding.EncodeToString(raw)
	rawB64 := strings.TrimRight(stdB64, "=")
	if rawB64 == stdB64 {
		t.Skip("JSON length divisible by 3 вЂ” no padding to strip; skipping RawStdEncoding branch")
	}
	node, err := parseVMess("vmess://" + rawB64)
	if err != nil {
		t.Fatalf("parseVMess RawBase64: %v", err)
	}
	if node.Address != "raw.example.com" {
		t.Errorf("address: want raw.example.com, got %s", node.Address)
	}
	t.Logf("OK: RawStdEncoding fallback path, node=%s", node.Name)
}

// в”Ђв”Ђв”Ђ parseVMess вЂ” error paths в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseVMess_InvalidBase64(t *testing.T) {
	_, err := ParseLink("vmess://not!valid!base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
	t.Logf("OK: invalid base64 в†’ %v", err)
}

func TestParseVMess_InvalidJSON(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("not-json{{{"))
	_, err := ParseLink("vmess://" + b64)
	if err == nil {
		t.Error("expected error for invalid JSON in vmess payload")
	}
	t.Logf("OK: invalid json в†’ %v", err)
}

// в”Ђв”Ђв”Ђ parseShadowsocks в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseShadowsocks_NewFormat(t *testing.T) {
	// Username contains ':' so base64 decode fails в†’ else branch:
	// node.Method = u.User.Username(), node.Password = u.User.Password()
	node, err := ParseLink("ss://chacha20-ietf-poly1305:mysecret@192.168.0.1:8388#NewSS")
	if err != nil {
		t.Fatalf("parseShadowsocks new format: %v", err)
	}
	if node.Protocol != models.ProtoShadowsocks {
		t.Errorf("protocol: want ss, got %s", node.Protocol)
	}
	if node.Name != "NewSS" {
		t.Errorf("name: want NewSS, got %s", node.Name)
	}
	t.Logf("OK: ss new-format method=%q pass=%q", node.Method, node.Password)
}

// ss:// с плагином (obfs/v2ray-plugin) обязан ОТВЕРГАТЬСЯ с внятной ошибкой.
//
// Контракт изменён 2026-08-24. Раньше строка плагина клалась в Transport.Type, и это ломало
// работу двумя способами: при ручном добавлении ValidateNode отвергал узел с невнятным
// «unknown transport type "obfs-local"», а при импорте подписки валидации нет вовсе — узел
// попадал в пул, buildTransport писал мусорный transport.type, и sing-box отвергал
// КОНФИГУРАЦИЮ ЦЕЛИКОМ, роняя весь сеанс из-за одного узла.
func TestParseShadowsocks_WithPluginRejected(t *testing.T) {
	userInfo := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pluginpass"))
	link := "ss://" + userInfo + "@10.0.0.1:8388?plugin=obfs-local&plugin-opts=obfs%3Dhttp#PluginSS"

	node, err := ParseLink(link)
	if err == nil {
		t.Fatalf("ожидался отказ для ss:// с плагином, получен узел %+v", node)
	}
	if !strings.Contains(err.Error(), "obfs-local") {
		t.Errorf("ошибка не называет плагин: %v", err)
	}
}

func TestParseShadowsocks_AutoName(t *testing.T) {
	// No fragment в†’ auto-name "SS host:port"
	userInfo := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	node, err := ParseLink("ss://" + userInfo + "@1.2.3.4:1080")
	if err != nil {
		t.Fatalf("parseShadowsocks auto-name: %v", err)
	}
	if node.Name == "" {
		t.Error("auto-name must not be empty")
	}
	t.Logf("OK: ss auto-name=%s", node.Name)
}

// в”Ђв”Ђв”Ђ parseTrojan в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseTrojan_AutoSNI(t *testing.T) {
	// No sni in query в†’ sni falls back to node.Address
	node, err := ParseLink("trojan://pass@trojan2.example.com:443#AutoSNI")
	if err != nil {
		t.Fatalf("parseTrojan auto-sni: %v", err)
	}
	if node.TLS == nil {
		t.Fatal("expected TLS for trojan")
	}
	if node.TLS.ServerName != "trojan2.example.com" {
		t.Errorf("sni: want trojan2.example.com, got %s", node.TLS.ServerName)
	}
	t.Logf("OK: trojan auto-sni=%s", node.TLS.ServerName)
}

func TestParseTrojan_WithTransport(t *testing.T) {
	// type=ws в†’ Transport set
	node, err := ParseLink("trojan://pass@t3.example.com:443?type=ws&path=/ws&sni=t3.example.com#WSTrojan")
	if err != nil {
		t.Fatalf("parseTrojan transport: %v", err)
	}
	if node.Transport == nil {
		t.Fatal("expected Transport for ws type")
	}
	if node.Transport.Type != "ws" {
		t.Errorf("transport type: want ws, got %s", node.Transport.Type)
	}
	if node.Transport.Path != "/ws" {
		t.Errorf("path: want /ws, got %s", node.Transport.Path)
	}
	t.Logf("OK: trojan ws transport path=%s", node.Transport.Path)
}

func TestParseTrojan_AutoName(t *testing.T) {
	// No fragment в†’ auto-name "Trojan host:port"
	node, err := ParseLink("trojan://pw@t.example.com:443")
	if err != nil {
		t.Fatalf("parseTrojan auto-name: %v", err)
	}
	if node.Name == "" {
		t.Error("auto-name must not be empty")
	}
	t.Logf("OK: trojan auto-name=%s", node.Name)
}

// в”Ђв”Ђв”Ђ parseVLESS extras в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseVLESS_TLS_NoReality(t *testing.T) {
	// security=tls (not reality) в†’ TLS.Enabled=true, TLS.Reality=nil
	node, err := ParseLink("vless://uuid@tls.example.com:443?security=tls&sni=tls.example.com#TLSOnly")
	if err != nil {
		t.Fatalf("parseVLESS tls-no-reality: %v", err)
	}
	if node.TLS == nil || !node.TLS.Enabled {
		t.Error("TLS must be enabled")
	}
	if node.TLS.Reality != nil {
		t.Error("Reality must be nil for plain tls")
	}
	t.Logf("OK: vless tls-only sni=%s", node.TLS.ServerName)
}

func TestParseVLESS_WithTransport(t *testing.T) {
	// type=ws в†’ Transport set
	node, err := ParseLink("vless://uuid@ws.example.com:443?security=tls&type=ws&path=/path&host=ws.example.com#WSNode")
	if err != nil {
		t.Fatalf("parseVLESS ws: %v", err)
	}
	if node.Transport == nil {
		t.Fatal("expected Transport for ws type")
	}
	if node.Transport.Type != "ws" {
		t.Errorf("transport type: want ws, got %s", node.Transport.Type)
	}
	t.Logf("OK: vless ws path=%s", node.Transport.Path)
}

func TestParseVLESS_AutoName(t *testing.T) {
	// No fragment в†’ auto-name "VLESS host:port"
	node, err := ParseLink("vless://uuid@vless.example.com:443?security=tls")
	if err != nil {
		t.Fatalf("parseVLESS auto-name: %v", err)
	}
	if node.Name == "" {
		t.Error("auto-name must not be empty")
	}
	t.Logf("OK: vless auto-name=%s", node.Name)
}

// в”Ђв”Ђв”Ђ tryBase64 в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestTryBase64_RawStdEncoding(t *testing.T) {
	// RawStdEncoding produces no '=' padding в†’ StdEncoding.Decode fails,
	// RawStdEncoding.Decode succeeds.
	original := []byte{0x01, 0x02} // 2 bytes → 3 RawStd chars ("AQI") → not multiple-of-4 → StdEncoding rejects
	encoded := base64.RawStdEncoding.EncodeToString(original)
	// Verify StdEncoding actually rejects this (i.e., padding was needed).
	if _, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		t.Skip("StdEncoding decoded RawStdEncoding string without error вЂ” padding not needed for this input")
	}
	decoded, err := tryBase64([]byte(encoded))
	if err != nil {
		t.Fatalf("tryBase64 RawStdEncoding: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded mismatch: want %q got %q", original, decoded)
	}
	t.Log("OK: RawStdEncoding path covered")
}

func TestTryBase64_URLEncoding(t *testing.T) {
	// Bytes 0xfb,0xff produce '+','/' in standard, '-','_' in URL alphabet.
	// URLEncoding uses '-' and '_' в†’ StdEncoding and RawStdEncoding both fail.
	original := []byte{0xfb, 0xff, 0xfe, 0x00, 0x01, 0x02}
	encoded := base64.URLEncoding.EncodeToString(original)
	if !strings.ContainsAny(encoded, "-_") {
		t.Skip("encoded string has no URL-specific chars; cannot distinguish from Std")
	}
	decoded, err := tryBase64([]byte(encoded))
	if err != nil {
		t.Fatalf("tryBase64 URLEncoding: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded mismatch")
	}
	t.Logf("OK: URLEncoding path covered, encoded=%s", encoded)
}

func TestTryBase64_RawURLEncoding(t *testing.T) {
	// RawURLEncoding: '-'/'_' alphabet, no padding.
	// StdEncoding fails (wrong chars), RawStdEncoding fails (wrong chars),
	// URLEncoding fails (missing '=' padding), RawURLEncoding succeeds.
	original := []byte{0xfb, 0xff, 0xfe, 0x00, 0x01}
	encoded := base64.RawURLEncoding.EncodeToString(original)
	if !strings.ContainsAny(encoded, "-_") {
		t.Skip("encoded string has no URL-specific chars")
	}
	// Confirm URLEncoding fails (needs padding).
	if _, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		t.Skip("URLEncoding decoded RawURL string; cannot distinguish from RawURL")
	}
	decoded, err := tryBase64([]byte(encoded))
	if err != nil {
		t.Fatalf("tryBase64 RawURLEncoding: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded mismatch")
	}
	t.Logf("OK: RawURLEncoding path covered, encoded=%s", encoded)
}

func TestTryBase64_AllFail(t *testing.T) {
	_, err := tryBase64([]byte("not!valid!base64!@#$"))
	if err == nil {
		t.Error("expected error for clearly invalid base64")
	}
	t.Logf("OK: all-fail в†’ %v", err)
}

// в”Ђв”Ђв”Ђ ParseSubscription вЂ” base64-encoded content в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func TestParseSubscription_Base64Encoded(t *testing.T) {
	// Wrap a plain multi-link list in base64 в†’ tryBase64 succeeds в†’ data = decoded
	plain := "wireguard://pubkey@wg1.example.com:51820#WG1\nwireguard://pubkey2@wg2.example.com:51820#WG2\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	nodes, err := ParseSubscription([]byte(b64))
	if err != nil {
		t.Fatalf("ParseSubscription base64: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected at least one WireGuard node from base64 subscription")
	}
	t.Logf("OK: %d nodes from base64 subscription", len(nodes))
}

// ─── url.Parse error paths (control character in URL) ────────────────────────

func TestParseVLESS_URLParseError(t *testing.T) {
	// \x00 (null byte) causes url.Parse to return an error
	_, err := parseVLESS("vless://\x00@host:443")
	if err == nil {
		t.Error("expected error for URL with control character")
	}
	t.Logf("OK: parseVLESS url.Parse error → %v", err)
}

func TestParseShadowsocks_URLParseError(t *testing.T) {
	_, err := parseShadowsocks("ss://\x00@host:443")
	if err == nil {
		t.Error("expected error for URL with control character")
	}
	t.Logf("OK: parseShadowsocks url.Parse error → %v", err)
}

func TestParseTrojan_URLParseError(t *testing.T) {
	_, err := parseTrojan("trojan://\x00@host:443")
	if err == nil {
		t.Error("expected error for URL with control character")
	}
	t.Logf("OK: parseTrojan url.Parse error → %v", err)
}

func TestParseWireGuard_URLParseError(t *testing.T) {
	_, err := parseWireGuard("wireguard://\x00@host:51820")
	if err == nil {
		t.Error("expected error for URL with control character")
	}
	t.Logf("OK: parseWireGuard url.Parse error → %v", err)
}

// ─── parseVMess — auto-name when PS is empty ──────────────────────────────────

func TestParseVMess_AutoName(t *testing.T) {
	cfg := vmessConfig{
		Add:  "vmess.example.com",
		Port: "8443",
		// PS intentionally absent → node.Name == "" → auto-name branch
	}
	raw, _ := json.Marshal(cfg)
	b64 := base64.StdEncoding.EncodeToString(raw)
	node, err := parseVMess("vmess://" + b64)
	if err != nil {
		t.Fatalf("parseVMess auto-name: %v", err)
	}
	if node.Name == "" {
		t.Error("auto-name must not be empty")
	}
	t.Logf("OK: parseVMess auto-name=%s", node.Name)
}

// ─── parseClashProxyBlock — empty block → nil ────────────────────────────────

func TestParseClashProxyBlock_Empty(t *testing.T) {
	result := parseClashProxyBlock([]string{})
	if result != nil {
		t.Errorf("expected nil for empty block, got %+v", result)
	}
	t.Log("OK: parseClashProxyBlock empty → nil")
}

// ─── ParseClashYAML — end-of-proxies section branch ──────────────────────────

func TestParseClashYAML_EndOfProxiesSection(t *testing.T) {
	// "rules:" at top level (no leading space/tab/dash) while inProxies=true
	// triggers the end-of-section branch (lines 81-84 in parser.go)
	yaml := []byte(`proxies:
  - name: clash-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: testpass
rules:
  - MATCH,DIRECT
`)
	nodes, err := ParseClashYAML(yaml)
	if err != nil {
		t.Fatalf("ParseClashYAML end-of-section: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected at least one node parsed before section end")
	}
	t.Logf("OK: ParseClashYAML end-of-section → %d nodes", len(nodes))
}

// ─── clashBuildNode — trojan: sni fallback + ws transport ────────────────────

func TestClashBuildNode_TrojanSNIFallback(t *testing.T) {
	// No "sni" key → sni == "" → fallback sni = server (lines 479-481)
	f := map[string]string{
		"type":     "trojan",
		"name":     "trojan-sni-fallback",
		"server":   "trojan.example.com",
		"port":     "443",
		"password": "secret",
		// intentionally no "sni"
	}
	node := clashBuildNode(f)
	if node == nil {
		t.Fatal("clashBuildNode trojan returned nil")
	}
	if node.TLS == nil {
		t.Fatal("trojan must have TLS config")
	}
	if node.TLS.ServerName != "trojan.example.com" {
		t.Errorf("sni fallback: want %q got %q", "trojan.example.com", node.TLS.ServerName)
	}
	t.Logf("OK: trojan sni fallback → ServerName=%s", node.TLS.ServerName)
}

func TestClashBuildNode_TrojanWSTransport(t *testing.T) {
	// network=ws → Transport block set (lines 483-488)
	f := map[string]string{
		"type":     "trojan",
		"name":     "trojan-ws",
		"server":   "trojan.example.com",
		"port":     "443",
		"password": "secret",
		"sni":      "trojan.example.com",
		"network":  "ws",
		"ws-path":  "/ws",
	}
	node := clashBuildNode(f)
	if node == nil {
		t.Fatal("clashBuildNode trojan ws returned nil")
	}
	if node.Transport == nil {
		t.Fatal("trojan ws must have Transport config")
	}
	if node.Transport.Type != "ws" {
		t.Errorf("transport type: want ws got %s", node.Transport.Type)
	}
	t.Logf("OK: trojan ws transport → Type=%s Path=%s", node.Transport.Type, node.Transport.Path)
}

// ─── clashBuildNode — vless: ws transport (lines 505-510) ────────────────────

func TestClashBuildNode_VLESSWSTransport(t *testing.T) {
	f := map[string]string{
		"type":    "vless",
		"name":    "vless-ws",
		"server":  "vless.example.com",
		"port":    "443",
		"uuid":    "some-uuid",
		"tls":     "true",
		"network": "ws",
		"ws-path": "/ws",
	}
	node := clashBuildNode(f)
	if node == nil {
		t.Fatal("clashBuildNode vless ws returned nil")
	}
	if node.Transport == nil {
		t.Fatal("vless ws must have Transport config")
	}
	if node.Transport.Type != "ws" {
		t.Errorf("transport type: want ws got %s", node.Transport.Type)
	}
	t.Logf("OK: vless ws transport → Type=%s", node.Transport.Type)
}
