package androidbridge

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// resetServerRoleState изолирует роль «Выход» от порядка выполнения других тестов
// в пакете (тот же приём, что withTestEngine в tun_test.go — package-level состояние,
// не per-test).
func resetServerRoleState(t *testing.T) {
	t.Helper()
	reset := func() {
		serverRoleMu.Lock()
		serverRoleProtectCB = nil
		serverRoleRunner = nil
		serverRoleListen = 0
		serverRoleInternal = 0
		serverRoleAdmission = nil
		serverRoleAdmissionCancel = nil
		serverRoleExit = nil
		serverRoleExitCancel = nil
		serverRoleExitAddr = ""
		serverRoleExitFingerprint = ""
		serverRoleMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// setupServerRoleCredentialsFile изолирует relay-путь (BuildServerLinkJSON с непустым
// relayAddr пишет server_relay_credentials.json через relay.EnsureExitCredentials) от
// файла на РЕАЛЬНОМ config.DataDir() этой машины — тот же приём снимок/восстановление,
// что TestAdBlockStatus_AfterInit в bridge_test.go уже применяет к config.json (Windows-
// ветка config.DataDir() не переопределяется APF_DATA_DIR, см. тот комментарий) — тест не
// имеет права оставить хост в другом состоянии, чем застал.
func setupServerRoleCredentialsFile(t *testing.T) {
	t.Helper()
	path := serverRelayCredentialsPath()
	original, readErr := os.ReadFile(path)
	existed := readErr == nil
	t.Cleanup(func() {
		if existed {
			os.WriteFile(path, original, 0600)
		} else {
			os.Remove(path)
		}
	})
}

// Контракт GenerateServerIdentityJSON — успешный путь возвращает JSON, разбираемый
// обратно теми же полями, что и singbox.ServerIdentity (round-trip, не выдуманная схема).
func TestGenerateServerIdentityJSON_RoundTrips(t *testing.T) {
	out := GenerateServerIdentityJSON()
	var decoded struct {
		UUID       string
		PrivateKey string
		PublicKey  string
		ShortID    string
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("GenerateServerIdentityJSON() = %q, не парсится: %v", out, err)
	}
	if decoded.UUID == "" || decoded.PrivateKey == "" || decoded.PublicKey == "" || decoded.ShortID == "" {
		t.Fatalf("GenerateServerIdentityJSON() = %q, ожидались все четыре поля непустыми", out)
	}
}

// Контракт StartServerRole — отвергает пустой identityJSON до создания runner-а
// (decodeIdentity), не доходя до SetServerProtectCallback вовсе.
func TestStartServerRole_RejectsEmptyIdentity(t *testing.T) {
	resetServerRoleState(t)
	got := StartServerRole(18443, "", "", 0, "", "")
	if !strings.Contains(got, "identity") {
		t.Errorf("StartServerRole(..., \"\") = %q, ожидался отказ по identity", got)
	}
}

// Контракт StartServerRole — отвергает невалидный JSON identity с понятной ошибкой,
// а не паникой/тихим нулевым UUID.
func TestStartServerRole_RejectsInvalidIdentityJSON(t *testing.T) {
	resetServerRoleState(t)
	got := StartServerRole(18443, "", "{not valid json", 0, "", "")
	if got == "" {
		t.Fatal("StartServerRole(..., невалидный JSON) = \"\", ожидался отказ")
	}
}

// Контракт StartServerRole — отвергает отсутствующий SetServerProtectCallback (тот же
// принцип, что TestStartTun_RejectsMissingProtectCallback: честнее отказать на входе,
// чем поднять runner, у которого AutoDetectInterfaceControl откажет на каждом сокете).
func TestStartServerRole_RejectsMissingProtectCallback(t *testing.T) {
	resetServerRoleState(t)
	identity := GenerateServerIdentityJSON()

	got := StartServerRole(18443, "", identity, 0, "", "")
	if !strings.Contains(got, "ProtectCallback") {
		t.Errorf("StartServerRole() без SetServerProtectCallback = %q, ожидался отказ по ProtectCallback", got)
	}
}

// Контракт StopServerRole/IsServerRoleRunning в состоянии покоя — идемпотентность и
// честное false без инициализации, тот же контракт, что у StopTun/androidServerRunner.
func TestServerRole_IdleStateIsSafe(t *testing.T) {
	resetServerRoleState(t)
	if IsServerRoleRunning() {
		t.Fatal("IsServerRoleRunning() = true до первого StartServerRole")
	}
	if got := StopServerRole(); got != "" {
		t.Errorf("StopServerRole() до старта = %q, ожидалась пустая строка (идемпотентность)", got)
	}
}

// Контракт GetServerRoleStatusJSON в состоянии покоя.
func TestGetServerRoleStatusJSON_IdleState(t *testing.T) {
	resetServerRoleState(t)
	var status struct {
		Running    bool `json:"running"`
		ListenPort int  `json:"listen_port"`
	}
	if err := json.Unmarshal([]byte(GetServerRoleStatusJSON()), &status); err != nil {
		t.Fatalf("GetServerRoleStatusJSON() не парсится: %v", err)
	}
	if status.Running {
		t.Error("GetServerRoleStatusJSON().running = true в состоянии покоя")
	}
}

// Контракт BuildServerLinkJSON — успешный путь содержит vless:// и не теряет identity/host.
func TestBuildServerLinkJSON_Success(t *testing.T) {
	identity := GenerateServerIdentityJSON()
	out := BuildServerLinkJSON(identity, "example.com", 8443, "", "test-link", "", "")

	var decoded struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("BuildServerLinkJSON() = %q, не парсится: %v", out, err)
	}
	if !strings.HasPrefix(decoded.Link, "vless://") {
		t.Errorf("BuildServerLinkJSON().link = %q, ожидался префикс vless://", decoded.Link)
	}
	if !strings.Contains(decoded.Link, "example.com:8443") {
		t.Errorf("BuildServerLinkJSON().link = %q, ожидался host:port example.com:8443", decoded.Link)
	}
}

// Контракт BuildServerLinkJSON — отвергает пустой identityJSON тем же decodeIdentity,
// что и StartServerRole, с ошибкой в JSON-обёртке (не паника, не пустая строка).
func TestBuildServerLinkJSON_RejectsEmptyIdentity(t *testing.T) {
	out := BuildServerLinkJSON("", "example.com", 8443, "", "test-link", "", "")
	var decoded struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("BuildServerLinkJSON(\"\", ...) = %q, не парсится: %v", out, err)
	}
	if decoded.Error == "" {
		t.Errorf("BuildServerLinkJSON(\"\", ...) = %q, ожидалось непустое поле error", out)
	}
}

// testRelayFingerprint — валидный по форме (hex, 64 символа — как настоящий hex(sha256(...)))
// плейсхолдер-отпечаток для тестов, которым не важен конкретный TLS-сертификат, только сам
// факт, что непустое значение корректно доходит до ссылки/конструкторов.
const testRelayFingerprint = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd3"

// [Фаза E, доп. TZ_RELAY_HARDENING_2026-08-29.md кластер B] Контракт BuildServerLinkJSON с
// relayAddr — собирает relay-формат ссылки (docs/TZ_APF_RELAY_v1.0.md §3): host в ссылке —
// адрес relay, не значение параметра host (тот, что ушёл бы в прямую ссылку), плюс apf_relay=1,
// непустой apf_exitid и непустой apf_relayfp (отпечаток TLS-сертификата relay).
func TestBuildServerLinkJSON_RelayFormat(t *testing.T) {
	setupServerRoleCredentialsFile(t)
	identity := GenerateServerIdentityJSON()
	out := BuildServerLinkJSON(identity, "direct-host.example", 8443, "", "test-link", "relay.example.com:9443", testRelayFingerprint)

	var decoded struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("BuildServerLinkJSON(..., relayAddr) = %q, не парсится: %v", out, err)
	}
	if !strings.Contains(decoded.Link, "relay.example.com:9443") {
		t.Errorf("BuildServerLinkJSON(..., relayAddr).link = %q, ожидался host relay.example.com:9443", decoded.Link)
	}
	if strings.Contains(decoded.Link, "direct-host.example") {
		t.Errorf("BuildServerLinkJSON(..., relayAddr).link = %q, host из прямого пути не должен встречаться в relay-ссылке", decoded.Link)
	}
	if !strings.Contains(decoded.Link, "apf_relay=1") {
		t.Errorf("BuildServerLinkJSON(..., relayAddr).link = %q, ожидался apf_relay=1", decoded.Link)
	}
	if !strings.Contains(decoded.Link, "apf_exitid=") {
		t.Errorf("BuildServerLinkJSON(..., relayAddr).link = %q, ожидался непустой apf_exitid", decoded.Link)
	}
	if !strings.Contains(decoded.Link, "apf_relayfp="+testRelayFingerprint) {
		t.Errorf("BuildServerLinkJSON(..., relayAddr).link = %q, ожидался apf_relayfp=%s", decoded.Link, testRelayFingerprint)
	}
}

// [Фаза E] Контракт BuildServerLinkJSON — невалидный relayAddr (без порта) отклоняется с
// понятной ошибкой в JSON-обёртке, не паникой.
func TestBuildServerLinkJSON_RejectsInvalidRelayAddr(t *testing.T) {
	setupServerRoleCredentialsFile(t)
	identity := GenerateServerIdentityJSON()
	out := BuildServerLinkJSON(identity, "example.com", 8443, "", "test-link", "not-a-valid-addr", testRelayFingerprint)

	var decoded struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("BuildServerLinkJSON(..., \"not-a-valid-addr\") = %q, не парсится: %v", out, err)
	}
	if decoded.Error == "" {
		t.Errorf("BuildServerLinkJSON(..., \"not-a-valid-addr\") = %q, ожидалось непустое поле error", out)
	}
}

// [TZ_RELAY_HARDENING_2026-08-29.md кластер B] Отпечаток TLS-сертификата relay обязателен
// вместе с валидным relayAddr — без него партнёр получил бы ссылку, по которой EntryBridge
// гарантированно откажет (fail-closed), поэтому отказ обязан произойти ЗДЕСЬ, до выдачи
// ссылки, а не молча позже на стороне партнёра.
func TestBuildServerLinkJSON_RejectsMissingRelayFingerprint(t *testing.T) {
	setupServerRoleCredentialsFile(t)
	identity := GenerateServerIdentityJSON()
	out := BuildServerLinkJSON(identity, "example.com", 8443, "", "test-link", "relay.example.com:9443", "")

	var decoded struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("BuildServerLinkJSON(..., relayAddr, \"\") = %q, не парсится: %v", out, err)
	}
	if decoded.Error == "" {
		t.Errorf("BuildServerLinkJSON(..., relayAddr, \"\") = %q, ожидалось непустое поле error (отпечаток обязателен)", out)
	}
}
