// secrets_dpapi_test.go — S-5 (TZ_APF_v1.4_FINAL.md), лот L1b-SEC2.
//
// Проверяется контракт ящика «секреты на диске» (см. AGENTS/L1b-SEC2/result.md §1, ящик B):
// принимает — байты секрета и config.json; выводит — файл, в котором подстроки секрета нет;
// отвергает — отказ защиты (плайнтекст НЕ пишется) и нечитаемый контейнер (исходный файл цел);
// fail-safe — нечитаемое поле конфига становится пустым, а не шифртекстом, и не теряется.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/crypto"
)

// requireDPAPI — тесты настоящего кругового шифрования идут только там, где DPAPI есть.
// На Linux/Android поведение по S-5 намеренно не меняется, проверять там нечего.
func requireDPAPI(t *testing.T) {
	t.Helper()
	if !crypto.DPAPIAvailable() {
		t.Skipf("DPAPI недоступен на %s — по S-5 поведение платформы не меняется", runtime.GOOS)
	}
}

// resetSecretsGlobals — общее состояние пакета (флаг «секреты недоступны», загашник, швы)
// не должно протекать в соседние тесты.
func resetSecretsGlobals(t *testing.T) {
	t.Helper()
	prevProtect, prevUnprotect := protectSecretFn, unprotectSecretFn
	t.Cleanup(func() {
		protectSecretFn, unprotectSecretFn = prevProtect, prevUnprotect
		ClearSecretsState()
		ResetUnreadableSecretsCache()
	})
	ClearSecretsState()
	ResetUnreadableSecretsCache()
}

const testSecretMarker = "S3CR3T-shadowtls-p@ssw0rd-L1bSEC2"

// ─── Файл целиком ─────────────────────────────────────────────────────────────────────────

// Круговой «зашифровали → прочитали обратно» + главный критерий приёмки лота: файла на диске
// с подстрокой секрета не существует.
func TestV14_SecretFile_RoundtripAndNoPlaintextOnDisk(t *testing.T) {
	requireDPAPI(t)
	resetSecretsGlobals(t)

	path := filepath.Join(t.TempDir(), "server_identity.json")
	payload := []byte(`{"UUID":"u-1","PrivateKey":"` + testSecretMarker + `"}`)

	if err := WriteSecretFile(path, payload); err != nil {
		t.Fatalf("WriteSecretFile: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("файл не создан: %v", err)
	}
	if strings.Contains(string(raw), testSecretMarker) {
		t.Fatalf("секрет лежит на диске открытым текстом: %s", raw)
	}
	if !crypto.IsDPAPIProtected(raw) {
		t.Fatalf("нет маркера защищённого контейнера: %.20s", raw)
	}

	got, wasProtected, err := ReadSecretFile(path)
	if err != nil {
		t.Fatalf("ReadSecretFile: %v", err)
	}
	if !wasProtected {
		t.Error("wasProtected=false для только что защищённого файла")
	}
	if string(got) != string(payload) {
		t.Errorf("круговой прогон исказил данные: %q", got)
	}
}

// Миграция: старый открытый файл читается как раньше и переписывается защищённым, содержимое
// то же (критерий приёмки «миграция существующих открытых файлов»).
func TestV14_SecretFile_MigratesLegacyPlaintext(t *testing.T) {
	requireDPAPI(t)
	resetSecretsGlobals(t)

	path := filepath.Join(t.TempDir(), "server_relay_credentials.json")
	payload := []byte(`{"exit_id":"e1","relay_token":"` + testSecretMarker + `"}`)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	got, wasProtected, err := ReadSecretFile(path)
	if err != nil || wasProtected || string(got) != string(payload) {
		t.Fatalf("старый открытый файл должен читаться как есть: got=%q protected=%v err=%v", got, wasProtected, err)
	}

	migrated, err := EnsureSecretFileProtected(path)
	if err != nil {
		t.Fatalf("EnsureSecretFileProtected: %v", err)
	}
	if !migrated {
		t.Fatal("миграция не произошла")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), testSecretMarker) {
		t.Fatalf("после миграции секрет всё ещё открыт: %s", raw)
	}
	got2, wasProtected2, err := ReadSecretFile(path)
	if err != nil || !wasProtected2 || string(got2) != string(payload) {
		t.Fatalf("после миграции данные не совпали: got=%q protected=%v err=%v", got2, wasProtected2, err)
	}

	// Повторная миграция — no-op, файл не портится.
	if again, err := EnsureSecretFileProtected(path); err != nil || again {
		t.Errorf("повторная миграция должна быть пустой операцией: again=%v err=%v", again, err)
	}
}

// Ветка «не смог расшифровать» через ШОВ: работает на любой платформе, не зависит от DPAPI.
// Требование — понятная ошибка и НЕТРОНУТЫЙ исходный файл.
func TestV14_SecretFile_UnreadableIsHonestAndKeepsFile(t *testing.T) {
	resetSecretsGlobals(t)

	path := filepath.Join(t.TempDir(), "server_identity.json")
	container := []byte(crypto.DPAPIMarker + "bm90LWEtcmVhbC1ibG9i") // валидный base64, чужой blob
	if err := os.WriteFile(path, container, 0600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	unprotectSecretFn = func([]byte) ([]byte, error) {
		return nil, errors.New("CryptUnprotectData: ключ этой машины не подходит")
	}

	_, wasProtected, err := ReadSecretFile(path)
	if err == nil {
		t.Fatal("нечитаемый контейнер должен давать ошибку, а не молча пустоту")
	}
	if !wasProtected {
		t.Error("wasProtected должен быть true: маркер в файле есть")
	}
	if !strings.Contains(err.Error(), "server_identity.json") {
		t.Errorf("ошибка не называет файл: %v", err)
	}

	raw, readErr := os.ReadFile(path)
	if readErr != nil || string(raw) != string(container) {
		t.Fatalf("исходный файл не должен быть тронут: err=%v raw=%q", readErr, raw)
	}
}

// То же самое, но БЕЗ шва: настоящий DPAPI на настоящем испорченном blob'е.
func TestV14_SecretFile_CorruptedRealBlobIsHonest(t *testing.T) {
	requireDPAPI(t)
	resetSecretsGlobals(t)

	path := filepath.Join(t.TempDir(), "server_identity.json")
	if err := WriteSecretFile(path, []byte(`{"PrivateKey":"`+testSecretMarker+`"}`)); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	raw, _ := os.ReadFile(path)

	// Портим середину полезной нагрузки, сохраняя маркер и корректность base64.
	body := []byte(string(raw))
	mid := len(body)/2 + 1
	if body[mid] == 'A' {
		body[mid] = 'B'
	} else {
		body[mid] = 'A'
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("порча файла: %v", err)
	}

	if _, _, err := ReadSecretFile(path); err == nil {
		t.Fatal("испорченный blob расшифровался — этого быть не может")
	} else if !errors.Is(err, crypto.ErrSecretUnreadable) {
		t.Errorf("ожидался ErrSecretUnreadable, получено: %v", err)
	}
	after, _ := os.ReadFile(path)
	if len(after) != len(body) {
		t.Error("испорченный файл не должен ни удаляться, ни переписываться при чтении")
	}
}

// Карантин: файл уводится в .bak и не теряется; второй раз — .bak.1.
func TestV14_QuarantineSecretFile_KeepsData(t *testing.T) {
	resetSecretsGlobals(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "server_identity.json")

	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	bak1, err := QuarantineSecretFile(path)
	if err != nil {
		t.Fatalf("QuarantineSecretFile: %v", err)
	}
	if bak1 != path+".bak" {
		t.Errorf("ожидался .bak, получено %s", bak1)
	}
	if data, _ := os.ReadFile(bak1); string(data) != "first" {
		t.Errorf("данные потеряны при карантине: %q", data)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("исходный путь должен освободиться под пересоздание")
	}

	if err := os.WriteFile(path, []byte("second"), 0600); err != nil {
		t.Fatalf("подготовка 2: %v", err)
	}
	bak2, err := QuarantineSecretFile(path)
	if err != nil {
		t.Fatalf("второй карантин: %v", err)
	}
	if bak2 != path+".bak.1" {
		t.Errorf("второй карантин не должен затирать первый: %s", bak2)
	}
	if data, _ := os.ReadFile(bak1); string(data) != "first" {
		t.Errorf("первый .bak затёрт: %q", data)
	}
}

// ─── Поля config.json ─────────────────────────────────────────────────────────────────────

type secretsTestConfig struct {
	WebUIPort         int    `json:"webui_port"`
	ShadowTLSPassword string `json:"shadowtls_password"`
	AntiBlockAPIKey   string `json:"anti_block_api_key"`
	Note              string `json:"note"`
}

func TestV14_ConfigSecrets_FieldsProtectedOnDiskAndRestoredOnLoad(t *testing.T) {
	requireDPAPI(t)
	resetSecretsGlobals(t)

	cfg := secretsTestConfig{
		WebUIPort:         9090,
		ShadowTLSPassword: testSecretMarker,
		AntiBlockAPIKey:   "api-" + testSecretMarker,
		Note:              "обычное поле не трогаем",
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	raw, err := os.ReadFile(ConfigPath())
	if err != nil {
		t.Fatalf("config.json не записан: %v", err)
	}
	if strings.Contains(string(raw), testSecretMarker) {
		t.Fatalf("секрет остался в config.json открытым текстом:\n%s", raw)
	}
	// Файл обязан остаться обычным JSON: его читает служба и правит человек.
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("config.json перестал быть валидным JSON: %v", err)
	}
	if probe["note"] != "обычное поле не трогаем" {
		t.Errorf("несекретное поле изменилось: %v", probe["note"])
	}
	if p, _ := probe["webui_port"].(float64); p != 9090 {
		t.Errorf("несекретное число изменилось: %v", probe["webui_port"])
	}
	if s, _ := probe["shadowtls_password"].(string); !strings.HasPrefix(s, crypto.DPAPIMarker) {
		t.Errorf("секретное поле не защищено: %q", s)
	}

	var loaded secretsTestConfig
	found, err := LoadInto(&loaded)
	if err != nil || !found {
		t.Fatalf("LoadInto: found=%v err=%v", found, err)
	}
	if loaded.ShadowTLSPassword != testSecretMarker || loaded.AntiBlockAPIKey != "api-"+testSecretMarker {
		t.Fatalf("секреты не восстановились: %+v", loaded)
	}
	if unavailable, reason := SecretsState(); unavailable {
		t.Errorf("флаг «секреты недоступны» не должен подниматься на здоровом файле: %s", reason)
	}

	// Повторное сохранение уже защищённого значения не должно шифровать шифртекст повторно.
	if err := SaveConfig(loaded); err != nil {
		t.Fatalf("повторный SaveConfig: %v", err)
	}
	var again secretsTestConfig
	if _, err := LoadInto(&again); err != nil {
		t.Fatalf("повторный LoadInto: %v", err)
	}
	if again.ShadowTLSPassword != testSecretMarker {
		t.Errorf("второй круг исказил секрет: %q", again.ShadowTLSPassword)
	}
}

// Fail-safe: конфиг принесли с чужой машины. Поле не должно превратиться в шифртекст (движок
// принял бы его за пароль), не должно уронить загрузку и не должно пропасть при следующем
// сохранении настроек.
func TestV14_ConfigSecrets_UnreadableFieldEmptiedStatedAndPreserved(t *testing.T) {
	resetSecretsGlobals(t)

	foreign := crypto.DPAPIMarker + "Zm9yZWlnbi1ibG9i"
	onDisk := "{\n  \"webui_port\": 9090,\n  \"shadowtls_password\": \"" + foreign + "\",\n  \"note\": \"n\"\n}\n"
	if err := os.MkdirAll(DataDir(), 0700); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	if err := os.WriteFile(ConfigPath(), []byte(onDisk), 0600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	unprotectSecretFn = func([]byte) ([]byte, error) {
		return nil, errors.New("CryptUnprotectData: ключ этой машины не подходит")
	}
	protectSecretFn = func(p []byte) ([]byte, error) {
		return []byte(crypto.DPAPIMarker + "bmV3"), nil
	}

	var loaded secretsTestConfig
	found, err := LoadInto(&loaded)
	if err != nil || !found {
		t.Fatalf("нечитаемое поле не должно ронять загрузку: found=%v err=%v", found, err)
	}
	if loaded.ShadowTLSPassword != "" {
		t.Fatalf("нечитаемое поле обязано стать пустым, а не шифртекстом: %q", loaded.ShadowTLSPassword)
	}
	if loaded.WebUIPort != 9090 || loaded.Note != "n" {
		t.Errorf("остальной конфиг должен загрузиться: %+v", loaded)
	}
	unavailable, reason := SecretsState()
	if !unavailable {
		t.Fatal("состояние «секреты недоступны» не выставлено — ветка была бы молчаливой")
	}
	if !strings.Contains(reason, "shadowtls_password") {
		t.Errorf("причина не называет поле: %s", reason)
	}

	// Пользователь сохранил настройки, не трогая пароль: исходный шифртекст обязан вернуться.
	if err := SaveConfig(loaded); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	raw, _ := os.ReadFile(ConfigPath())
	if !strings.Contains(string(raw), foreign) {
		t.Fatalf("сохранение настроек уничтожило нечитаемый секрет:\n%s", raw)
	}
}

// Отказ защиты при доступном DPAPI: конфиг НЕ сохраняется, старый файл цел, плайнтекста нет.
func TestV14_ConfigSecrets_ProtectFailureDoesNotWritePlaintext(t *testing.T) {
	requireDPAPI(t)
	resetSecretsGlobals(t)

	if err := SaveConfig(secretsTestConfig{WebUIPort: 1, Note: "старый"}); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	before, _ := os.ReadFile(ConfigPath())

	protectSecretFn = func([]byte) ([]byte, error) { return nil, errors.New("crypt32 недоступна") }

	err := SaveConfig(secretsTestConfig{WebUIPort: 2, ShadowTLSPassword: testSecretMarker, Note: "новый"})
	if err == nil {
		t.Fatal("при отказе защиты SaveConfig обязан вернуть ошибку, а не записать секрет открытым")
	}
	after, _ := os.ReadFile(ConfigPath())
	if string(after) != string(before) {
		t.Fatalf("старый config.json должен остаться нетронутым:\n%s", after)
	}
	if strings.Contains(string(after), testSecretMarker) {
		t.Fatal("секрет попал на диск открытым текстом")
	}
	if _, statErr := os.Stat(ConfigPath() + ".tmp"); statErr == nil {
		t.Error("временный файл остался после отказа")
	}
}

// Отказ защиты, когда DPAPI на платформе НЕТ: поведение прежнее, конфиг сохраняется.
func TestV14_ConfigSecrets_NoDPAPIKeepsOldBehaviour(t *testing.T) {
	if crypto.DPAPIAvailable() {
		t.Skip("проверяется поведение платформы без DPAPI")
	}
	resetSecretsGlobals(t)

	if err := SaveConfig(secretsTestConfig{ShadowTLSPassword: testSecretMarker}); err != nil {
		t.Fatalf("на платформе без DPAPI сохранение не должно ломаться: %v", err)
	}
	raw, _ := os.ReadFile(ConfigPath())
	if !strings.Contains(string(raw), testSecretMarker) {
		t.Error("на платформе без DPAPI поведение должно остаться прежним (S-5: Linux/Android не трогаем)")
	}
}

// ─── Разбор JSON ──────────────────────────────────────────────────────────────────────────

// Ключ, случайно оказавшийся ВНУТРИ чужого значения, ключом не считается — иначе замена
// испортила бы файл. Регулярное выражение здесь ошиблось бы.
func TestV14_FindJSONStringFields_IgnoresKeyLookalikeInsideValue(t *testing.T) {
	data := []byte(`{
  "note": "текст со словами \"shadowtls_password\": \"не настоящий\"",
  "shadowtls_password": "настоящий",
  "nodes": [{"shadowtls_password": "второй"}]
}`)
	got := findJSONStringFields(data, configSecretKeys)
	if len(got) != 2 {
		t.Fatalf("ожидались ровно 2 настоящих вхождения, получено %d: %+v", len(got), got)
	}
	if got[0].value != "настоящий" || got[0].occurrence != 0 {
		t.Errorf("первое вхождение разобрано неверно: %+v", got[0])
	}
	if got[1].value != "второй" || got[1].occurrence != 1 {
		t.Errorf("вложенное вхождение разобрано неверно: %+v", got[1])
	}
}

// Не-строковые и отсутствующие значения игнорируются, документ не портится.
func TestV14_ConfigSecrets_IgnoresNonStringAndAbsentFields(t *testing.T) {
	resetSecretsGlobals(t)
	protectSecretFn = func(p []byte) ([]byte, error) { return []byte(crypto.DPAPIMarker + "x"), nil }

	for _, in := range []string{
		`{"shadowtls_password": null, "a": 1}`,
		`{"a": 1, "b": [1,2,3]}`,
		`[1,2,3]`,
		`{"shadowtls_password": ""}`,
	} {
		out, err := protectConfigSecrets([]byte(in))
		if err != nil {
			t.Fatalf("%s → ошибка %v", in, err)
		}
		if !crypto.DPAPIAvailable() {
			continue
		}
		if string(out) != in {
			t.Errorf("документ изменён без нужды: %s → %s", in, out)
		}
	}
}
