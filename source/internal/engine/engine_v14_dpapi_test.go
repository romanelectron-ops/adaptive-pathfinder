// engine_v14_dpapi_test.go — S-5 (TZ_APF_v1.4_FINAL.md), лот L1b-SEC2, критерии приёмки:
// круговой шифр/расшифр после «перезапуска процесса»; файл на диске не содержит подстроку
// секрета; миграция старого открытого файла; ветка «не смог расшифровать → пересоздать + .bak».
//
// Контракт ящика C (AGENTS/L1b-SEC2/result.md §1): вход и выход функций роли «Выход» те же,
// меняется только представление на диске и появляется честная ветка отказа.
package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/crypto"
	"github.com/apf/adaptive-pathfinder/internal/relay"
)

// dpapiTestEnv — свой каталог данных на тест + сброс глобального состояния секретов, чтобы
// предупреждение из одного теста не протекало в соседний.
func dpapiTestEnv(t *testing.T) string {
	t.Helper()
	if !crypto.DPAPIAvailable() {
		t.Skipf("DPAPI недоступен на %s — по S-5 поведение платформы не меняется", runtime.GOOS)
	}
	dir := withTempDataDir(t)
	config.ClearSecretsState()
	config.ResetUnreadableSecretsCache()
	t.Cleanup(func() {
		config.ClearSecretsState()
		config.ResetUnreadableSecretsCache()
	})
	return dir
}

// Ключ REALITY звена «Выход» не лежит на диске открытым текстом, и «перезапуск процесса»
// (повторное чтение файла без всякого состояния в памяти) его возвращает.
func TestV14_ServerIdentity_NotPlaintextOnDiskAndSurvivesRestart(t *testing.T) {
	dir := dpapiTestEnv(t)
	e := &Engine{}

	id, err := e.GenerateServerRoleIdentity()
	if err != nil {
		t.Fatalf("GenerateServerRoleIdentity: %v", err)
	}
	if id.PrivateKey == "" {
		t.Fatal("пустой приватный ключ — тест бессмыслен")
	}

	path := filepath.Join(dir, "server_identity.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("server_identity.json не создан: %v", err)
	}
	if strings.Contains(string(raw), id.PrivateKey) {
		t.Fatalf("приватный ключ REALITY лежит на диске открытым текстом:\n%s", raw)
	}
	if strings.Contains(string(raw), id.UUID) {
		t.Fatalf("UUID звена лежит на диске открытым текстом:\n%s", raw)
	}
	if !crypto.IsDPAPIProtected(raw) {
		t.Fatalf("файл без маркера защиты: %.20s", raw)
	}

	// «Перезапуск процесса»: ничего не помним, читаем с нуля.
	got, found, err := (&Engine{}).LoadServerRoleIdentity()
	if err != nil || !found {
		t.Fatalf("LoadServerRoleIdentity: found=%v err=%v", found, err)
	}
	if got != id {
		t.Fatalf("круговой прогон исказил ключ:\nбыло  %+v\nстало %+v", id, got)
	}
	if _, warned := e.SecretsWarning(); warned {
		t.Error("на здоровом файле предупреждения быть не должно")
	}
}

// Миграция: файл, оставшийся от прежних версий в открытом виде, читается и молча
// переписывается защищённым — ключ звена не теряется, ранее выданные ссылки продолжают жить.
func TestV14_ServerIdentity_MigratesLegacyPlaintextFile(t *testing.T) {
	dir := dpapiTestEnv(t)
	path := filepath.Join(dir, "server_identity.json")

	legacy := `{
  "UUID": "11111111-2222-3333-4444-555555555555",
  "PrivateKey": "LEGACY-PRIVATE-KEY-L1bSEC2",
  "PublicKey": "LEGACY-PUBLIC-KEY",
  "ShortID": "0123456789abcdef"
}`
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	id, found, err := (&Engine{}).LoadServerRoleIdentity()
	if err != nil || !found {
		t.Fatalf("старый открытый файл должен читаться: found=%v err=%v", found, err)
	}
	if id.PrivateKey != "LEGACY-PRIVATE-KEY-L1bSEC2" || id.ShortID != "0123456789abcdef" {
		t.Fatalf("миграция исказила ключ: %+v", id)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "LEGACY-PRIVATE-KEY-L1bSEC2") {
		t.Fatalf("после чтения файл не был защищён:\n%s", raw)
	}
	again, found2, err := (&Engine{}).LoadServerRoleIdentity()
	if err != nil || !found2 || again != id {
		t.Fatalf("после миграции ключ не читается: found=%v err=%v id=%+v", found2, err, again)
	}
}

// Ветка В-2: файл защищён на ДРУГОЙ машине. Требуется — не упасть, не потерять файл (.bak),
// сказать это человеку и освободить место под новый ключ.
func TestV14_ServerIdentity_UnreadableGoesToBakAndAllowsRegenerate(t *testing.T) {
	dir := dpapiTestEnv(t)
	path := filepath.Join(dir, "server_identity.json")

	if _, err := (&Engine{}).GenerateServerRoleIdentity(); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	raw, _ := os.ReadFile(path)
	corrupted := []byte(string(raw))
	mid := len(corrupted)/2 + 1
	if corrupted[mid] == 'A' {
		corrupted[mid] = 'B'
	} else {
		corrupted[mid] = 'A'
	}
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatalf("порча файла: %v", err)
	}

	e := &Engine{}
	_, found, err := e.LoadServerRoleIdentity()
	if err != nil {
		t.Fatalf("нечитаемый ключ не должен превращаться в ошибку наверх: %v", err)
	}
	if found {
		t.Fatal("нечитаемый ключ не должен считаться найденным — иначе тупик")
	}

	bak := path + ".bak"
	bakData, bakErr := os.ReadFile(bak)
	if bakErr != nil {
		t.Fatalf("старый файл обязан сохраниться как .bak: %v", bakErr)
	}
	if string(bakData) != string(corrupted) {
		t.Error(".bak должен содержать исходные байты, а не что-то новое")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("исходный путь должен освободиться под пересоздание")
	}

	reason, warned := e.SecretsWarning()
	if !warned {
		t.Fatal("ветка «не смог расшифровать» обязана быть видимой, а не молчаливой")
	}
	if !strings.Contains(reason, "server_identity.json") || !strings.Contains(reason, ".bak") {
		t.Errorf("предупреждение не объясняет, что произошло: %s", reason)
	}

	// Пересоздание после карантина работает и даёт читаемый ключ.
	fresh, err := e.GenerateServerRoleIdentity()
	if err != nil {
		t.Fatalf("пересоздание после карантина: %v", err)
	}
	got, found, err := (&Engine{}).LoadServerRoleIdentity()
	if err != nil || !found || got != fresh {
		t.Fatalf("новый ключ не читается: found=%v err=%v", found, err)
	}
}

// relay-token роли «Выход»: тот же контракт «загрузить или создать», но на диске защищён.
func TestV14_ExitCredentials_ProtectedAndStable(t *testing.T) {
	dir := dpapiTestEnv(t)
	path := filepath.Join(dir, "server_relay_credentials.json")

	exitID, token, err := ensureExitCredentials()
	if err != nil {
		t.Fatalf("ensureExitCredentials: %v", err)
	}
	if exitID == "" || token == "" {
		t.Fatal("пустые креды")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("файл не создан: %v", err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatalf("relay-token лежит открытым текстом:\n%s", raw)
	}
	if !crypto.IsDPAPIProtected(raw) {
		t.Fatalf("файл без маркера защиты: %.20s", raw)
	}

	exitID2, token2, err := ensureExitCredentials()
	if err != nil {
		t.Fatalf("повторный вызов: %v", err)
	}
	if exitID2 != exitID || token2 != token {
		t.Fatalf("креды обязаны быть стабильными: было %s/%s, стало %s/%s", exitID, token, exitID2, token2)
	}
}

func TestV14_ExitCredentials_MigratesLegacyPlaintext(t *testing.T) {
	dir := dpapiTestEnv(t)
	path := filepath.Join(dir, "server_relay_credentials.json")

	legacy, _ := json.MarshalIndent(relay.ExitCredentials{
		ExitID:     "exit-legacy-id",
		RelayToken: "TOKEN-LEGACY-L1bSEC2",
	}, "", "  ")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	exitID, token, err := ensureExitCredentials()
	if err != nil {
		t.Fatalf("ensureExitCredentials: %v", err)
	}
	if exitID != "exit-legacy-id" || token != "TOKEN-LEGACY-L1bSEC2" {
		t.Fatalf("миграция не должна пересоздавать креды: %s/%s", exitID, token)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "TOKEN-LEGACY-L1bSEC2") {
		t.Fatalf("после миграции токен всё ещё открыт:\n%s", raw)
	}
}

// Нечитаемый файл кредов: карантин + новая пара, без падения.
func TestV14_ExitCredentials_UnreadableGoesToBakAndRegenerates(t *testing.T) {
	dir := dpapiTestEnv(t)
	path := filepath.Join(dir, "server_relay_credentials.json")

	_, token, err := ensureExitCredentials()
	if err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	raw, _ := os.ReadFile(path)
	corrupted := []byte(string(raw))
	mid := len(corrupted)/2 + 1
	if corrupted[mid] == 'A' {
		corrupted[mid] = 'B'
	} else {
		corrupted[mid] = 'A'
	}
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatalf("порча файла: %v", err)
	}

	_, token2, err := ensureExitCredentials()
	if err != nil {
		t.Fatalf("нечитаемые креды не должны ронять роль: %v", err)
	}
	if token2 == token {
		t.Error("после карантина ожидалась НОВАЯ пара")
	}
	if _, statErr := os.Stat(path + ".bak"); statErr != nil {
		t.Errorf("старый файл обязан сохраниться как .bak: %v", statErr)
	}
	if _, warned := (&Engine{}).SecretsWarning(); !warned {
		t.Error("предупреждение о нечитаемом секрете не выставлено")
	}
	newRaw, _ := os.ReadFile(path)
	if strings.Contains(string(newRaw), token2) {
		t.Error("новая пара записана открытым текстом")
	}
}
