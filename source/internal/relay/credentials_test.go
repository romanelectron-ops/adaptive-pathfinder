package relay

// credentials_test.go — EnsureExitCredentials (load-or-generate-and-save пары exit-id/
// relay-token) раньше проверялась только косвенно, через GenerateExitCredentials в
// tunnel_e2e_test.go. Сама персистентность на диске (round-trip, права доступа, откат при
// повреждённом файле, создание каталога) не имела ни одного теста — эти тесты закрывают
// пробел.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Первый вызов на пустом пути обязан сгенерировать новую пару и сохранить её на диск.
func TestEnsureExitCredentials_FirstCall_GeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "creds.json")

	exitID, token, err := EnsureExitCredentials(path)
	if err != nil {
		t.Fatalf("EnsureExitCredentials: %v", err)
	}
	if exitID == "" || token == "" {
		t.Fatal("сгенерированные exitID/token не должны быть пустыми")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("файл не создан: %v", err)
	}
	var onDisk ExitCredentials
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("файл не парсится как ExitCredentials: %v", err)
	}
	if onDisk.ExitID != exitID || onDisk.RelayToken != token {
		t.Errorf("на диске %+v, ожидалось exit_id=%q relay_token=%q", onDisk, exitID, token)
	}
}

// Повторный вызов с тем же путём обязан вернуть ТУ ЖЕ пару, а не сгенерировать новую —
// иначе Exit получал бы новый exit-id/token при каждом перезапуске приложения, и все ссылки
// с прежним exit-id, уже розданные партнёрам, переставали бы работать.
func TestEnsureExitCredentials_SecondCall_ReturnsSamePair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")

	exitID1, token1, err := EnsureExitCredentials(path)
	if err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	exitID2, token2, err := EnsureExitCredentials(path)
	if err != nil {
		t.Fatalf("второй вызов: %v", err)
	}
	if exitID1 != exitID2 || token1 != token2 {
		t.Errorf("пара разошлась между вызовами: (%q,%q) != (%q,%q)",
			exitID1, token1, exitID2, token2)
	}
}

// Повреждённый (не-JSON) файл на диске — восстановление, а не фатальный сбой: EnsureExitCredentials
// обязан откатиться на генерацию новой пары и переписать файл рабочим содержимым, а не
// вернуть ошибку разбора наружу (тот же fail-safe принцип, что и у остальных load-or-generate
// путей проекта — например, crypto/LoadOrGenerateRelayCert).
func TestEnsureExitCredentials_CorruptedFile_RegeneratesInstead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	exitID, token, err := EnsureExitCredentials(path)
	if err != nil {
		t.Fatalf("EnsureExitCredentials на повреждённом файле вернул ошибку: %v", err)
	}
	if exitID == "" || token == "" {
		t.Error("после восстановления exitID/token не должны быть пустыми")
	}

	// Файл на диске обязан быть переписан валидным содержимым (иначе следующий запуск
	// снова столкнётся с тем же повреждением).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("файл исчез: %v", err)
	}
	var onDisk ExitCredentials
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("файл всё ещё повреждён после восстановления: %v", err)
	}
}

// Файл с валидным JSON, но пустым exit_id/relay_token (например, обрезан на записи, или
// ручное редактирование) — тот же откат на генерацию новой пары, что и для полностью
// повреждённого файла: пустой секрет так же непригоден, как отсутствующий.
func TestEnsureExitCredentials_EmptyFieldsInFile_Regenerates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	blank, _ := json.Marshal(ExitCredentials{ExitID: "", RelayToken: ""})
	if err := os.WriteFile(path, blank, 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	exitID, token, err := EnsureExitCredentials(path)
	if err != nil {
		t.Fatalf("EnsureExitCredentials: %v", err)
	}
	if exitID == "" || token == "" {
		t.Error("пустые поля в файле должны быть заменены сгенерированной парой, а не сохранены как есть")
	}
}

// Несуществующий родительский каталог обязан быть создан автоматически (MkdirAll) — иначе
// первый запуск на чистой машине падал бы с ENOENT вместо тихого создания caталога данных.
func TestEnsureExitCredentials_CreatesMissingParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does", "not", "exist", "yet", "creds.json")
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("тестовая предпосылка нарушена: каталог уже существует")
	}

	if _, _, err := EnsureExitCredentials(path); err != nil {
		t.Fatalf("EnsureExitCredentials: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("файл не создан после создания недостающих каталогов: %v", err)
	}
}

// relay-token — секрет уровня пароля (docs/TZ_APF_RELAY_v1.0.md §2.1): файл обязан быть
// создан с правами 0600 (владелец: чтение+запись, остальным — ничего), а не с более
// широкими правами по умолчанию.
func TestEnsureExitCredentials_FilePermissions_Restricted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-права доступа неприменимы на Windows (ACL — другая модель)")
	}
	path := filepath.Join(t.TempDir(), "creds.json")
	if _, _, err := EnsureExitCredentials(path); err != nil {
		t.Fatalf("EnsureExitCredentials: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("права файла = %o, ожидалось 0600", perm)
	}
}

// Две независимые генерации (разные пути) обязаны дать РАЗНЫЕ пары — иначе весь механизм
// идентификации Exit-узлов был бы бессмысленным.
func TestEnsureExitCredentials_DifferentPaths_DifferentPairs(t *testing.T) {
	exitID1, token1, err := EnsureExitCredentials(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	exitID2, token2, err := EnsureExitCredentials(filepath.Join(t.TempDir(), "b.json"))
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if exitID1 == exitID2 || token1 == token2 {
		t.Error("две независимые генерации совпали — генератор случайности сломан")
	}
}
