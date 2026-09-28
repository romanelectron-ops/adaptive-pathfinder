package emergency

import (
	"os"
	"path/filepath"
	"testing"
)

// P1 (аудит 2026-09-01, security-раздел, находка №18). Раньше removeFile/overwriteWithZeros
// использовали os.Stat (следует по символьным ссылкам): содержимое ЦЕЛИ ссылки (файл вне
// DataDir/BinDir) забивалось нулями, а os.Remove удалял только саму ссылку — целевой файл
// оставался на диске пустым, WipeResult при этом рапортовал успех.
//
// Windows требует Developer Mode либо права администратора для os.Symlink на файлы — если
// создать ссылку не удалось (типичная непривилегированная машина), тест пропускается, а не
// падает: это ограничение окружения, не сигнал о дефекте.
func TestRemoveFile_SymlinkDoesNotTouchTarget(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "outside_target.txt")
	const content = "содержимое вне DataDir — трогать нельзя"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("создание целевого файла: %v", err)
	}

	link := filepath.Join(dir, "link_inside_datadir.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("os.Symlink недоступен в этом окружении (нужны права/Developer Mode): %v", err)
	}

	w := New()
	res := &WipeResult{}
	w.removeFile(link, WipeOptions{ShredPasses: 1}, res)

	// Ссылка обязана исчезнуть...
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("ссылка %q должна быть удалена, Lstat err = %v", link, err)
	}
	// ...а ЦЕЛЬ — остаться нетронутой, с исходным содержимым.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("целевой файл должен остаться на диске: %v", err)
	}
	if string(got) != content {
		t.Errorf("содержимое целевого файла изменено: got %q, want %q — "+
			"removeFile забил его нулями через символьную ссылку", string(got), content)
	}
	if len(res.Errors) != 0 {
		t.Errorf("неожиданные ошибки: %v", res.Errors)
	}
	if res.FilesDeleted != 1 {
		t.Errorf("FilesDeleted = %d, ожидалось 1 (удалена ссылка)", res.FilesDeleted)
	}
}

func TestOverwriteWithZeros_SkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target2.txt")
	const content = "не трогать"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("создание целевого файла: %v", err)
	}
	link := filepath.Join(dir, "link2.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("os.Symlink недоступен в этом окружении: %v", err)
	}

	if err := overwriteWithZeros(link, 1); err != nil {
		t.Fatalf("overwriteWithZeros(symlink) вернул ошибку: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("целевой файл должен остаться: %v", err)
	}
	if string(got) != content {
		t.Errorf("overwriteWithZeros забил нулями цель ссылки вместо самой ссылки: got %q", string(got))
	}
}
