// Package testenv — обвязка для тестов: уводит каталог данных APF из профиля
// пользователя во временный.
//
// В production-сборку пакет не попадает: его импортируют только файлы _test.go, а Go
// не включает в бинарник пакеты, которые никто не импортирует.
//
// Зачем это нужно (дефекты D-E1, D-E2). Тесты пишут туда, куда указывает
// config.DataDir(), а он на Windows берёт %APPDATA%, на прочих системах — домашний
// каталог. Прогон `go test ./internal/...` оставлял в НАСТОЯЩЕМ профиле пользователя
// config.json, bypass_list.json и кэш узлов на три с лишним мегабайта, скачанный из
// сети. Барьер internal/hostguard этого не ловит: он сторожит состояние ОС, а не файлы.
//
// Пакет намеренно НЕ импортирует internal/config: тому нужна такая же изоляция в
// собственных тестах, и импорт замкнул бы цикл. Проверку «подмена подействовала»
// выполняет вызывающая сторона — ей config уже доступен.
package testenv

import (
	"fmt"
	"os"
	"path/filepath"
)

// Isolate подменяет переменные окружения, из которых выводится каталог данных, на
// свежий временный каталог.
//
// Вызывать ТОЛЬКО из TestMain и только до m.Run(): подмена глобальна для процесса, а
// сделанная позже оставила бы часть тестов работать с настоящим профилем.
//
// Возвращает путь к временному каталогу и функцию удаления.
func Isolate(prefix string) (dir string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", nil, fmt.Errorf("временный каталог данных: %w", err)
	}

	// APPDATA — ветка windows в config.DataDir();
	// HOME и USERPROFILE — os.UserHomeDir() на прочих системах и на запасном пути
	// windows-ветки (когда APPDATA пуста);
	// XDG_CONFIG_HOME — на случай, если каталог когда-нибудь начнут выводить по XDG.
	for _, kv := range [][2]string{
		{"APPDATA", tmp},
		{"HOME", tmp},
		{"USERPROFILE", tmp},
		{"XDG_CONFIG_HOME", filepath.Join(tmp, ".config")},
	} {
		if e := os.Setenv(kv[0], kv[1]); e != nil {
			_ = os.RemoveAll(tmp)
			return "", nil, fmt.Errorf("подмена %s: %w", kv[0], e)
		}
	}

	return tmp, func() { _ = os.RemoveAll(tmp) }, nil
}

// MustIsolate — Isolate для TestMain: при неудаче незачем запускать тесты, которые
// начнут писать в профиль пользователя.
func MustIsolate(prefix string) (dir string, cleanup func()) {
	dir, cleanup, err := Isolate(prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "изоляция каталога данных не удалась: %v\n", err)
		os.Exit(1)
	}
	return dir, cleanup
}

// CheckRedirected убеждается, что подмена подействовала на самом деле.
//
// Проверяем факт, а не намерение: путь мог быть вычислен в обход config.DataDir().
// Вызывающая сторона передаёт сюда результат config.DataDir() — импортировать config
// здесь нельзя, см. комментарий к пакету.
func CheckRedirected(dataDir, tmp string) {
	if len(dataDir) < len(tmp) || dataDir[:len(tmp)] != tmp {
		fmt.Fprintf(os.Stderr,
			"каталог данных не увёлся во временный: получено %q, ожидался префикс %q\n"+
				"без этого тесты снова писали бы в профиль пользователя\n", dataDir, tmp)
		os.Exit(1)
	}
}
