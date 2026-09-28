//go:build windows

package crypto

// Реализация DPAPI через crypt32.dll (golang.org/x/sys/windows, уже в vendor — CGO не нужен).
//
// Область — CRYPTPROTECT_LOCAL_MACHINE (машинная), НЕ пользовательская. Обоснование (S-5
// оставляет выбор открытым, решение записано как допущение лота L1b-SEC2):
//
//	apf-svc.exe работает под LocalSystem (ServiceStartName пуст), GUI — под пользователем, и
//	это ОДНИ И ТЕ ЖЕ файлы: config.json служба читает и пишет в профиле ИНТЕРАКТИВНОГО
//	пользователя (config.FindInteractiveUserConfigPath — инцидент 2026-08-19), каталог данных
//	службе переопределяют через config.SetDataDirOverride. При пользовательской области файл,
//	записанный службой, был бы нечитаем для GUI и наоборот — то есть гарантированный вход в
//	ветку «не смог расшифровать» на КАЖДОМ старте, ровно то, чего В-2 требует избежать.
//
// CRYPTPROTECT_UI_FORBIDDEN обязателен: в службе некому показать диалог, без флага вызов в
// сессии 0 может зависнуть вместо честной ошибки.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiSupported = true

func newDataBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{Size: 0, Data: nil}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// copyDataBlob копирует результат в память Go и освобождает LocalAlloc-буфер, который
// оставила после себя crypt32 (иначе — утечка на каждый вызов).
func copyDataBlob(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return []byte{}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Size == 0 {
		return []byte{}
	}
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func dpapiProtect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(
		newDataBlob(plain),
		nil, // описание не нужно: имя файла и так известно вызывающей стороне
		newDataBlob(dpapiEntropy),
		0,
		nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN,
		&out,
	)
	if err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	return copyDataBlob(&out), nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptUnprotectData(
		newDataBlob(blob),
		nil,
		newDataBlob(dpapiEntropy),
		0,
		nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		&out,
	)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	return copyDataBlob(&out), nil
}
