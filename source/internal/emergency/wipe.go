package emergency

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// walkFn is replaceable in tests to inject walk errors.
var walkFn = filepath.Walk

// Wiper выполняет аварийную очистку данных приложения.
type Wiper struct{}

// WipeOptions параметры удаления.
type WipeOptions struct {
	WipeSelf    bool
	WipeSingBox bool
	ShredPasses int
	OnProgress  func(step, total int, msg string)

	// ExtraFiles — P1 (аудит 2026-09-01, security-раздел, находка №17 «улики»): отдельные
	// файлы ВНЕ dataDir/binDir, которые тоже нужно стереть — например, временный
	// netsh-скрипт с IP VPN-узла в %TEMP% (обычно сам себя удаляет через defer, но не
	// переживает крах процесса — см. killswitch.EnableWithUAC) или метка порта Web UI в
	// %ProgramData% (config.PortFilePath — вне DataDir/%APPDATA%, Wipe() её не видит).
	// Каждый путь стирается тем же shred-проходом, что и остальное; отсутствие файла —
	// НЕ ошибка (тот же контракт, что и у walkFn/removeFile ниже).
	ExtraFiles []string
}

// WipeResult итог удаления.
type WipeResult struct {
	FilesDeleted int
	BytesDeleted int64
	Errors       []string
	Duration     time.Duration
}

// New создаёт новый Wiper.
func New() *Wiper {
	return &Wiper{}
}

// Wipe удаляет файлы данных и, опционально, бинарники.
func (w *Wiper) Wipe(dataDir, binDir string, opts WipeOptions) *WipeResult {
	started := time.Now()
	res := &WipeResult{}
	if opts.ShredPasses < 1 {
		opts.ShredPasses = 1
	}

	targets := []string{dataDir}
	if opts.WipeSingBox || opts.WipeSelf {
		targets = append(targets, binDir)
	}
	total := len(targets) + len(opts.ExtraFiles)

	for i, root := range targets {
		if root == "" {
			continue
		}
		if opts.OnProgress != nil {
			opts.OnProgress(i+1, total, "Wiping "+root)
		}
		w.wipePath(root, opts, res)
	}

	for i, f := range opts.ExtraFiles {
		if f == "" {
			continue
		}
		if opts.OnProgress != nil {
			opts.OnProgress(len(targets)+i+1, total, "Wiping "+f)
		}
		w.removeFile(f, opts, res)
	}

	res.Duration = time.Since(started)
	return res
}

func (w *Wiper) wipePath(root string, opts WipeOptions, res *WipeResult) {
	info, err := os.Stat(root)
	if err != nil {
		if !os.IsNotExist(err) {
			res.Errors = append(res.Errors, err.Error())
		}
		return
	}

	if !info.IsDir() {
		w.removeFile(root, opts, res)
		return
	}

	_ = walkFn(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			res.Errors = append(res.Errors, walkErr.Error())
			return nil
		}
		if fi.IsDir() {
			return nil
		}

		// Когда wipe binaries не requested, оставляем бинарники.
		if !opts.WipeSingBox && strings.Contains(strings.ToLower(path), "sing-box") {
			return nil
		}
		w.removeFile(path, opts, res)
		return nil
	})
}

func (w *Wiper) removeFile(path string, opts WipeOptions, res *WipeResult) {
	// P1 (аудит 2026-09-01, security-раздел, находка №18): Lstat, не Stat — иначе на файловой
	// ссылке (Windows-симлинк, требует Developer Mode/прав, но не невозможен — сторонним
	// установщиком или самим пользователем) размер и дальнейшая перезапись относились бы к
	// ЦЕЛИ ссылки, а не к самой ссылке внутри DataDir/BinDir. overwriteWithZeros(path) через
	// os.OpenFile СЛЕДУЕТ по ссылке и физически забивает нулями чужой файл вне подконтрольного
	// APF каталога; os.Remove(path) ниже при этом удаляет только саму ссылку — целевой файл
	// остаётся на диске, просто пустым, а WipeResult рапортует успех как ни в чём не бывало.
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		// P1 (аудит 2026-09-01): раньше "не существует" всё равно инкрементировал
		// FilesDeleted (падал в общий путь ниже) — WipeResult.FilesDeleted тогда включал
		// файлы, которых не было вовсе. Раньше не наблюдалось на практике (removeFile
		// вызывался только из wipePath, для файлов, которые сама walkFn только что нашла
		// существующими), но с WipeOptions.ExtraFiles — списком путей, которые часто
		// заведомо отсутствуют (например, самоочищающийся временный netsh-скрипт) — это
		// стало бы систематическим искажением счётчика для вызывающей стороны.
		return
	}
	isRegular := err == nil && fi.Mode().IsRegular()
	if err == nil {
		res.BytesDeleted += fi.Size()
	}

	// Shred — ТОЛЬКО для обычных файлов. Символьная ссылка, устройство и т.п. не перезаписываем:
	// у них либо нет собственного содержимого, либо перезапись ушла бы не туда (см. выше).
	if isRegular {
		_ = overwriteWithZeros(path, opts.ShredPasses)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		res.Errors = append(res.Errors, err.Error())
		return
	}
	res.FilesDeleted++
}

func overwriteWithZeros(path string, passes int) error {
	// Lstat: вторая линия защиты от того же класса дефекта, что и в removeFile — эта функция
	// не экспортируется и сегодня вызывается только оттуда (уже отфильтровавшей симлинки), но
	// как самостоятельная примитив-функция она обязана быть безопасна и при прямом вызове.
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() || !fi.Mode().IsRegular() {
		return nil
	}

	size := fi.Size()
	if size <= 0 {
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	for p := 0; p < passes; p++ {
		if _, err = f.Seek(0, 0); err != nil {
			return err
		}
		remaining := size
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			if _, err = f.Write(buf[:n]); err != nil {
				return err
			}
			remaining -= n
		}
		if err = f.Sync(); err != nil {
			return err
		}
	}
	return nil
}
