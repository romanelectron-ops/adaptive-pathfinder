package singbox

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// Injection var — swapped in tests to avoid real HTTP calls.
//
// netguard вместо http.DefaultClient: подмену в тестах делают не везде, и прогон честно
// уходил на GitHub за архивом sing-box (Т-5). Таймаут не задан намеренно — как у
// DefaultClient: скачивание крупного архива ограничивается контекстом, а не клиентом.
var httpClientForDownload = netguard.Client(0)

// Injection var — swapped in tests to change OS-specific path selection.
var downloaderGOOS = func() string { return runtime.GOOS }

// Downloader — умный загрузчик sing-box
type Downloader struct {
	Version    string
	BinDir     string
	OnProgress func(pct int, msg string)
	OnLog      func(string)
}

// NewDownloader создаёт загрузчик
func NewDownloader(binDir string) *Downloader {
	return &Downloader{
		Version: SingBoxVersion,
		BinDir:  binDir,
	}
}

// EnsureInstalled проверяет наличие sing-box и скачивает если нужно
func (d *Downloader) EnsureInstalled(ctx context.Context) error {
	p := NewProcess(d.BinDir, os.TempDir())

	if p.IsInstalled() {
		ver, err := p.Version()
		if err == nil {
			d.log(fmt.Sprintf("sing-box already installed: %s", ver))
			return nil
		}
	}

	d.log("sing-box not found, downloading...")
	return d.Download(ctx)
}

// Download скачивает и устанавливает sing-box
func (d *Downloader) Download(ctx context.Context) error {
	url, archiveName := d.buildURL()
	d.log(fmt.Sprintf("Downloading sing-box v%s for %s/%s", d.Version, runtime.GOOS, runtime.GOARCH))
	d.log(fmt.Sprintf("From: %s", url))

	if err := os.MkdirAll(d.BinDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", d.BinDir, err)
	}

	// Скачиваем во временный файл
	tmpPath := filepath.Join(d.BinDir, "tmp_"+archiveName)
	defer os.Remove(tmpPath)

	if err := d.downloadFile(ctx, url, tmpPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	// Извлекаем бинарник
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	destPath := filepath.Join(d.BinDir, binName)

	d.progress(90, "Extracting...")
	if err := d.extract(tmpPath, archiveName, binName, destPath); err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	// chmod
	if runtime.GOOS != "windows" {
		os.Chmod(destPath, 0755)
	}

	d.progress(100, "Done")
	d.log(fmt.Sprintf("sing-box installed at: %s", destPath))
	return nil
}

func (d *Downloader) downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "APF/1.0")

	resp, err := httpClientForDownload.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := resp.Body.Read(buf)
		if n > 0 {
			f.Write(buf[:n])
			downloaded += int64(n)
			if total > 0 {
				pct := int(downloaded * 85 / total) // 0-85%, остальное — распаковка
				d.progress(pct, fmt.Sprintf("%.1f / %.1f MB",
					float64(downloaded)/1e6, float64(total)/1e6))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// extract распаковывает sing-box бинарник из архива
func (d *Downloader) extract(archivePath, archiveName, binName, destPath string) error {
	if strings.HasSuffix(archiveName, ".zip") {
		return d.extractFromZip(archivePath, binName, destPath)
	}
	return d.extractFromTarGz(archivePath, binName, destPath)
}

func (d *Downloader) extractFromZip(src, binName, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Ищем sing-box.exe в любой вложенной папке
		if filepath.Base(f.Name) != binName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, rc)
		return err
	}
	return fmt.Errorf("%s not found in archive", binName)
}

func (d *Downloader) extractFromTarGz(src, binName, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != binName {
			continue
		}

		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, tr)
		return err
	}
	return fmt.Errorf("%s not found in archive", binName)
}

func (d *Downloader) buildURL() (url, archiveName string) {
	goos := downloaderGOOS()
	goarch := runtime.GOARCH

	archMap := map[string]string{
		"amd64": "amd64", "arm64": "arm64",
		"386": "386", "arm": "armv7",
	}
	arch := archMap[goarch]
	if arch == "" {
		arch = goarch
	}

	switch goos {
	case "windows":
		archiveName = fmt.Sprintf("sing-box-%s-windows-%s.zip", d.Version, arch)
	case "darwin":
		archiveName = fmt.Sprintf("sing-box-%s-darwin-%s.tar.gz", d.Version, arch)
	default:
		archiveName = fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", d.Version, arch)
	}

	url = fmt.Sprintf(
		"https://github.com/SagerNet/sing-box/releases/download/v%s/%s",
		d.Version, archiveName,
	)
	return
}

func (d *Downloader) log(msg string) {
	if d.OnLog != nil {
		d.OnLog(msg)
	}
}

func (d *Downloader) progress(pct int, msg string) {
	if d.OnProgress != nil {
		d.OnProgress(pct, msg)
	}
}
