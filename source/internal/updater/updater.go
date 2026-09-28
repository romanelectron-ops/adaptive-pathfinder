// Package updater проверяет наличие новых версий APF на GitHub и применяет обновления.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// updaterHTTPClient — вместо http.DefaultClient: прогон тестов ходил на api.github.com
// за списком релизов (Т-5). Таймаут не задан намеренно — как у DefaultClient: скачивание
// обновления ограничивается контекстом запроса, а не клиентом.
var updaterHTTPClient = netguard.Client(0)

const (
	requestTimeout = 15 * time.Second

	// maxUpdateBytes — верхняя граница размера скачиваемого обновления (P1-9).
	// Ориентир: боевой APF.exe ~22 МБ, инсталлятор ~31 МБ; 200 МБ — заведомо достаточный
	// запас, при этом отсекающий бесконечный поток от враждебного/сломанного сервера.
	maxUpdateBytes = 200 * 1024 * 1024
)

// githubAPI — URL GitHub API для проверки последнего релиза (var для подмены в тестах).
//
// 2026-09-29: официальный открытый репозиторий проекта — romanelectron-ops/adaptive-pathfinder.
// Раньше здесь стоял apf/adaptive-pathfinder — организация, которой не существовало: её мог
// занять кто угодно и публиковать «релизы» с бОльшей версией (уведомление «доступно
// обновление» вело бы на чужой файл). Применение обновлений по-прежнему выключено
// (engine.updateApplyEnabled) — релизы не подписаны.
var githubAPI = "https://api.github.com/repos/romanelectron-ops/adaptive-pathfinder/releases/latest"

// autoCheckInterval is the period for StartAutoCheck ticker (overrideable in tests).
var autoCheckInterval = 24 * time.Hour

// updaterGOOS — точка подмены целевой ОС для тестов.
var updaterGOOS = func() string { return runtime.GOOS }

// SelfUpdateSupported — можно ли на этой системе применить обновление (дефект D-A23).
//
// Вход:      целевая ОС.
// Тело:      мобильные системы отделяются от настольных.
// Выход:     false там, где заменить собственный исполняемый файл невозможно.
// Fail-safe: сомнение трактуется в пользу «нельзя» — лишняя проверка обновлений это
//
//	бесполезный поход в сеть, а ложная попытка обновиться — испорченная установка.
//
// Инвариант: проверка обновлений не запускается там, где её результатом всё равно
// нельзя воспользоваться.
//
// Почему это про Android. Обновление применяется заменой файла: Apply() берёт
// os.Executable(), скачивает новый и делает os.Rename поверх. В Android приложение
// живёт в APK, подписанном ключом разработчика; заменить его может только системный
// установщик пакетов. Вдобавок с Android 10 запуск файлов из каталога данных запрещён
// (W^X) — подменённый файл было бы нечем запустить.
//
// Наблюдалось это как строка `updater: initial check error: updater: GitHub API returned 404`
// при каждом запуске приложения на телефоне: поход в сеть до поднятия туннеля, всегда
// безрезультатный.
func SelfUpdateSupported() bool {
	switch updaterGOOS() {
	case "android", "ios":
		return false
	}
	return true
}

// executableFn is os.Executable, overrideable in tests.
var executableFn = os.Executable

// renameFn is os.Rename, overrideable in tests.
var renameFn = os.Rename

// goosHook and goarchHook override runtime.GOOS/GOARCH in pickAsset (tests only).
var goosHook = ""
var goarchHook = ""

// UpdateStatus содержит результат проверки обновлений.
type UpdateStatus struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	DownloadURL     string    `json:"download_url"`
	ReleaseNotes    string    `json:"release_notes"`
	CheckedAt       time.Time `json:"checked_at"`

	// SHA256 — ожидаемая контрольная сумма выбранного бинарника (hex, нижний регистр), если
	// релиз публикует манифест контрольных сумм (см. findChecksumManifest). Пусто, если релиз
	// такого манифеста не публикует — DownloadAndApply в этом случае не может проверить
	// целостность/подлинность файла и обязан честно предупредить об этом (см. её комментарий).
	//
	// Менее срочная находка аудита 2026-09-01 (security-раздел, №3): апстрим не проверял
	// скачанный бинарник вообще никак, кроме кода ответа HTTP (P1-9). Полноценная защита от
	// компрометации самого репозитория/пайплайна публикации требует офлайн-ключа подписи,
	// которого у проекта сегодня нет — эта проверка не заменяет его, а защищает от повреждения
	// при передаче и от подмены на стороне CDN/канала загрузки, если сам манифест не подменён
	// одновременно с бинарником (тот же источник — та же граница доверия, что и раньше).
	SHA256 string `json:"sha256,omitempty"`
}

// Updater периодически проверяет наличие обновлений APF.
type Updater struct {
	currentVersion string
	mu             sync.RWMutex
	lastStatus     *UpdateStatus
	wg             sync.WaitGroup // B-25: позволяет дождаться завершения фоновой горутины
	// Callbacks (опциональные, устанавливаются снаружи)
	OnLog             func(msg string)
	OnUpdateAvailable func(status *UpdateStatus)
}

// New создаёт Updater с текущей версией приложения.
func New(currentVersion string) *Updater {
	return &Updater{
		currentVersion: strings.TrimPrefix(currentVersion, "v"),
	}
}

// githubRelease — ответ GitHub API /releases/latest.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckForUpdate запрашивает GitHub API и возвращает статус обновления.
func (u *Updater) CheckForUpdate(ctx context.Context) (*UpdateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("updater: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "APF/"+u.currentVersion)

	resp, err := updaterHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("updater: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("updater: GitHub API returned %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("updater: decode response: %w", err)
	}

	latest := strings.TrimPrefix(rel.TagName, "v")
	status := &UpdateStatus{
		CurrentVersion:  u.currentVersion,
		LatestVersion:   latest,
		UpdateAvailable: compareVersions(u.currentVersion, latest) < 0,
		ReleaseNotes:    rel.Body,
		CheckedAt:       time.Now(),
	}

	// Выбираем бинарник под текущую платформу
	assetName, assetURL := pickAssetMatch(rel.Assets)
	status.DownloadURL = assetURL

	// Контрольная сумма (см. doc-comment UpdateStatus.SHA256) — best-effort: отсутствие
	// манифеста или ошибка его скачивания не должны срывать саму проверку обновления,
	// DownloadAndApply просто честно предупредит при пустом SHA256.
	if manifestURL := findChecksumManifest(rel.Assets); manifestURL != "" && assetName != "" {
		if sum := u.fetchChecksum(ctx, manifestURL, assetName); sum != "" {
			status.SHA256 = sum
		}
	}

	u.mu.Lock()
	u.lastStatus = status
	u.mu.Unlock()

	if status.UpdateAvailable && u.OnUpdateAvailable != nil {
		u.OnUpdateAvailable(status)
	}
	if u.OnLog != nil {
		u.OnLog(fmt.Sprintf("updater: current=%s latest=%s available=%v",
			status.CurrentVersion, status.LatestVersion, status.UpdateAvailable))
	}
	return status, nil
}

// StartAutoCheck запускает фоновую горутину, которая проверяет обновления каждые 24 часа.
// Горутина завершается когда ctx отменён.
func (u *Updater) StartAutoCheck(ctx context.Context) {
	// Дефект D-A23: не ходим в сеть за тем, чем не сможем воспользоваться.
	if !SelfUpdateSupported() {
		if u.OnLog != nil {
			u.OnLog("updater: обновление приложения на этой системе ставит системный " +
				"установщик пакетов, а не APF — проверка не запускается")
		}
		return
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		// Первая проверка при запуске
		if _, err := u.CheckForUpdate(ctx); err != nil && u.OnLog != nil {
			u.OnLog(fmt.Sprintf("updater: initial check error: %v", err))
		}
		ticker := time.NewTicker(autoCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := u.CheckForUpdate(ctx); err != nil && u.OnLog != nil {
					u.OnLog(fmt.Sprintf("updater: periodic check error: %v", err))
				}
			}
		}
	}()
}

// Wait блокирует до завершения фоновой горутины StartAutoCheck (после отмены ctx).
// B-25: даёт штатную остановку (graceful shutdown) и детерминированность в тестах —
// без него горутина переживала вызывающий код и читала глобальные переменные после
// их восстановления (гонка данных, ловится -race).
func (u *Updater) Wait() {
	u.wg.Wait()
}

// GetLastStatus возвращает последний закэшированный статус (может быть nil).
func (u *Updater) GetLastStatus() *UpdateStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.lastStatus == nil {
		return &UpdateStatus{CurrentVersion: u.currentVersion}
	}
	return u.lastStatus
}

// DownloadAndApply скачивает бинарник и заменяет текущий исполняемый файл.
//
// expectedSHA256 — hex-строка ожидаемой контрольной суммы (обычно UpdateStatus.SHA256 из
// CheckForUpdate). Пустая строка означает «релиз не публикует манифест контрольных сумм» —
// DownloadAndApply в этом случае НЕ отказывает (иначе апдейтер перестал бы работать вовсе,
// пока не появится инфраструктура публикации манифестов), но громко предупреждает в лог:
// целостность и подлинность файла в этом случае ничем не подтверждены, ровно как и раньше
// этой правки. Несовпадающая непустая сумма — жёсткий отказ, файл не применяется.
func (u *Updater) DownloadAndApply(ctx context.Context, downloadURL string, expectedSHA256 string, onProgress func(int)) error {
	if downloadURL == "" {
		return fmt.Errorf("updater: empty download URL")
	}
	if u.OnLog != nil {
		u.OnLog(fmt.Sprintf("updater: downloading from %s", downloadURL))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("updater: build download request: %w", err)
	}

	resp, err := updaterHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("updater: download failed: %w", err)
	}
	defer resp.Body.Close()

	// P1-9 (аудит 2026-09-01): проверка кода ответа.
	//
	// Раньше её здесь не было (в отличие от CheckForUpdate, где она есть). Любой ответ —
	// 404, 403, 502 со страницей ошибки — записывался в exe+".update", получал chmod 0755 и
	// переименовывался поверх работающего apf.exe. Пользователь видел «update applied,
	// please restart APF», перезапускался и обнаруживал, что приложение больше не стартует,
	// потому что это HTML на пару сотен байт.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("updater: сервер обновлений вернул HTTP %d — обновление не применено",
			resp.StatusCode)
	}

	// Временный файл рядом с текущим бинарником
	exe, err := executableFn()
	if err != nil {
		return fmt.Errorf("updater: locate executable: %w", err)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	tmp := exe + ".update"

	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("updater: create temp file: %w", err)
	}

	total := resp.ContentLength
	var written int64
	buf := make([]byte, 32*1024)
	hasher := sha256.New()
	// P1-9: верхняя граница объёма. Без неё враждебный (или просто сломанный) сервер
	// обновлений мог отдавать бесконечный поток, забивая диск пользователя — размер не
	// ограничивался ничем, кроме контекста.
	body := io.LimitReader(resp.Body, maxUpdateBytes)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				os.Remove(tmp)
				return fmt.Errorf("updater: write: %w", werr)
			}
			hasher.Write(buf[:n]) // io.Writer, не возвращает ошибку — hash.Hash контракт
			written += int64(n)
			if onProgress != nil && total > 0 {
				onProgress(int(written * 100 / total))
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("updater: read: %w", rerr)
		}
	}
	f.Close()

	// P1-9: пустой/усечённый ответ не должен становиться исполняемым файлом.
	if written == 0 {
		os.Remove(tmp)
		return fmt.Errorf("updater: сервер вернул пустой файл — обновление не применено")
	}
	if written >= maxUpdateBytes {
		os.Remove(tmp)
		return fmt.Errorf("updater: размер загрузки превысил лимит %d МБ — обновление отклонено",
			maxUpdateBytes/(1024*1024))
	}

	// Контрольная сумма (см. doc-comment функции и UpdateStatus.SHA256).
	gotSHA256 := hex.EncodeToString(hasher.Sum(nil))
	switch {
	case expectedSHA256 == "":
		if u.OnLog != nil {
			u.OnLog("updater: ВНИМАНИЕ — релиз не публикует манифест контрольных сумм, " +
				"целостность и подлинность скачанного файла НЕ проверены")
		}
	case !strings.EqualFold(gotSHA256, expectedSHA256):
		os.Remove(tmp)
		return fmt.Errorf("updater: контрольная сумма не совпадает (ожидалось %s, получено %s) "+
			"— файл повреждён при передаче или подменён, обновление ОТКЛОНЕНО",
			expectedSHA256, gotSHA256)
	default:
		if u.OnLog != nil {
			u.OnLog("updater: контрольная сумма совпала (" + gotSHA256 + ")")
		}
	}

	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("updater: chmod: %w", err)
	}

	// Атомарная замена: переименовываем старый, ставим новый
	backup := exe + ".old"
	os.Remove(backup)
	if err := renameFn(exe, backup); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("updater: backup current binary: %w", err)
	}
	if err := renameFn(tmp, exe); err != nil {
		// Откат
		renameFn(backup, exe) //nolint:errcheck
		return fmt.Errorf("updater: replace binary: %w", err)
	}
	os.Remove(backup)

	if u.OnLog != nil {
		u.OnLog("updater: update applied, please restart APF")
	}
	return nil
}

// pickAsset выбирает ссылку на бинарник под текущую ОС/архитектуру.
func pickAsset(assets []struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}) string {
	_, url := pickAssetMatch(assets)
	return url
}

// pickAssetMatch — то же, что pickAsset, но отдаёт ещё и имя выбранного ассета: оно нужно,
// чтобы найти строку с его контрольной суммой в манифесте (fetchChecksum), а сам pickAsset
// исторически отдаёт только URL и его сигнатуру трогать незачем — весь существующий код и
// тесты продолжают работать без изменений.
func pickAssetMatch(assets []struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}) (name string, url string) {
	goos := runtime.GOOS
	if goosHook != "" {
		goos = goosHook
	}
	goarch := runtime.GOARCH
	if goarchHook != "" {
		goarch = goarchHook
	}

	// Маппинг: windows/amd64 → "windows", linux/amd64 → "linux"
	var want []string
	switch goos {
	case "windows":
		want = []string{"windows", ".exe"}
	case "linux":
		want = []string{"linux"}
	case "darwin":
		want = []string{"darwin", "macos"}
	}
	if goarch == "arm64" {
		want = append(want, "arm64")
	}

	for _, a := range assets {
		low := strings.ToLower(a.Name)
		match := true
		for _, w := range want {
			if !strings.Contains(low, w) {
				match = false
				break
			}
		}
		if match {
			return a.Name, a.BrowserDownloadURL
		}
	}
	// Fallback: первый ассет
	if len(assets) > 0 {
		return assets[0].Name, assets[0].BrowserDownloadURL
	}
	return "", ""
}

// checksumManifestNames — общепринятые имена файла с контрольными суммами релиза
// (формат `sha256sum`: "<hex>  <имя файла>" построчно, опционально с "*" перед именем
// в бинарном режиме). Сравнение регистронезависимое.
var checksumManifestNames = []string{
	"checksums.txt", "sha256sums", "sha256sums.txt", "checksums.sha256",
}

// findChecksumManifest ищет в списке ассетов релиза файл-манифест контрольных сумм по
// общепринятому имени. Пусто, если релиз такой файл не публикует.
func findChecksumManifest(assets []struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}) string {
	for _, a := range assets {
		low := strings.ToLower(a.Name)
		for _, want := range checksumManifestNames {
			if low == want {
				return a.BrowserDownloadURL
			}
		}
	}
	return ""
}

// maxChecksumManifestBytes — манифест текстовый и на релиз с разумным числом ассетов весит
// килобайты; тот же принцип, что и maxUpdateBytes (P1-9) — не читать неограниченный поток от
// сервера, которым бы он ни был.
const maxChecksumManifestBytes = 1 << 20 // 1 МБ — щедрый запас для сотен строк

// fetchChecksum скачивает манифест контрольных сумм и возвращает hex SHA-256 (нижний
// регистр) для assetName, либо "", если файл не скачался или в нём нет такой строки —
// best-effort, вызывающая сторона (CheckForUpdate) не считает это фатальной ошибкой.
func (u *Updater) fetchChecksum(ctx context.Context, manifestURL, assetName string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return ""
	}
	resp, err := updaterHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumManifestBytes))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if strings.EqualFold(name, assetName) {
			return strings.ToLower(fields[0])
		}
	}
	return ""
}

// compareVersions возвращает -1, 0 или 1 (упрощённое сравнение semver).
func compareVersions(a, b string) int {
	pa := parseVer(a)
	pb := parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseVer(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	var major, minor, patch int
	fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
	return [3]int{major, minor, patch}
}
