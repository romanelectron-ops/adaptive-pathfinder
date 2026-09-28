// Package config управляет путями и I/O конфигурации APF.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Injection vars for testing OS-specific branches.
var (
	runtimeGOOS     = runtime.GOOS
	osExecutableFn  = os.Executable
	osUserHomeDirFn = os.UserHomeDir
	osTempDirFn     = os.TempDir
	winUsersRoot    = `C:\Users`
	globFn          = filepath.Glob
	statFn          = os.Stat
)

// withAbsFallback — находка консилиума 2026-08-10 (low): ветки windows/default DataDir
// зависят от APPDATA/UserHomeDir — при пустых обоих (нетипичная, но реальная служебная
// учётка без загруженного профиля, например Windows-служба, запущенная SCM) filepath.Join
// с пустой базой давал ОТНОСИТЕЛЬНЫЙ путь ("APF" вместо C:\Users\...\APF). Инвариант,
// заявленный у CacheFileConfig.Path («ВСЕГДА абсолютный путь, никогда не пустая строка»),
// нарушался молча — ни один вызывающий код это не проверял. os.TempDir() документированно
// никогда не возвращает пустую строку, поэтому годится как абсолютный запасной путь.
//
// НЕ применяется к ветке android (см. DataDir) — там APF_DATA_DIR приходит от Kotlin-слоя
// или используется зашитый Unix-путь, уже абсолютный по построению, а filepath.IsAbs на
// хосте, где реально гоняются тесты (Windows), трактует "/data/data/..." как ОТНОСИТЕЛЬНЫЙ
// (нет буквы диска) — ложно сработал бы фоллбэк, ломая android-ветку именно на той
// платформе, где этот код физически не выполняется (кросс-компиляция под Android использует
// настоящую unix-семантику filepath на сборке под GOOS=android).
func withAbsFallback(dir string) string {
	if !filepath.IsAbs(dir) {
		return filepath.Join(osTempDirFn(), "APF")
	}
	return dir
}

// dataDirOverride — см. SetDataDirOverride.
var (
	dataDirOverride   string
	dataDirOverrideMu sync.RWMutex
)

// SetDataDirOverride переопределяет DataDir() для ВСЕХ последующих вызовов в процессе.
// Нужен процессам, чей нативный APPDATA не совпадает с профилем реального интерактивного
// пользователя — Windows-служба apf-svc.exe под LocalSystem резолвит DataDir() в
// C:\Windows\System32\config\systemprofile\..., отдельный от %APPDATA%\APF пользователя, и
// заводит там свой собственный nodes_cache.json (P1.1, docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md
// — тот же класс дефекта, что уже чинили для config.json в FindInteractiveUserConfigPath, но
// для КАТАЛОГА данных, не одного файла). Звать ДО engine.New()/NewServiceHost() — dataDir
// прошивается в несколько подкомпонентов (singbox.NewProcess, killswitch.SetSentinelDir,
// bypass.NewManager, fallback-оркестратор) в момент конструктора, не при каждом обращении к
// DataDir() позже.
func SetDataDirOverride(path string) {
	dataDirOverrideMu.Lock()
	dataDirOverride = path
	dataDirOverrideMu.Unlock()
}

// DataDir возвращает путь к директории данных APF.
func DataDir() string {
	dataDirOverrideMu.RLock()
	if dataDirOverride != "" {
		d := dataDirOverride
		dataDirOverrideMu.RUnlock()
		return d
	}
	dataDirOverrideMu.RUnlock()
	switch runtimeGOOS {
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			base, _ = osUserHomeDirFn()
		}
		return withAbsFallback(filepath.Join(base, "APF"))
	case "android":
		base := os.Getenv("APF_DATA_DIR")
		if base == "" {
			base = "/data/data/com.apf.app/files"
		}
		return base
	default:
		base, _ := osUserHomeDirFn()
		return withAbsFallback(filepath.Join(base, ".config", "apf"))
	}
}

// ConfigPath возвращает путь к файлу конфигурации
func ConfigPath() string {
	return filepath.Join(DataDir(), "config.json")
}

// SharedDataDir — каталог, читаемый и служебной учёткой (SYSTEM), и интерактивным
// пользователем ОДИНАКОВО, в отличие от DataDir() (%APPDATA%, у SYSTEM и у человека —
// РАЗНЫЕ профили, см. FindInteractiveUserConfigPath выше). Нужен для данных, которые
// пишет один процесс (владелец Web UI, см. WritePortFile), а читает другой, работающий
// под другой учёткой (GUI-наблюдатель, cmd/apf-tray в режиме наблюдателя) — обходить это
// эвристикой сканирования профилей (как для config.json) для каждого нового файла такого
// рода избыточно, когда есть готовый общий каталог уровня машины.
func SharedDataDir() string {
	if runtimeGOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "APF")
	}
	return DataDir()
}

func portFilePath() string {
	return filepath.Join(SharedDataDir(), "webui_port.txt")
}

// PortFilePath — экспортированный доступ к portFilePath для internal/engine (аварийное
// стирание, находка «улики» аудита 2026-09-01: файл лежит в SharedDataDir/%ProgramData%, не
// в DataDir/%APPDATA%, поэтому Wipe() его не трогает — engine.EmergencyWipe стирает его
// отдельно, явным путём).
func PortFilePath() string { return portFilePath() }

// WritePortFile публикует ФАКТИЧЕСКИЙ порт, на котором поднялся Web UI (internal/web/
// server.go, Start()) — живой инцидент 2026-08-25: сторонний процесс (Docker Desktop/WSL)
// занял настроенный по умолчанию 9090 раньше APF; сам сервер это переживает (перебирает
// диапазон и садится на следующий свободный), но GUI-наблюдатель (webclient.go) слепо
// стучался в cfg.WebUIPort и ловил либо чужой процесс на этом порту, либо тишину — для
// пользователя это выглядело как «не подключилось»/«не может найти узел» без всякой
// связи с истинной причиной. Запись — best-effort: невозможность создать SharedDataDir
// не должна ронять сам веб-сервер, только оставлять наблюдателей без подсказки (они
// откатятся на cfg.WebUIPort, как и раньше этого механизма).
// hardenPortFileACLFn — S-4 (TZ v1.4, лот L1-KS): webui_port.txt создаётся с правами 0644 в
// %ProgramData%\APF и наследует DACL каталога — на обычной машине это, как правило,
// Everyone/Users на чтение, то есть порт локального Web UI API виден ЛЮБОМУ локальному
// пользователю, не только владельцу процесса/администраторам. По умолчанию — no-op:
// на не-Windows платформах (Linux/Android) SharedDataDir() совпадает с DataDir() пользователя
// и не наследует общесистемный ACL каталога уровня машины — того же класса риска там нет.
//
// На Windows переопределяется в config_acl_windows.go (init()) на реальное ограничение DACL
// через golang.org/x/sys/windows (уже vendored, чистый Go, без cgo/icacls). Var — чтобы тест
// мог перехватить факт вызова и чтобы файл (не являющийся build-tagged) оставался
// компилируемым на всех платформах — golang.org/x/sys/windows физически не собирается вне
// Windows, поэтому сам вызов API живёт в отдельном файле с `//go:build windows`.
var hardenPortFileACLFn = func(path string) error { return nil }

func WritePortFile(port int) error {
	dir := SharedDataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := portFilePath()
	if err := os.WriteFile(path, []byte(strconv.Itoa(port)), 0o644); err != nil {
		return err
	}
	// S-4: сразу после записи ограничиваем ACL до SYSTEM/Administrators/владельца процесса.
	// Ошибку пробрасываем наверх — вызывающий (internal/web/server.go, Start()) уже трактует
	// WritePortFile целиком как best-effort (логирует и продолжает, не роняет сервер), поэтому
	// сюрприз для существующих вызывающих не возникает, а молчаливо оставлять файл
	// мировочитаемым при сбое хардненинга — потерять весь смысл фикса.
	return hardenPortFileACLFn(path)
}

// ReadPortFile — порт, о котором в последний раз отчитался владелец. ok=false, если
// файла нет (владелец ни разу не стартовал на этой машине с версией, знающей про этот
// механизм, или мы не на Windows). Файл может быть УСТАРЕВШИМ после неаккуратного
// завершения владельца — это подсказка, не гарантия; вызывающий обязан пережить неудачное
// подключение по прочитанному порту так же, как раньше переживал неудачу на cfg.WebUIPort.
func ReadPortFile() (int, bool) {
	data, err := os.ReadFile(portFilePath())
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// BinDir возвращает путь к директории бинарников (sing-box и др.)
//
// Android разбирается отдельно: os.Executable() там указывает на /system/bin/app_process64,
// то есть «рядом с исполняемым файлом» — это /system/bin/bin, каталог чужой и недоступный на
// запись. EnsureDirs() на нём падает, и инициализация моста не доходит до движка.
// Правильный каталог задаёт Kotlin-слой через APF_BIN_DIR: это nativeLibraryDir приложения,
// единственное место, откуда Android 10+ разрешает выполнять файлы (запрет W^X на каталог
// данных). Если переменная не выставлена, откатываемся в каталог данных — там бинарник
// хотя бы можно скачать и проверить, пусть и не запустить.
func BinDir() string {
	if runtimeGOOS == "android" {
		if dir := os.Getenv("APF_BIN_DIR"); dir != "" {
			return dir
		}
		return filepath.Join(DataDir(), "bin")
	}
	exe, err := osExecutableFn()
	if err != nil {
		return "./bin"
	}
	return filepath.Join(filepath.Dir(exe), "bin")
}

// LogPath возвращает путь к лог-файлу
func LogPath() string {
	return filepath.Join(DataDir(), "apf.log")
}

// EnsureDirs создаёт все нужные директории
func EnsureDirs() error {
	dirs := []string{DataDir(), BinDir()}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return nil
}

// SaveConfig сохраняет любую структуру конфигурации в файл.
// Принимает interface{} чтобы избежать циклических импортов с пакетом models.
func SaveConfig(cfg interface{}) error {
	return SaveConfigTo(ConfigPath(), cfg)
}

// SaveConfigTo — то же самое, что SaveConfig, но с явно заданным путём (нужно процессам,
// чей ConfigPath() не совпадает с профилем реального пользователя — см. SetConfigSavePath
// в internal/engine).
func SaveConfigTo(path string, cfg interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// S-5 (лот L1b-SEC2): секретные поля (shadowtls_password, anti_block_api_key) уходят на
	// диск защищёнными DPAPI. Сам файл остаётся обычным JSON — см. secrets_dpapi.go. Ошибка
	// здесь НАМЕРЕННО прерывает сохранение: писать секрет открытым текстом вместо защищённого
	// нельзя (тот же принцип, что у saveNodes, K2-E П11), а старый config.json на диске цел,
	// потому что подмена файла происходит только ниже, через rename.
	if data, err = protectConfigSecrets(data); err != nil {
		return err
	}
	// Атомарно (temp + rename), как nodes_cache.json (P0-9): убийство процесса между усечением
	// и записью оставляло пустой/битый config.json, и следующий старт молча откатывался на
	// DefaultConfig (ТЗ v1.3 F5.2, гигиена конфига). Rename в пределах каталога атомарен и на
	// Windows (MoveFileEx с заменой).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// LoadRaw загружает конфиг как сырые байты
func LoadRaw() ([]byte, error) {
	return os.ReadFile(ConfigPath())
}

// LoadInto читает сохранённый config.json и распаковывает его ПОВЕРХ уже переданной
// структуры (обычно — заполненной models.DefaultConfig()), поэтому поля, отсутствующие
// в файле (например, добавленные в более новой версии), сохраняют значение по умолчанию,
// а не обнуляются json.Unmarshal. Принимает interface{}, а не *models.AppConfig — тот же
// архитектурный принцип, что и у SaveConfig (см. её комментарий): избегаем циклического
// импорта с пакетом models.
//
// found=false, err=nil — файла ещё нет, обычный случай первого запуска, не ошибка.
func LoadInto(dst interface{}) (found bool, err error) {
	return LoadIntoFrom(ConfigPath(), dst)
}

// LoadIntoFrom — то же самое, что LoadInto, но с явно заданным путём к файлу
// (используется, когда пользователь передал свой конфиг явно, например через
// флаг --config у cmd/apf).
func LoadIntoFrom(path string, dst interface{}) (found bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	// S-5 (лот L1b-SEC2): обратная сторона protectConfigSecrets — вернуть секретные поля в
	// открытый вид ТОЛЬКО В ПАМЯТИ. Файл на диске не переписывается. Нечитаемое поле (конфиг
	// принесли с другой машины) не роняет загрузку: оно становится пустым, исходный шифртекст
	// сохраняется, а состояние «секреты недоступны» видно через config.SecretsState().
	data = unprotectConfigSecrets(data)
	if err := json.Unmarshal(data, dst); err != nil {
		return false, err
	}
	return true, nil
}

// FindInteractiveUserConfigPath — обходной путь для Windows-службы (LocalSystem): её
// собственный %APPDATA%/UserHomeDir указывает на профиль SYSTEM, а не на профиль реального
// пользователя, поэтому обычный ConfigPath() (через DataDir()) для службы ВСЕГДА бьёт мимо
// сохранённого файла — найдено живым инцидентом 2026-08-19 (см.
// docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md): служба под SYSTEM исправно вызывала
// LoadInto(), но искала config.json в профиле SYSTEM, где его никогда не было, и молча
// откатывалась на DefaultConfig() — то есть AutoConnect снова оказывался true.
//
// Сканирует C:\Users\*\AppData\Roaming\APF\config.json и берёт САМЫЙ СВЕЖИЙ найденный
// (по mtime). Эвристика годится для целевого сценария этого приложения (однопользовательская
// десктопная машина) и намеренно не пытается решить общий случай терминал-сервера с
// несколькими одновременно залогиненными пользователями — точный способ (WTS-импersonation
// активной консольной сессии) не стоит сложности ради этого сценария.
func FindInteractiveUserConfigPath() (string, bool) {
	if runtimeGOOS != "windows" {
		return "", false
	}
	matches, err := globFn(filepath.Join(winUsersRoot, "*", "AppData", "Roaming", "APF", "config.json"))
	if err != nil || len(matches) == 0 {
		return "", false
	}
	sort.Slice(matches, func(i, j int) bool {
		ti, errI := statFn(matches[i])
		tj, errJ := statFn(matches[j])
		if errI != nil || errJ != nil {
			return false
		}
		return ti.ModTime().After(tj.ModTime())
	})
	return matches[0], true
}
