package harvester

// budget.go — бюджеты и деградация (ТЗ v1.4 §5, пункт AI-10).
//
// Смысл файла в одном предложении: проход по источникам обязан заканчиваться, помещаться в
// память телефона и никогда не утаскивать за собой приложение вместе с активным VpnService.
// Поэтому все лимиты собраны в одну структуру с умолчаниями, а не рассыпаны по коду.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Умолчания бюджета. Числа — из таблицы AI-10 и из существующего кода источников.
const (
	// DefaultMaxBodyBytes — тот же лимит, с которым sources.Manager читает тело
	// (io.LimitReader(resp.Body, 10*1024*1024)). Держать их разными бессмысленно: больше
	// десяти мегабайт до харвестера просто не доедет.
	DefaultMaxBodyBytes int64 = 10 * 1024 * 1024
	// DefaultMaxSources — потолок числа источников за проход.
	DefaultMaxSources = 64
	// DefaultMaxCandidates — потолок кандидатов за проход. Пул и так ограничен 10000 узлов
	// на стороне движка; смысл лимита — не дать одной странице-бомбе съесть память телефона.
	DefaultMaxCandidates = 5000
	// DefaultTimeout — «время прохода ≤ 10 мин по умолчанию, настраивается» (AI-10).
	DefaultTimeout = 10 * time.Minute
	// DefaultModelCtxTokens — n_ctx = 4096 (AI-10). Заявленные моделью 32768 не нужны.
	DefaultModelCtxTokens = 4096
	// DefaultModelWindowTokens — окно нарезки тела ≤ 2000 токенов (AI-4).
	DefaultModelWindowTokens = 2000
	// DefaultModelWindowOverlap — перекрытие окон, чтобы ссылка на стыке не потерялась.
	DefaultModelWindowOverlap = 200
	// DefaultConfirmK — бюджет подтверждений за проход, K = 10 (C-18). Харвестер его НЕ
	// применяет (подтверждает движок TUN-пробой) — только переносит рядом с прочими лимитами,
	// чтобы UI показал одно согласованное число на экране подтверждения.
	DefaultConfirmK = 10

	// MinFreeMemForModel — порог отказа модельного пути: 1,8 ГиБ (AI-10, возражение O-20).
	//
	// Откуда число. Замер MemAvailable на целевом телефоне <test-phone> — 2,36 ГиБ, и сделан он
	// БЕЗ активной VpnService, без процесса sing-box и без браузера. Это потолок, а не запас:
	// модель (1,06 ГиБ) плюс KV-кэш при n_ctx=4096 (≈1,2 ГиБ по замеру ГЕЙТА №1) на оставшемся
	// не поместятся, и low-memory killer снимет приложение вместе с туннелем.
	MinFreeMemForModel int64 = 1932735283 // 1,8 * 2^30
)

// ErrLowMemory — свободной памяти меньше порога; модельный путь не стартует.
var ErrLowMemory = errors.New("недостаточно свободной памяти для модели")

// ErrMemUnknown — определить свободную память не удалось. Fail-safe в сторону запрета:
// неизвестность трактуется как «нельзя», потому что цена ошибки — убитое системой приложение
// вместе с активным туннелем, а выгода — всего лишь один необязательный проход модели.
var ErrMemUnknown = errors.New("не удалось определить объём свободной памяти")

// Budget — лимиты одного прохода.
type Budget struct {
	MaxBodyBytes      int64         `json:"max_body_bytes"`
	MaxSources        int           `json:"max_sources"`
	MaxCandidates     int           `json:"max_candidates"`
	Timeout           time.Duration `json:"timeout"`
	MinFreeMemBytes   int64         `json:"min_free_mem_bytes"`
	ModelCtxTokens    int           `json:"model_ctx_tokens"`
	ModelWindowTokens int           `json:"model_window_tokens"`
	ModelWindowOvlp   int           `json:"model_window_overlap"`
	ConfirmK          int           `json:"confirm_k"`
}

// DefaultBudget — бюджет по умолчанию (значения см. в константах выше).
func DefaultBudget() Budget {
	return Budget{
		MaxBodyBytes:      DefaultMaxBodyBytes,
		MaxSources:        DefaultMaxSources,
		MaxCandidates:     DefaultMaxCandidates,
		Timeout:           DefaultTimeout,
		MinFreeMemBytes:   MinFreeMemForModel,
		ModelCtxTokens:    DefaultModelCtxTokens,
		ModelWindowTokens: DefaultModelWindowTokens,
		ModelWindowOvlp:   DefaultModelWindowOverlap,
		ConfirmK:          DefaultConfirmK,
	}
}

// Normalize подставляет умолчания вместо нулей и отрицательных.
//
//	Принимает:  любой Budget, в том числе нулевой.
//	Игнорирует: ничего.
//	Отвергает:  ничего — это не валидатор; невозможные значения заменяются умолчанием.
//	Выход:      бюджет, с которым можно работать.
//
// Нулевой Budget{} — законный вход: вызывающему (UI, движок, тест) не обязано быть известно
// про все семь лимитов, чтобы запустить проход.
func (b Budget) Normalize() Budget {
	d := DefaultBudget()
	if b.MaxBodyBytes <= 0 {
		b.MaxBodyBytes = d.MaxBodyBytes
	}
	if b.MaxSources <= 0 {
		b.MaxSources = d.MaxSources
	}
	if b.MaxCandidates <= 0 {
		b.MaxCandidates = d.MaxCandidates
	}
	if b.Timeout <= 0 {
		b.Timeout = d.Timeout
	}
	if b.MinFreeMemBytes <= 0 {
		b.MinFreeMemBytes = d.MinFreeMemBytes
	}
	if b.ModelCtxTokens <= 0 {
		b.ModelCtxTokens = d.ModelCtxTokens
	}
	if b.ModelWindowTokens <= 0 || b.ModelWindowTokens > b.ModelCtxTokens {
		b.ModelWindowTokens = d.ModelWindowTokens
	}
	// `<= 0`, а не `< 0`: нулевое перекрытие — это тоже «поле не задано», как и у остальных
	// лимитов выше; Budget{}.Normalize() обязан дать ПОЛНЫЙ DefaultBudget()
	// (TestZeroBudgetNormalizesToDefaults). Раньше стояло `< 0` — нуль проходил мимо и оставался
	// нулём при уже подставленном ModelWindowTokens=2000, ломая инвариант «нулевой бюджет → умолчания».
	if b.ModelWindowOvlp <= 0 || b.ModelWindowOvlp >= b.ModelWindowTokens {
		b.ModelWindowOvlp = d.ModelWindowOvlp
	}
	if b.ConfirmK <= 0 {
		b.ConfirmK = d.ConfirmK
	}
	return b
}

// Validate объясняет по-русски, что именно не так с бюджетом (для UI и для тестов).
// Нормализованный бюджет валиден всегда.
func (b Budget) Validate() error {
	switch {
	case b.MaxBodyBytes <= 0:
		return fmt.Errorf("бюджет: размер тела источника должен быть больше нуля")
	case b.MaxSources <= 0:
		return fmt.Errorf("бюджет: число источников за проход должно быть больше нуля")
	case b.MaxCandidates <= 0:
		return fmt.Errorf("бюджет: число кандидатов за проход должно быть больше нуля")
	case b.Timeout <= 0:
		return fmt.Errorf("бюджет: общий таймаут должен быть больше нуля")
	case b.ModelWindowTokens > b.ModelCtxTokens:
		return fmt.Errorf("бюджет: окно (%d токенов) не помещается в контекст (%d)",
			b.ModelWindowTokens, b.ModelCtxTokens)
	}
	return nil
}

// MemProbe — замер свободной памяти. Возвращает (байты, известно ли).
// Точка подмены для тестов: настоящий замер зависит от ОС, а поведение порога проверить надо.
type MemProbe func() (int64, bool)

// SystemMemAvailable — штатный замер: MemAvailable из /proc/meminfo.
//
//	Вход:      —.
//	Тело:      читает /proc/meminfo, ищет строку MemAvailable (килобайты).
//	Выход:     (байты, true) на Android/Linux; (0, false) везде, где файла нет (Windows).
//	Fail-safe: отсутствие файла и любая ошибка разбора — это «неизвестно», а не паника и не
//	           ошибка: модельный путь тогда просто не стартует (см. ErrMemUnknown).
//
// Файл читается через os.ReadFile, поэтому код компилируется под все три поставки и не тянет
// ни одной платформенно-специфичной зависимости — требование кросс-сборки android/arm64.
func SystemMemAvailable() (int64, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb < 0 {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// CheckModelPreconditions — можно ли вообще запускать модельный путь (AI-10).
//
//	Вход:      нормализованный бюджет и замер памяти (nil ⇒ SystemMemAvailable).
//	Тело:      сравнивает MemAvailable с порогом MinFreeMemBytes.
//	Выход:     nil — можно; иначе ошибка с ПОНЯТНЫМ текстом, что закрыть.
//	Отвергает: память ниже порога (ErrLowMemory); память неизвестна (ErrMemUnknown).
//	Fail-safe: отказ касается ТОЛЬКО модели. Детерминированный проход после этого обязан
//	           отработать полностью — «без модели всё работает» (AI-10, деградация).
//
// Вызывается дважды по замыслу: UI зовёт её ДО старта, чтобы показать отказ на экране
// подтверждения (AI-8), и Run зовёт её ещё раз, чтобы отказ нельзя было обойти мимо UI.
func CheckModelPreconditions(b Budget, probe MemProbe) error {
	b = b.Normalize()
	if probe == nil {
		probe = SystemMemAvailable
	}
	avail, ok := probe()
	if !ok {
		return fmt.Errorf("%w — модельный поиск не запускается; детерминированный поиск по источникам работает как обычно",
			ErrMemUnknown)
	}
	if avail < b.MinFreeMemBytes {
		return fmt.Errorf("%w: свободно %s, нужно не меньше %s. Закройте фоновые приложения "+
			"(браузер, мессенджеры) и отключите VPN, затем повторите. Поиск по источникам без "+
			"модели работает и сейчас",
			ErrLowMemory, humanBytes(avail), humanBytes(b.MinFreeMemBytes))
	}
	return nil
}

// humanBytes — «1,8 ГиБ» вместо 1932735283. Русская запятая: текст идёт пользователю.
func humanBytes(n int64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case n >= gib:
		return strings.Replace(strconv.FormatFloat(float64(n)/float64(gib), 'f', 1, 64), ".", ",", 1) + " ГиБ"
	case n >= mib:
		return strconv.FormatInt(n/mib, 10) + " МиБ"
	case n >= kib:
		return strconv.FormatInt(n/kib, 10) + " КиБ"
	default:
		return strconv.FormatInt(n, 10) + " Б"
	}
}
