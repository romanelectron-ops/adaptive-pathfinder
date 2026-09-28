package singbox

import (
	"errors"
	"strings"
)

// Классы отказа старта sing-box (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0 §8, этап A1).
//
// Зачем. Движок раньше считал ЛЮБУЮ ошибку старта виной узла: recordNodeFailure (Score=0,
// на диск) + markNodeFailed (исключение на 10 мин). Живой лог ПК 2026-09-21: ОС создавала
// процесс sing-box.exe по 10-32с, порт не открывался за 10с — и шесть узлов подряд со score
// 0.84-0.85 и живым TCP получили штраф за сбой, который случился ДО того, как sing-box
// прочитал хоть одно поле узла. Узел тут ни при чём, а штраф — навсегда в nodes_cache.json.
//
// Вход:      ошибка Process.Start / Process.Reload.
// Выход:     errors.Is(err, ErrLocalStart) — сбой этой машины, узел не судим;
//
//	errors.Is(err, ErrConfigRejected) — sing-box отверг конфиг, собранный из данных узла.
//
// Инвариант: текст исходной ошибки не меняется (startError.Error отдаёт его как есть) — по
// нему люди читают журнал, а тесты awaitReady сверяют номер порта и причину.
var (
	// ErrLocalStart — ОС не создала процесс, процесс жив, но за ReadyTimeout не открыл свой
	// порт, запуск прерван, либо sing-box умер, не сумев занять локальный ресурс (порт, TUN,
	// файл кэша). Данные удалённого узла на этом этапе не участвуют: исходящее соединение в
	// sing-box ленивое, при старте к узлу никто не ходит.
	ErrLocalStart = errors.New("локальный сбой запуска sing-box")
	// ErrConfigRejected — sing-box завершился сразу после запуска, отвергнув конфигурацию
	// (ошибка разбора/инициализации outbound). Outbound строится из данных узла, поэтому это
	// отказ узла. Нераспознанный ранний выход тоже попадает сюда — см. classifyEarlyExit.
	ErrConfigRejected = errors.New("sing-box отверг конфигурацию")
	// ErrReadyTimeout — уточнение внутри ErrLocalStart: процесс жив, но порт не открылся за
	// ReadyTimeout. Единственный локальный подкласс, где процесс уже исполнял конфиг узла, —
	// поэтому движок по нему делает мягкую ротацию (консилиум приёмки этапа A, правка M2).
	ErrReadyTimeout = errors.New("sing-box не открыл локальный порт за срок")
)

// startError — ошибка старта с классом. Unwrap отдаёт класс (для errors.Is по
// ErrLocalStart/ErrConfigRejected), необязательное уточнение (ErrReadyTimeout) и исходную
// причину (для errors.Is(err, context.Canceled) — движок различает «нас отменили» и «сломалась
// машина»).
type startError struct {
	class  error
	detail error
	err    error
}

func (e *startError) Error() string { return e.err.Error() }
func (e *startError) Unwrap() []error {
	if e.detail != nil {
		return []error{e.class, e.detail, e.err}
	}
	return []error{e.class, e.err}
}

func localStartError(err error) error    { return &startError{class: ErrLocalStart, err: err} }
func configRejectedError(err error) error { return &startError{class: ErrConfigRejected, err: err} }
func readyTimeoutError(err error) error {
	return &startError{class: ErrLocalStart, detail: ErrReadyTimeout, err: err}
}

// localExitMarkers — признаки того, что sing-box умер на ЛОКАЛЬНОМ ресурсе. Взяты из того, как
// sing-box сам оборачивает ошибки старта (vendor/.../adapter/inbound/manager.go: "start
// inbound/<type>[<tag>]", protocol/tun/inbound.go: "starting tun stack"/"starting TUN
// interface") и из текстов ОС про занятый порт/доступ. Сравнение без учёта регистра.
var localExitMarkers = []string{
	"start inbound/",
	"starting tun",
	"configure tun",
	"wintun",
	"bind:",
	"address already in use",
	"only one usage of each socket address", // WSAEADDRINUSE на Windows
	"access is denied",
	"permission denied",
	"open cache file", // bbolt cache.db занят другим экземпляром
}

// classifyEarlyExit — класс отказа по выводу sing-box, умершего сразу после запуска.
//
// Вход:      последние строки вывода процесса (stdout+stderr) этого запуска.
// Тело:      судит по строке FATAL (её печатает sing-box при отказе старта), если её нет — по
//
//	последней строке. Упоминание outbound → конфиг узла отвергнут; локальный маркер →
//	локальный сбой; иначе — отказ конфигурации.
//
// Почему «не распознано» = отказ узла, а не локальный сбой. Локальный сбой останавливает
// перебор кандидатов (этап A2) — если бы нераспознанная ошибка плохого узла читалась как
// локальная, повтор по ре-армингу снова и снова брал бы тот же верхний узел, и связь не
// восстановилась бы никогда (класс дефекта «мёртвый узел держал без интернета»). Ошибочный
// штраф одного узла обратим — узел вернётся после следующей удачной проверки; зависание нет.
func classifyEarlyExit(lines []string) error {
	line := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "FATAL") {
			line = lines[i]
			break
		}
	}
	if line == "" && len(lines) > 0 {
		line = lines[len(lines)-1]
	}
	low := strings.ToLower(line)
	if strings.Contains(low, "outbound") {
		return ErrConfigRejected
	}
	for _, m := range localExitMarkers {
		if strings.Contains(low, m) {
			return ErrLocalStart
		}
	}
	return ErrConfigRejected
}
