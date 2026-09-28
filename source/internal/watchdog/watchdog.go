package watchdog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// defaultMaxCheckErrors — сколько ПОДРЯД неудачных ПРОВЕРОК (см. ErrCheckUnavailable) Run
// терпит, прежде чем сдаться. При дефолтном PollEvery=750мс это ~6 секунд непрерывной
// невозможности выполнить проверку. Сбои `tasklist` носят импульсный характер (нехватка
// ресурсов на создание процесса, переходное состояние сессии при блокировке/разблокировке,
// временный отказ RPC/WMI) и укладываются в один-два опроса; шесть секунд подряд — это уже не
// импульс, а сломанный механизм проверки, о котором надо сообщить честно, а не молча выдать
// его за смерть процесса. Число намеренно НЕ маленькое: цена ложного «мёртв» (снятая защита с
// живого APF) несопоставимо выше цены задержки в несколько секунд перед честным отказом.
const defaultMaxCheckErrors = 8

// ErrCheckUnavailable — проверить живость PID не удалось MaxCheckErrors раз подряд. ОТДЕЛЬНАЯ,
// различимая причина (`errors.Is`): это НЕ «процесс завершился» (для него Run возвращает nil) и
// НЕ отмена контекста. Вызывающий (cmd/apf/main.go) обязан отличать одно от другого: `nil` для
// него — команда звать killswitch.ResetAll(), а «я не смог проверить» такой командой быть не
// может, иначе один сбой tasklist снимает Kill Switch с ЖИВОГО APF (P3, аудит 2026-09-07).
var ErrCheckUnavailable = errors.New("watchdog: не удалось проверить живость PID")

// Config определяет поведение watchdog.
type Config struct {
	PID         int
	PollEvery   time.Duration
	GracePeriod time.Duration
	// MaxCheckErrors — сколько ПОДРЯД неудачных проверок допустимо, прежде чем Run вернёт
	// ErrCheckUnavailable. <=0 ⇒ defaultMaxCheckErrors. Счётчик обнуляется ЛЮБОЙ удавшейся
	// проверкой (и «жив», и «мёртв»): чередование отказов с успехами — признак нестабильной
	// среды, а не сломанного механизма.
	MaxCheckErrors int
	// OnLog — необязательный приёмник диагностики (тот же приём, что RelayServerConfig.OnLog).
	// nil ⇒ стандартный логгер: подпроцесс `apf watchdog` уже настроил ему префикс.
	OnLog func(string)
}

func (cfg Config) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if cfg.OnLog != nil {
		cfg.OnLog(msg)
		return
	}
	log.Print(msg)
}

// Run опрашивает целевой PID и возвращается ровно в трёх случаях:
//
//	nil                  — проверка УДАЛАСЬ и показала, что процесс завершился (штатный сигнал
//	                       вызывающему: пора восстанавливать сеть);
//	ErrCheckUnavailable  — проверку не удалось выполнить MaxCheckErrors раз ПОДРЯД: про процесс
//	                       ничего не известно, и выдавать это за смерть нельзя;
//	ctx.Err()            — работу свернули снаружи.
//
// Различие первых двух — суть P3: раньше ошибка проверки отбрасывалась (`alive, _ :=`) и
// «не смог проверить» становилось «мёртв».
func Run(ctx context.Context, cfg Config) error {
	if cfg.PID <= 0 {
		return fmt.Errorf("invalid pid: %d", cfg.PID)
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 750 * time.Millisecond
	}
	if cfg.GracePeriod < 0 {
		cfg.GracePeriod = 0
	}
	if cfg.MaxCheckErrors <= 0 {
		cfg.MaxCheckErrors = defaultMaxCheckErrors
	}

	// Optional grace period to allow the main process to fully start.
	if cfg.GracePeriod > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.GracePeriod):
		}
	}

	t := time.NewTicker(cfg.PollEvery)
	defer t.Stop()

	consecutiveErrs := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			alive, err := isPIDAlive(cfg.PID)
			if err != nil {
				// (c) Проверка НЕ выполнена. Про процесс не известно НИЧЕГО — ни что он жив,
				// ни что он мёртв. Молчать нельзя (это диагностика реальной поломки среды),
				// но и завершаться на первой же неудаче нельзя тем более.
				consecutiveErrs++
				cfg.logf("watchdog: проверка PID %d не удалась (%d/%d подряд): %v",
					cfg.PID, consecutiveErrs, cfg.MaxCheckErrors, err)
				if consecutiveErrs >= cfg.MaxCheckErrors {
					return fmt.Errorf("%w: PID %d, %d неудачных проверок подряд, последняя: %v",
						ErrCheckUnavailable, cfg.PID, consecutiveErrs, err)
				}
				continue
			}
			// (a)/(b) Проверка удалась — серия неудач прервана, счётчик обнуляется.
			if consecutiveErrs > 0 {
				cfg.logf("watchdog: проверка PID %d снова выполняется (было %d неудач подряд)",
					cfg.PID, consecutiveErrs)
				consecutiveErrs = 0
			}
			if !alive {
				return nil
			}
		}
	}
}

// runTasklist is an injection hook for testing the Windows tasklist error branch.
// If non-nil, it replaces exec.Command("tasklist",...).CombinedOutput().
var runTasklist func(pid int) ([]byte, error)

// watchdogGOOS allows tests to simulate a different OS in isPIDAlive.
var watchdogGOOS = runtime.GOOS

// killCheckFn is an injection hook for the default (non-Windows) PID check.
var killCheckFn = func(pid int) error {
	return exec.Command("sh", "-c", "kill -0 "+strconv.Itoa(pid)+" 2>/dev/null").Run()
}

func isPIDAlive(pid int) (bool, error) {
	switch watchdogGOOS {
	case "windows":
		// tasklist returns header + rows. If PID not found -> no matching tasks.
		var out []byte
		var err error
		if runTasklist != nil {
			out, err = runTasklist(pid)
		} else {
			out, err = exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid)).CombinedOutput()
		}
		if err != nil {
			return false, err
		}
		s := strings.ToLower(string(out))
		if strings.Contains(s, "no tasks are running") || strings.Contains(s, "задачи не запущены") {
			return false, nil
		}
		// If PID appears in output, assume alive.
		return strings.Contains(s, " "+strconv.Itoa(pid)+" "), nil
	default:
		// kill -0 is a standard way to check process existence without sending a signal.
		err := killCheckFn(pid)
		if err == nil {
			return true, nil
		}
		return classifyKillCheckErr(err)
	}
}

// classifyKillCheckErr различает «kill -0 подтвердил, что процесса нет» от «проверку выполнить
// не удалось» (S-10, ТЗ v1.4, лот L1-WD; открытый вопрос №2 K3-S/P3). До этой правки ЛЮБАЯ
// ошибка killCheckFn на не-Windows схлопывалась в (false, nil) — «мёртв» — из-за чего защита P3
// (ErrCheckUnavailable/MaxCheckErrors, введена K3-S для Windows-ветки tasklist) на Linux/Android
// была холостой: одна неудачная попытка запустить kill -0 (sh недоступен, отказ прав, иной сбой
// среды) заставляла Run() решить, что APF умер, и вызывающий (cmd/apf/main.go) снимал Kill
// Switch с ЖИВОГО процесса.
//
//	*exec.ExitError с кодом 1 (ESRCH, «no such process» по конвенции kill(1)) -> (false, nil):
//	    это и есть штатное «процесса нет», поведение не меняется;
//	exec.ErrNotFound (sh не найден) или ЛЮБОЙ иной код выхода (>=2, включая 127 —
//	    «command not found» внутри sh) -> (false, err): проверку выполнить не удалось, вызывающий
//	    обязан трактовать это как исход (c) из P3 (K3-S), а не как подтверждённую смерть.
//	любая иная (опаковая) ошибка без такой структуры -> (false, nil): это старый контракт шва
//	    killCheckFn, которым пользуются watchdog_extra2_test.go/watchdog_extra3_test.go — их
//	    инъекции (errors.New(...) без кода выхода) обязаны остаться зелёными без единой правки.
//	    Расширяющая, а не ломающая замена: новая классификация добавлена ТОЛЬКО для структур,
//	    которых раньше не различали, старое поведение — сохранённый фолбэк по умолчанию.
func classifyKillCheckErr(err error) (bool, error) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("kill -0: неожиданный код выхода %d: %w", exitErr.ExitCode(), err)
	}
	if errors.Is(err, exec.ErrNotFound) {
		return false, fmt.Errorf("kill -0: %w", err)
	}
	return false, nil
}
