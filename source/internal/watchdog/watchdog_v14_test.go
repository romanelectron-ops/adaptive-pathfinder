package watchdog

// watchdog_v14_test.go — S-10 (ТЗ v1.4, лот L1-WD; открытый вопрос №2 K3-S/P3,
// APF_Audit/BLACKBOX_AUDIT_2026-09-07/K3-S/result.md).
//
// Дефект. isPIDAlive (watchdog.go), ветка default (не-Windows): ЛЮБАЯ ошибка killCheckFn —
// не только «процесса нет» (kill -0 код выхода 1, ESRCH), но и «проверку выполнить не удалось»
// (sh не найден, иной код выхода) — схлопывалась в (false, nil), то есть в «процесс мёртв».
// Из-за этого защита P3 (K3-S: ErrCheckUnavailable + MaxCheckErrors, введена для Windows-ветки
// tasklist) на Linux/Android была холостой: Run() решал, что APF умер, ПОСЛЕ ПЕРВОЙ ЖЕ неудачной
// попытки выполнить kill -0, и звал killswitch.ResetAll() на ЖИВОМ APF.
//
// Фикс. Ветка default различает:
//   - kill -0 код выхода 1 (ESRCH)              -> (false, nil)  — процесс подтверждённо мёртв;
//   - exec.ErrNotFound (sh не найден) / код ≥ 2 -> (false, err)  — проверку выполнить не удалось,
//     то есть Run() обязан трактовать это как исход (c) из P3, а не как (b).
//
// Контракт шва killCheckFn (var killCheckFn func(pid int) error) НЕ МЕНЯЕТСЯ — это тот же шов,
// которым пользуются watchdog_extra2_test.go/watchdog_extra3_test.go. Их инъекции — опаковые
// errors.New("...") БЕЗ структуры кода выхода — по-прежнему трактуются как «мёртв, ошибки нет»:
// это совместимая РАСШИРЯЮЩАЯ замена (новая классификация для *exec.ExitError/exec.ErrNotFound
// поверх старого поведения по умолчанию для всего остального), а не разрыв контракта. Поэтому
// все 27 существующих тестов пакета остаются зелёными без единой правки.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ─── Хелпер: настоящий *exec.ExitError с заданным кодом выхода ───────────────────────────────
//
// os.ProcessState нельзя сконструировать вручную — используем стандартный приём стандартной
// библиотеки Go (см. os/exec/exec_test.go): перезапускаем сам тестовый бинарник со спец-флагом,
// подпроцесс завершается через os.Exit(code) в TestHelperProcess_Exit, а вызывающий получает
// настоящий *exec.ExitError. Портируемо (Windows/Linux), не трогает реальные процессы машины —
// это тот же тестовый бинарник, а не сторонний исполняемый файл.

// TestHelperProcess_Exit — не самостоятельный тест: код выполняется только при
// GO_WANT_HELPER_PROCESS=1, иначе мгновенно возвращается. Обычный запуск пакета его не видит
// как содержательный тест.
func TestHelperProcess_Exit(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	code, _ := strconv.Atoi(os.Getenv("GO_HELPER_EXIT_CODE"))
	os.Exit(code)
}

// realExitError запускает helper-подпроцесс, которому родитель прямо указывает завершиться с
// заданным кодом, и возвращает получившийся *exec.ExitError.
func realExitError(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Exit")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"GO_HELPER_EXIT_CODE="+strconv.Itoa(code))
	err := cmd.Run()
	if err == nil {
		t.Fatalf("хелпер-подпроцесс должен был завершиться с кодом %d, а завершился успешно", code)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("ожидался *exec.ExitError, получено %T: %v", err, err)
	}
	if exitErr.ExitCode() != code {
		t.Fatalf("хелпер вернул код %d, ожидался %d", exitErr.ExitCode(), code)
	}
	return exitErr
}

// notFoundError — реальная ошибка exec.LookPath на несуществующий исполняемый файл, оборачивает
// exec.ErrNotFound (проверяется отдельно, чтобы тест не зависел молча от факта обёртки).
func notFoundError(t *testing.T) error {
	t.Helper()
	err := exec.Command("apf-s10-does-not-exist-anywhere-3f9c").Run()
	if err == nil {
		t.Fatal("ожидалась ошибка запуска несуществующего исполняемого файла")
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("ожидалась ошибка, оборачивающая exec.ErrNotFound, получено %T: %v", err, err)
	}
	return err
}

// setDefaultBranch переключает isPIDAlive на не-Windows ветку и восстанавливает killCheckFn/
// watchdogGOOS по завершении теста — тот же приём, что в watchdog_extra2_test.go/extra3_test.go.
func setDefaultBranch(t *testing.T, fn func(pid int) error) {
	t.Helper()
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	t.Cleanup(func() { watchdogGOOS = origGOOS; killCheckFn = origKill })
	watchdogGOOS = "linux"
	killCheckFn = fn
}

// ═══════════════════════════ ЯЩИК: isPIDAlive (ветка default) ═══════════════════════════════

// Позитив/граница: kill -0 код выхода 1 (ESRCH) — процесс подтверждённо отсутствует, ошибки при
// этом НЕТ (в этом старое и новое поведение совпадают — регрессия исключена).
func TestIsPIDAlive_Default_ExitCode1_MeansConfirmedDead(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return realExitError(t, 1) })

	alive, err := isPIDAlive(99999)
	if err != nil {
		t.Fatalf("код выхода 1 (ESRCH) обязан давать err=nil (процесс подтверждённо мёртв, "+
			"а не «проверить не удалось»), получено: %v", err)
	}
	if alive {
		t.Error("код выхода 1 обязан давать alive=false")
	}
}

// НЕГАТИВ (доказательство дефекта S-10, до фикса ПАДАЕТ): exec.ErrNotFound (sh недоступен) —
// это «проверить не удалось», а не «процесс мёртв». isPIDAlive обязана вернуть err!=nil, чтобы
// Run() отличил это от подтверждённой смерти (см. TestRun_NonWindows_CheckFailureNotDeath ниже).
func TestIsPIDAlive_Default_ErrNotFound_MeansCheckUnavailable(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return notFoundError(t) })

	alive, err := isPIDAlive(99999)
	if alive {
		t.Error("недоступность sh не может означать alive=true")
	}
	if err == nil {
		t.Fatal("S-10: exec.ErrNotFound (sh недоступен) схлопнулось в (false, nil) — " +
			"«проверить не удалось» неотличимо от «процесс мёртв»; вызывающий (Run) " +
			"решит, что APF умер, и снимет Kill Switch с живого процесса")
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("ошибка обязана трассироваться до exec.ErrNotFound (errors.Is), получено: %v", err)
	}
}

// НЕГАТИВ (доказательство дефекта S-10, до фикса ПАДАЕТ): код выхода 127 («command not found»
// внутри sh) — тоже «проверить не удалось», не ESRCH. Дословно из плана лота L1-WD.
func TestIsPIDAlive_Default_ExitCode127_MeansCheckUnavailable(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return realExitError(t, 127) })

	alive, err := isPIDAlive(99999)
	if alive {
		t.Error("код выхода 127 не может означать alive=true")
	}
	if err == nil {
		t.Fatal("S-10: код выхода 127 схлопнулся в (false, nil) вместо (false, err) — " +
			"«проверить не удалось» неотличимо от подтверждённой смерти процесса")
	}
}

// Граница: код выхода 2 (и любой другой, кроме 1) — тоже «проверить не удалось», не только 127.
func TestIsPIDAlive_Default_ExitCode2_MeansCheckUnavailable(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return realExitError(t, 2) })

	alive, err := isPIDAlive(99999)
	if alive {
		t.Error("код выхода 2 не может означать alive=true")
	}
	if err == nil {
		t.Fatal("код выхода 2 (≠1) обязан давать err!=nil — это не ESRCH")
	}
}

// СТОЙКОСТЬ / обратная совместимость: опаковая ошибка-заглушка БЕЗ структуры кода выхода
// (тот же вид инъекции, что в watchdog_extra2_test.go/watchdog_extra3_test.go) обязана
// по-прежнему трактоваться как «мёртв, ошибки нет» — это старый контракт шва killCheckFn,
// фикс S-10 его расширяет, а не ломает. Дублирует существующие тесты намеренно: страховка
// от регрессии контракта прямо в новом файле, рядом с тестами, доказывающими сам дефект.
func TestIsPIDAlive_Default_OpaqueError_StaysBackwardCompatible(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return errors.New("no such process") })

	alive, err := isPIDAlive(99999)
	if err != nil {
		t.Fatalf("опаковая ошибка-заглушка (без *exec.ExitError/exec.ErrNotFound) обязана "+
			"давать err=nil — контракт шва killCheckFn для существующих тестов не должен "+
			"сломаться; получено: %v", err)
	}
	if alive {
		t.Error("опаковая ошибка-заглушка обязана давать alive=false")
	}
}

// FAIL-SAFE: kill -0 успешен (err=nil) — процесс жив, поведение не изменилось.
func TestIsPIDAlive_Default_Success_MeansAlive(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return nil })

	alive, err := isPIDAlive(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !alive {
		t.Error("kill -0 без ошибки обязан давать alive=true")
	}
}

// ═══════════════════ ВЕТКА: Run() — сквозной эффект фикса (не только isPIDAlive) ═════════════

// НЕГАТИВ/fail-safe (доказательство дефекта S-10 на уровне всего Run(), до фикса ПАДАЕТ):
// на не-Windows платформе постоянная невозможность выполнить проверку (sh недоступен) не имеет
// права выглядеть как подтверждённая смерть процесса. Это ровно тот сценарий, из-за которого
// защита P3 (K3-S) была холостой на Linux/Android — Run() возвращал nil на ПЕРВОЙ ЖЕ ошибке
// killCheckFn, cmd/apf/main.go звал killswitch.ResetAll() на живом APF.
func TestRun_NonWindows_CheckFailureNotTreatedAsDeath(t *testing.T) {
	quietLog(t)
	var calls int64
	setDefaultBranch(t, func(pid int) error {
		atomic.AddInt64(&calls, 1)
		return notFoundError(t)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{PID: 4242, PollEvery: 10 * time.Millisecond})

	if err == nil {
		t.Fatal("S-10: Run вернул nil на не-Windows при недоступном sh — «проверить не удалось» " +
			"истолковано как «процесс мёртв»: cmd/apf/main.go снимет Kill Switch с ЖИВОГО APF")
	}
	if n := atomic.LoadInt64(&calls); n < 2 {
		t.Errorf("проверка вызвана %d раз — опрос прекратился на первой же ошибке", n)
	}
}

// Тот же дефект должен закрываться штатным контрактом P3 (K3-S): после MaxCheckErrors подряд
// неудач на не-Windows Run() обязан вернуть ИМЕННО ErrCheckUnavailable, а не какую-то иную
// ошибку и не context-ошибку. Это и есть доказательство, что "ErrCheckUnavailable достижим на
// не-Windows" (акцептанс-критерий лота L1-WD) — до фикса недостижим в принципе (см. тест выше).
func TestRun_NonWindows_GivesUpWithErrCheckUnavailable(t *testing.T) {
	quietLog(t)
	var calls int64
	setDefaultBranch(t, func(pid int) error {
		atomic.AddInt64(&calls, 1)
		return notFoundError(t)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{PID: 4242, PollEvery: time.Millisecond, MaxCheckErrors: 3})

	if !errors.Is(err, ErrCheckUnavailable) {
		t.Fatalf("после 3 неудачных проверок подряд на не-Windows ожидалась ErrCheckUnavailable, "+
			"получено: %v", err)
	}
	if n := atomic.LoadInt64(&calls); n != 3 {
		t.Errorf("проверка вызвана %d раз, ожидалось ровно MaxCheckErrors=3", n)
	}
}

// Регрессия: подтверждённая смерть процесса (код выхода 1) на не-Windows по-прежнему даёт nil —
// P3/K3-S для Windows-ветки это уже проверяет (TestRun_ConfirmedDeathStillReturnsNil), здесь —
// то же самое для default-ветки, которую и меняет S-10.
func TestRun_NonWindows_ConfirmedDeathStillReturnsNil(t *testing.T) {
	setDefaultBranch(t, func(pid int) error { return realExitError(t, 1) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Run(ctx, Config{PID: 4242, PollEvery: 5 * time.Millisecond}); err != nil {
		t.Fatalf("код выхода 1 (ESRCH) обязан давать nil (подтверждённая смерть), получено: %v", err)
	}
}
