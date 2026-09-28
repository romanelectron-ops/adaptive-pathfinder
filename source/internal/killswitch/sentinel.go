package killswitch

import (
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Sentinel («крах-маркер») делает Kill Switch crash-safe: пока KS включён, на диске
// лежит файл-маркер. При штатном выключении он удаляется. Если при следующем старте
// маркер ещё на месте — значит прошлая сессия завершилась аварийно (kill/BSOD/питание)
// с активным Kill Switch, и нужно выполнить полный отк ат сети (ResetAll).
//
// Маркер дополняет (не заменяет) безопасный QuickReset при старте: он позволяет
// отличить аварийный выход от штатного и выполнить полный ResetAll (включая DNS),
// а также может использоваться внешним хуком (служба/задача при загрузке).
var (
	sentinelMu   sync.Mutex
	sentinelPath string
)

// SetSentinelDir задаёт каталог для маркера. Вызывается один раз при инициализации
// (обычно из engine с config.DataDir()). Пустая строка отключает механизм.
func SetSentinelDir(dir string) {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	if dir == "" {
		sentinelPath = ""
		return
	}
	sentinelPath = filepath.Join(dir, "killswitch.active")
}

func sentinelFile() string {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	return sentinelPath
}

// markActive создаёт маркер (KS включён). No-op, если каталог не задан.
func markActive() {
	if p := sentinelFile(); p != "" {
		_ = os.WriteFile(p, []byte("1"), 0o600)
	}
}

// clearActive удаляет маркер (KS штатно выключен). No-op, если каталог не задан.
func clearActive() {
	if p := sentinelFile(); p != "" {
		_ = os.Remove(p)
	}
}

// WasActive сообщает, остался ли маркер от прошлой сессии (признак аварийного выхода).
func WasActive() bool {
	p := sentinelFile()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// RecoverIfNeeded вызывается при старте. Если прошлая сессия оставила KS включённым —
// выполняет полный ResetAll и снимает маркер. Возвращает true, если восстановление было.
//
// P0-4 (аудит 2026-09-01): маркер снимается ТОЛЬКО при успешном ResetAll.
//
// Раньше ошибка ResetAll отбрасывалась (`_ = ResetAll()`), а clearActive() вызывался
// БЕЗУСЛОВНО. Сценарий отказа: APF работал с Kill Switch без прав администратора (UAC-путь),
// процесс убит → политика blockoutbound осталась (она персистентна, переживает перезагрузку).
// При следующем запуске без прав все netsh падали, ошибка терялась, маркер удалялся — и
// БОЛЬШЕ НИКОГДА ни одной попытки восстановления не предпринималось, потому что признак
// «прошлая сессия оставила KS включённым» уничтожен. Пользователь оставался без интернета, а
// в лог шло «выполнен полный сброс сети».
//
// Теперь при неудаче маркер сохраняется: следующий запуск (например, уже от администратора,
// или после установки службы apf-svc) повторит попытку.
func RecoverIfNeeded() bool {
	if !WasActive() {
		return false
	}
	if err := ResetAll(); err != nil {
		// Маркер НЕ снимаем — восстановление не состоялось, попытку нужно повторить.
		recoverLogf("Kill Switch: восстановление после аварийного выхода НЕ УДАЛОСЬ (%v). "+
			"Правила брандмауэра могли остаться активными — требуются права администратора. "+
			"Маркер сохранён, попытка повторится при следующем запуске.", err)
		return true
	}
	clearActive()
	return true
}

// recoverLogf — точка вывода диагностики восстановления. var, а не прямой log.Printf, чтобы
// тест мог перехватить сообщение (тот же приём test-seam, что у execCmdFn).
var recoverLogf = func(format string, args ...interface{}) {
	log.Printf(format, args...)
}
