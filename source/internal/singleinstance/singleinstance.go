// Package singleinstance — машинно-глобальное право единолично владеть системными
// ресурсами APF (процесс sing-box, правила фаервола/WFP, системный HTTP-прокси, TUN apf0).
//
// B-0403 · R-3.1 (устраняет C-2). До этого пакета ничто не мешало одновременно работать
// службе `apf-svc` и трею `apf-tray`: оба создавали свой engine.Engine, оба ставили правила
// Kill Switch с ОДИНАКОВЫМИ именами и оба их удаляли. Итог — гонка, при которой Disable
// одного экземпляра снимал защиту у другого, а «остаточных правил» после цикла
// Enable/Disable становилось недетерминированно много (прямое нарушение инварианта TG-1).
//
// Контракт:
//
//	Вход:      имя ресурса (без префикса пространства имён), напр. EngineLockName.
//	Тело:      Windows — именованный мьютекс `Global\<имя>` с фолбэком на `Local\<имя>`;
//	           прочие ОС — flock(LOCK_EX|LOCK_NB) на файле в каталоге данных.
//	Выход:     *Lock (владение получено) либо ErrAlreadyRunning (владеет другой процесс).
//	Fail-safe: механизм недоступен (ошибка API, нет каталога данных) ⇒ возвращается обычная
//	           ошибка, НЕ ErrAlreadyRunning. Вызывающий обязан трактовать её как fail-open:
//	           «мы не смогли выяснить, есть ли второй экземпляр» — не повод не запускаться.
//	           Здесь fail-open корректен (в отличие от Kill Switch, см. R-2.1): singleinstance
//	           защищает от конфликта своих же процессов, а не от утечки трафика.
//	Инвариант: в системе одновременно не более ОДНОГО держателя лока; после Close()
//	           следующий Acquire() с тем же именем обязан пройти; Close() идемпотентен.
//
// Типовое применение в main():
//
//	lock, err := singleinstance.AcquireEngine()
//	switch {
//	case errors.Is(err, singleinstance.ErrAlreadyRunning):
//		// режим наблюдателя: движок НЕ поднимаем
//	case err != nil:
//		log.Printf("singleinstance: %v (продолжаем)", err) // fail-open
//	default:
//		defer lock.Close()
//	}
package singleinstance

import "errors"

// EngineLockName — имя ресурса, которым владеет процесс, поднявший движок APF.
// Один и тот же во всех трёх бинарях (cmd/apf, cmd/apf-tray, cmd/apf-svc).
const EngineLockName = "APF-Engine"

// ErrAlreadyRunning — владение принадлежит другому процессу. Это НЕ сбой: это штатный
// ответ «движок уже поднят», по которому вызывающий переходит в режим наблюдателя.
var ErrAlreadyRunning = errors.New("singleinstance: движком APF уже владеет другой процесс")

// Scope — область действия захваченного взаимоисключения.
type Scope string

const (
	// ScopeGlobal — вся машина, включая границу сессий (служба в сессии 0 против трея
	// в сессии пользователя). Единственная область, дающая полный инвариант.
	ScopeGlobal Scope = "global"
	// ScopeSession — только текущая сессия входа. Фолбэк, когда у процесса нет
	// SeCreateGlobalPrivilege. Слабее: не увидит службу под SYSTEM.
	ScopeSession Scope = "session"
	// ScopeFile — flock на файле в каталоге данных (не-Windows).
	ScopeFile Scope = "file"
)

// AcquireEngine — захват владения движком. Сахар над Acquire(EngineLockName).
func AcquireEngine() (*Lock, error) { return Acquire(EngineLockName) }
