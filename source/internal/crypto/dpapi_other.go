//go:build !windows

package crypto

// Заглушка для Linux и Android. S-5 прямо оставляет их без изменений поведения: на Android
// секреты роли «Выход» сохраняет Kotlin (EncryptedSharedPreferences, см. комментарий
// serverIdentityPath в internal/engine/server_role.go — Android не хранит identity через Go),
// на Linux аналога DPAPI без внешних зависимостей нет.
//
// Возвращаем ЧЕСТНУЮ ошибку, а не «тихо отдаём открытый текст под видом защищённого»: решение
// «писать открытым текстом» принимает вызывающая сторона явно (internal/config), и только там
// оно видно в одном месте.

const dpapiSupported = false

func dpapiProtect(plain []byte) ([]byte, error) { return nil, ErrDPAPIUnavailable }

func dpapiUnprotect(blob []byte) ([]byte, error) { return nil, ErrDPAPIUnavailable }
