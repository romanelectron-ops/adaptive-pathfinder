package crypto

// S-5 (TZ_APF_v1.4_FINAL.md), лот L1b-SEC2 — прозрачная защита секретов НА ДИСКЕ, работающая
// БЕЗ мастер-пароля.
//
// Зачем отдельно от Store: Store (AES-256-GCM + PBKDF2 600k) — опция пользователя, он молчит
// без мастер-пароля (`Encrypt` возвращает "master password is empty"), поэтому по умолчанию
// не защищает НИЧЕГО. При этом на диске лежат настоящие секреты, которые пользователь никогда
// не вводил руками и защитить паролем не может в принципе — приватный ключ REALITY роли
// «Выход» (server_identity.json) и relay-token (server_relay_credentials.json) генерируются
// самой программой, в том числе в headless-службе под LocalSystem, где спросить пароль не у
// кого.
//
// Windows DPAPI (CryptProtectData) закрывает ровно этот класс: ключ шифрования держит ОС,
// вводить нечего, работает в службе. Формат контейнера — свой маркер APFDP1: + base64, чтобы
// (а) отличать защищённый файл от старого открытого (миграция) и (б) не путать с APFENC1:
// формата Store: это РАЗНЫЕ слои, они не взаимозаменяемы.
//
// Что DPAPI НЕ даёт (записано честно, чтобы не появилось ложных утверждений в UI — Ц3):
// machine-scope blob расшифровывается любым процессом НА ЭТОЙ ЖЕ машине. От соседа по машине
// защищают права файла (0600/ACL), а DPAPI закрывает «унесли файл или диск на другую машину».

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// DPAPIMarker — префикс защищённого контейнера. Оставлен экспортированным: тем, кто пишет
// секреты в JSON-поле (internal/config), нужно уметь отличать «уже защищено» от «открытый
// текст» не декодируя.
const DPAPIMarker = "APFDP1:"

var dpapiMagic = []byte(DPAPIMarker)

var (
	// ErrDPAPIUnavailable — платформа без DPAPI (Linux, Android). НЕ ошибка выполнения:
	// вызывающая сторона обязана трактовать это как «защиты на этой платформе нет» и
	// сохранить прежнее поведение, а не падать (S-5: «Linux — оставить как есть с честной
	// подписью в UI»).
	ErrDPAPIUnavailable = errors.New("DPAPI недоступен на этой платформе")

	// ErrNotProtected — данные не начинаются с маркера, то есть это старый открытый файл.
	// Тоже не ошибка выполнения — сигнал «нужна миграция».
	ErrNotProtected = errors.New("данные не защищены DPAPI")

	// ErrEmptySecret — защищать нечего. CryptProtectData на пустом входе отвечает невнятным
	// «The parameter is incorrect»; отдаём вместо этого понятную ошибку. Реальные вызывающие
	// сюда не приходят: identity и креды — непустой JSON, а пустые поля config.json
	// пропускаются до вызова (см. internal/config/secrets_dpapi.go).
	ErrEmptySecret = errors.New("нечего защищать: пустой секрет")

	// ErrSecretUnreadable — контейнер защищён, но расшифровать не удалось: файл перенесли с
	// другой машины, профиль пересоздан, blob повреждён. Это та самая ветка «не смог
	// расшифровать» из В-2: нельзя ни падать молча, ни затирать файл.
	ErrSecretUnreadable = errors.New("защищённый секрет не читается на этой машине")
)

// dpapiEntropy — дополнительная энтропия DPAPI. НЕ секрет (константа в бинарнике) и не
// выдаётся за него: она лишь привязывает контейнер к APF, чтобы чужой процесс не расшифровал
// наш blob «мимоходом», вызвав CryptUnprotectData без параметров.
var dpapiEntropy = []byte("APF/DPAPI/secrets/v1")

// Швы для тестов недостижимых веток (тот же приём, что randFillFn/newCipherFn в store.go).
var (
	dpapiProtectFn   = dpapiProtect
	dpapiUnprotectFn = dpapiUnprotect
)

// DPAPIAvailable — есть ли на этой платформе прозрачная защита секретов.
func DPAPIAvailable() bool { return dpapiSupported }

// IsDPAPIProtected — начинается ли содержимое с маркера защищённого контейнера.
func IsDPAPIProtected(raw []byte) bool { return bytes.HasPrefix(raw, dpapiMagic) }

// ProtectBytes упаковывает plain в контейнер APFDP1:<base64(DPAPI blob)>.
// На платформе без DPAPI возвращает ErrDPAPIUnavailable и НИЧЕГО не возвращает в data —
// вызывающая сторона сама решает, писать ли открытый текст (см. internal/config).
func ProtectBytes(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, ErrEmptySecret
	}
	blob, err := dpapiProtectFn(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(dpapiMagic)+base64.StdEncoding.EncodedLen(len(blob)))
	out = append(out, dpapiMagic...)
	out = append(out, []byte(base64.StdEncoding.EncodeToString(blob))...)
	return out, nil
}

// UnprotectBytes разбирает контейнер, созданный ProtectBytes.
//
// Три различимых исхода (errors.Is):
//   - ErrNotProtected — маркера нет, это открытый текст (миграция);
//   - ErrSecretUnreadable — маркер есть, но содержимое не восстанавливается;
//   - ErrDPAPIUnavailable (в паре с ErrSecretUnreadable) — контейнер принесли на платформу
//     без DPAPI.
func UnprotectBytes(raw []byte) ([]byte, error) {
	if !IsDPAPIProtected(raw) {
		return nil, ErrNotProtected
	}
	blob, err := base64.StdEncoding.DecodeString(string(raw[len(dpapiMagic):]))
	if err != nil {
		return nil, fmt.Errorf("%w: повреждён base64: %v", ErrSecretUnreadable, err)
	}
	plain, err := dpapiUnprotectFn(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecretUnreadable, err)
	}
	return plain, nil
}
