package config

// S-5 (TZ_APF_v1.4_FINAL.md), лот L1b-SEC2 — файловый слой прозрачной защиты секретов.
//
// Две разные задачи, намеренно решённые по-разному:
//
//  1. ФАЙЛ ЦЕЛИКОМ (server_identity.json, server_relay_credentials.json) — в файле нет ничего,
//     кроме секрета, шифруется всё содержимое. Маркер APFDP1: в начале файла позволяет отличить
//     защищённый файл от старого открытого и мигрировать без потери данных.
//
//  2. ОТДЕЛЬНЫЕ ПОЛЯ (config.json: shadowtls_password, anti_block_api_key) — config.json
//     обязан остаться читаемым JSON: его читает служба, его правит руками пользователь,
//     на него смотрят инсталлятор и диагностика. Шифруется ЗНАЧЕНИЕ поля, файл остаётся
//     обычным JSON. Замена делается хирургически по месту (см. findJSONStringFields), а не
//     через map[string]any + повторный Marshal: пересборка через map переупорядочила бы все
//     ключи по алфавиту и испортила бы числа — файл, который человек открывает блокнотом,
//     менялся бы целиком на каждое сохранение.
//
// Правило отказа (единое, совпадает с K2-E П11 для saveNodes): если DPAPI на платформе ЕСТЬ,
// но защита сорвалась — наверх идёт ошибка и открытый текст НЕ пишется. Если DPAPI на
// платформе нет вовсе (Linux, Android) — поведение не меняется, пишется как раньше.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/apf/adaptive-pathfinder/internal/crypto"
)

// Швы для тестов недостижимых веток (тот же приём, что randFillFn в internal/crypto/store.go):
// подменив unprotectSecretFn, тест воспроизводит «не смог расшифровать» на любой платформе,
// не завися от того, есть ли на ней DPAPI.
var (
	protectSecretFn   = crypto.ProtectBytes
	unprotectSecretFn = crypto.UnprotectBytes
)

// configSecretKeys — БЕЛЫЙ список ключей config.json, значения которых считаются секретом
// (models.AppConfig: ShadowTLSPassword, AntiBlockAPIKey; тот же ключ shadowtls_password
// встречается и во вложенных узлах — обрабатываются все вхождения).
var configSecretKeys = map[string]bool{
	"shadowtls_password": true,
	"anti_block_api_key": true,
}

// ─── Состояние «секреты недоступны» ──────────────────────────────────────────────────────
//
// Ветка В-2 «не смог расшифровать» обязана быть ЗАМЕТНОЙ: молча пересоздать ключ и молча
// обнулить пароль — ровно тот класс дефекта, который проект уже ловил («Connected врёт»).
// Здесь хранится флаг и человеческая причина; движок обязан показать её в статусе
// (см. Engine.SecretsWarning в internal/engine/server_role.go).

var secretsState = struct {
	mu          sync.RWMutex
	unavailable bool
	reason      string
}{}

// SecretsState — «часть секретов на этой машине не читается» + причина для показа человеку.
func SecretsState() (unavailable bool, reason string) {
	secretsState.mu.RLock()
	defer secretsState.mu.RUnlock()
	return secretsState.unavailable, secretsState.reason
}

// MarkSecretsUnavailable выставляет флаг. Первая причина сохраняется — она ближе всего к
// корню, последующие уже её следствия.
func MarkSecretsUnavailable(reason string) {
	secretsState.mu.Lock()
	defer secretsState.mu.Unlock()
	if !secretsState.unavailable {
		secretsState.unavailable = true
		secretsState.reason = reason
	}
}

// ClearSecretsState сбрасывает флаг (после успешного пересоздания секрета и в тестах).
func ClearSecretsState() {
	secretsState.mu.Lock()
	defer secretsState.mu.Unlock()
	secretsState.unavailable = false
	secretsState.reason = ""
}

// ─── Загашник нечитаемых значений config.json ────────────────────────────────────────────
//
// Прочитали config.json, поле shadowtls_password защищено, но не расшифровывается (файл
// принесли с другой машины). Отдать наверх шифртекст нельзя — движок подставит его как
// пароль. Отдаём пустую строку, но САМ шифртекст запоминаем: при следующем сохранении
// конфига на его место вернётся он же, а не пустая строка. Иначе одно сохранение настроек
// уничтожило бы пароль, который на РОДНОЙ машине ещё прекрасно читается.
var unreadableSecrets = struct {
	mu sync.Mutex
	m  map[string]string
}{m: map[string]string{}}

func stashUnreadable(key string, occurrence int, ciphertext string) {
	unreadableSecrets.mu.Lock()
	defer unreadableSecrets.mu.Unlock()
	unreadableSecrets.m[fmt.Sprintf("%s#%d", key, occurrence)] = ciphertext
}

func takeUnreadable(key string, occurrence int) (string, bool) {
	unreadableSecrets.mu.Lock()
	defer unreadableSecrets.mu.Unlock()
	v, ok := unreadableSecrets.m[fmt.Sprintf("%s#%d", key, occurrence)]
	return v, ok
}

// ResetUnreadableSecretsCache — для тестов и для случая «пользователь сам переввёл секрет».
func ResetUnreadableSecretsCache() {
	unreadableSecrets.mu.Lock()
	defer unreadableSecrets.mu.Unlock()
	unreadableSecrets.m = map[string]string{}
}

// ─── Файл целиком ────────────────────────────────────────────────────────────────────────

// WriteSecretFile записывает секрет атомарно (tmp+rename, как SaveConfigTo) и с правами 0600.
// На Windows содержимое защищается DPAPI; на платформе без DPAPI пишется как раньше.
func WriteSecretFile(path string, plain []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("WriteSecretFile: каталог: %w", err)
	}
	out := plain
	if crypto.DPAPIAvailable() {
		protected, err := protectSecretFn(plain)
		if err != nil {
			// Плайнтекст НЕ пишется: лучше честный отказ, чем секрет открытым текстом в
			// файле, про который UI скажет «защищено» (K2-E П11, тот же принцип).
			return fmt.Errorf("WriteSecretFile %s: защита не удалась, открытый текст не записан: %w",
				filepath.Base(path), err)
		}
		out = protected
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return fmt.Errorf("WriteSecretFile: запись: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("WriteSecretFile: подмена: %w", err)
	}
	return nil
}

// ReadSecretFile читает секрет.
//
//	wasProtected=false — файл в старом открытом виде, вызывающая сторона обязана его
//	мигрировать (EnsureSecretFileProtected).
//	err с crypto.ErrSecretUnreadable — контейнер есть, но не читается: ИСХОДНЫЙ ФАЙЛ НЕ ТРОНУТ,
//	решение (карантин + пересоздание) принимает вызывающая сторона.
//	Отсутствие файла отдаётся как есть (os.IsNotExist) — прежний контракт вызывающих.
func ReadSecretFile(path string) (plain []byte, wasProtected bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if !crypto.IsDPAPIProtected(raw) {
		return raw, false, nil
	}
	out, err := unprotectSecretFn(raw)
	if err != nil {
		return nil, true, fmt.Errorf("ReadSecretFile %s: %w", filepath.Base(path), err)
	}
	return out, true, nil
}

// EnsureSecretFileProtected — миграция старого открытого файла: читает, и если он ещё не
// защищён, переписывает защищённым. Содержимое не меняется. Возвращает migrated=true, если
// файл действительно был переписан.
func EnsureSecretFileProtected(path string) (migrated bool, err error) {
	if !crypto.DPAPIAvailable() {
		return false, nil
	}
	plain, wasProtected, err := ReadSecretFile(path)
	if err != nil {
		return false, err
	}
	if wasProtected {
		return false, nil
	}
	if err := WriteSecretFile(path, plain); err != nil {
		return false, err
	}
	return true, nil
}

// QuarantineSecretFile уводит нечитаемый файл в <имя>.bak, освобождая место для пересоздания.
// Данные НЕ удаляются: на родной машине (или после восстановления профиля) .bak ещё можно
// расшифровать — это прямое требование В-2.
func QuarantineSecretFile(path string) (bakPath string, err error) {
	bakPath = path + ".bak"
	for i := 1; i < 100; i++ {
		if _, statErr := os.Stat(bakPath); statErr != nil {
			break
		}
		bakPath = fmt.Sprintf("%s.bak.%d", path, i)
	}
	if err := os.Rename(path, bakPath); err != nil {
		return "", fmt.Errorf("QuarantineSecretFile: %w", err)
	}
	return bakPath, nil
}

// ─── Отдельные поля config.json ──────────────────────────────────────────────────────────

// protectConfigSecrets заменяет значения секретных полей на защищённые контейнеры.
// Вызывается из SaveConfigTo сразу после json.MarshalIndent.
func protectConfigSecrets(data []byte) ([]byte, error) {
	if !crypto.DPAPIAvailable() {
		return data, nil
	}
	fields := findJSONStringFields(data, configSecretKeys)
	if len(fields) == 0 {
		return data, nil
	}
	repl := make([]jsonFieldReplacement, 0, len(fields))
	for _, f := range fields {
		switch {
		case f.value == "":
			// Пустое значение либо действительно пустое, либо это то самое поле, которое мы
			// не смогли расшифровать при загрузке. Во втором случае возвращаем на диск
			// исходный шифртекст — сохранение настроек не должно стирать секрет.
			if stashed, ok := takeUnreadable(f.key, f.occurrence); ok {
				repl = append(repl, jsonFieldReplacement{f.valStart, f.valEnd, stashed})
			}
		case len(f.value) >= len(crypto.DPAPIMarker) && f.value[:len(crypto.DPAPIMarker)] == crypto.DPAPIMarker:
			// Уже защищено (повторное сохранение без изменения поля) — не трогаем.
		default:
			protected, err := protectSecretFn([]byte(f.value))
			if err != nil {
				return nil, fmt.Errorf("защита поля %q не удалась, открытый текст не сохранён: %w", f.key, err)
			}
			repl = append(repl, jsonFieldReplacement{f.valStart, f.valEnd, string(protected)})
		}
	}
	return applyJSONReplacements(data, repl)
}

// unprotectConfigSecrets возвращает значения секретных полей в открытый вид ДЛЯ РАЗБОРА В
// ПАМЯТИ. Файл на диске не меняется. Вызывается из LoadIntoFrom сразу после os.ReadFile.
//
// Ошибку наружу НЕ отдаёт намеренно: нечитаемый пароль ShadowTLS не повод не запустить
// программу вовсе. Вместо этого поле становится пустым (а не шифртекстом, который движок
// принял бы за пароль), шифртекст уходит в загашник, состояние «секреты недоступны»
// выставляется — это и есть «честная ветка», а не молчание.
func unprotectConfigSecrets(data []byte) []byte {
	fields := findJSONStringFields(data, configSecretKeys)
	if len(fields) == 0 {
		return data
	}
	repl := make([]jsonFieldReplacement, 0, len(fields))
	for _, f := range fields {
		if len(f.value) < len(crypto.DPAPIMarker) || f.value[:len(crypto.DPAPIMarker)] != crypto.DPAPIMarker {
			continue // открытый текст: старый файл, миграция произойдёт при первом сохранении
		}
		plain, err := unprotectSecretFn([]byte(f.value))
		if err != nil {
			stashUnreadable(f.key, f.occurrence, f.value)
			reason := fmt.Sprintf("поле %q в config.json защищено на другой машине или учётной записи и не читается здесь; значение оставлено пустым, исходное сохранено", f.key)
			if errors.Is(err, crypto.ErrDPAPIUnavailable) {
				reason = fmt.Sprintf("поле %q в config.json защищено Windows DPAPI, на этой системе расшифровать нечем; значение оставлено пустым, исходное сохранено", f.key)
			}
			MarkSecretsUnavailable(reason)
			repl = append(repl, jsonFieldReplacement{f.valStart, f.valEnd, ""})
			continue
		}
		repl = append(repl, jsonFieldReplacement{f.valStart, f.valEnd, string(plain)})
	}
	out, err := applyJSONReplacements(data, repl)
	if err != nil {
		// Единственная причина — невозможность закодировать строку в JSON, чего для string
		// не бывает. Отдаём исходные байты: разбор конфига не должен зависеть от этого.
		return data
	}
	return out
}

// ─── Хирургическая замена строковых значений в JSON ───────────────────────────────────────

type jsonStringField struct {
	key        string
	occurrence int // порядковый номер вхождения ЭТОГО ключа в документе, с нуля
	valStart   int // индекс открывающей кавычки значения
	valEnd     int // индекс сразу за закрывающей кавычкой значения
	value      string
}

type jsonFieldReplacement struct {
	start, end int
	value      string
}

// findJSONStringFields проходит документ как поток JSON-токенов (а не регулярным выражением):
// строки читаются целиком с учётом экранирования, поэтому текст `"shadowtls_password":`,
// случайно оказавшийся ВНУТРИ чьего-то значения, ключом не считается.
func findJSONStringFields(data []byte, keys map[string]bool) []jsonStringField {
	var out []jsonStringField
	counts := map[string]int{}
	i := 0
	for i < len(data) {
		if data[i] != '"' {
			i++
			continue
		}
		tokStart := i
		tokEnd, ok := scanJSONString(data, i)
		if !ok {
			return out // документ обрезан: дальше идти небезопасно
		}
		colon := skipJSONSpace(data, tokEnd)
		if colon >= len(data) || data[colon] != ':' {
			i = tokEnd // это значение или элемент массива, не ключ
			continue
		}
		key, err := decodeJSONString(data[tokStart:tokEnd])
		if err != nil || !keys[key] {
			i = colon + 1
			continue
		}
		valStart := skipJSONSpace(data, colon+1)
		if valStart >= len(data) || data[valStart] != '"' {
			i = colon + 1 // null или не-строка — не наш случай
			continue
		}
		valEnd, ok := scanJSONString(data, valStart)
		if !ok {
			return out
		}
		value, err := decodeJSONString(data[valStart:valEnd])
		if err != nil {
			i = valEnd
			continue
		}
		out = append(out, jsonStringField{
			key:        key,
			occurrence: counts[key],
			valStart:   valStart,
			valEnd:     valEnd,
			value:      value,
		})
		counts[key]++
		i = valEnd
	}
	return out
}

// scanJSONString: data[i] == '"'; возвращает индекс сразу за закрывающей кавычкой.
func scanJSONString(data []byte, i int) (int, bool) {
	i++
	for i < len(data) {
		switch data[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1, true
		default:
			i++
		}
	}
	return 0, false
}

func skipJSONSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

func decodeJSONString(raw []byte) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// applyJSONReplacements подставляет новые значения, сохраняя весь остальной файл байт в байт.
func applyJSONReplacements(data []byte, repl []jsonFieldReplacement) ([]byte, error) {
	if len(repl) == 0 {
		return data, nil
	}
	out := make([]byte, 0, len(data)+len(repl)*64)
	prev := 0
	for _, r := range repl {
		encoded, err := json.Marshal(r.value)
		if err != nil {
			return nil, err
		}
		out = append(out, data[prev:r.start]...)
		out = append(out, encoded...)
		prev = r.end
	}
	out = append(out, data[prev:]...)
	return out, nil
}
