# internal/harvester — реализация (blackbox-TDD)

## Что создано

Четыре новых файла (только они, ничего в types.go/budget.go/testdata/*_test.go не тронуто):

- `sanitize.go` — `Secrets`, `SecretsFromNodes`, `(*Secrets).Sanitize/Leaks/Len`, `Redacted`, `SanitizeForLog`.
- `extract_deterministic.go` — `DeterministicExtractor`, `NewDeterministicExtractor`, `Extract`/`extractWithRejects`,
  вся общая машинерия схем (`schemeRegexes`, `supportedSchemes`/`unsupportedSchemes`/`userinfoSchemes`,
  `normalize`, `splitScheme`, `validateNodeShape`) — переиспользуется guard'ом модели из model_adapter.go.
- `model_adapter.go` — `ModelExtractor`, `NewNoopModelExtractor`, `ErrModelUnavailable`, `ParseModelJSON`,
  `Window`/`SplitWindows`, `BuildPrompt`, `guardModelCandidates`.
- `run.go` — `Options`, `New`, `harvesterImpl.Run/Available`.

## Результат тестов

```
go test ./internal/harvester/ -count=1
```
54 из 55 тестов верхнего уровня (плюс все 7 подтестов `TestSamplesGiveNonEmptyResult`) — PASS.
Один FAIL, см. «Известная проблема вне периметра» ниже.

```
go test ./internal/harvester/ -count=1 -race
```
Тот же единственный FAIL, гонок не обнаружено (никаких `DATA RACE` в выводе).

```
go vet ./internal/harvester/
```
Чисто, без вывода.

## Известная проблема вне периметра (НЕ мой файл, не трогал)

`TestZeroBudgetNormalizesToDefaults` (budget_test.go) падает из-за бага в уже существующем
`budget.go`, `Budget.Normalize()`:

```go
if b.ModelWindowTokens <= 0 || b.ModelWindowTokens > b.ModelCtxTokens {
    b.ModelWindowTokens = d.ModelWindowTokens   // 0 → 2000
}
if b.ModelWindowOvlp < 0 || b.ModelWindowOvlp >= b.ModelWindowTokens {
    b.ModelWindowOvlp = d.ModelWindowOvlp
}
```

Для `Budget{}` (все нули): `ModelWindowTokens` уже заменён на 2000 предыдущим блоком, а затем
проверка `0 < 0 || 0 >= 2000` — обе части ложны, поэтому `ModelWindowOvlp` остаётся 0 вместо
дефолтных 200 (`DefaultModelWindowOverlap`). `Budget{}.Normalize() != DefaultBudget()` —
тест это и ловит. Дефект чисто в budget.go, никак не связан с internal/harvester/*.go,
которые я писал; воспроизводится и без единой строки моего кода. Инструкция задачи прямо
запрещает трогать budget.go, поэтому я его не менял — завёл отдельную фоновую задачу
(`task_5475e6a3`, "Fix Budget.Normalize() ModelWindowOvlp default bug") с точным разбором и
однострочным предлагаемым фиксом (`b.ModelWindowOvlp <= 0 || ...` вместо `< 0`, по аналогии с
остальными полями этой же функции).

Моя собственная реализация (run.go) этим багом не задета: `ModelWindowTokens`/`ModelWindowOvlp`
нигде не читает и не использует.

## Неоднозначности спецификации и как я их решил

1. **`MinFreeMemForModel`** — в задании сказано объявить эту константу; на деле она уже
   объявлена в budget.go (1 932 735 283 = 1,8 ГиБ) и используется всеми тестами напрямую.
   Ничего не переопределял, просто использую существующую константу как есть.

2. **Зеро-width/«разорванная» схема (`TestSampleZeroWidthAndBrokenScheme`)** — невидимые
   символы (U+200B/200C/200D/FEFF) могут стоять ВНУТРИ имени схемы (`vl<ZWSP>ess://`), а не
   только в хвосте ссылки. Регэксп на каждую схему построен так, что между КАЖДОЙ буквой схемы
   и в каждом из трёх мест разделителя `://` допускается произвольное число невидимых символов
   плюс (только в разделителе) один обычный пробел — это же и чинит `trojan:/ /...`. Raw остаётся
   грязным (I-2), Normalized чистит через `strings.NewReplacer` + регэксп на разделитель +
   `html.UnescapeString`.

3. **Форма ссылки vs неподдерживаемая схема (`TestSampleXXReplacement`,
   `TestUnsupportedSchemesRejectedNotEmitted`)** — решил так: сперва проверяю схему на
   `unsupportedSchemes` (hysteria2/tuic/ssconf/hy2 → `unsupported_scheme` СРАЗУ, форму не
   проверяю), и только для `supportedSchemes` (vless/vmess/ss/trojan) проверяю форму
   (`vless`/`ss`/`trojan` обязаны содержать `@` — это и есть граница §5.2, `vmess` не обязан,
   у него нет user-info).

4. **Схема внутри чужого слова (`TestNoFalsePositiveInsideOtherScheme`, `ss://` внутри
   `vmess://`)** — решил через `\b` перед первой буквой схемы: между `...e` и `ss://` внутри
   "vmess" границы слова нет (обе стороны — буквы), Go regexp `\b` там не матчит.

5. **base64-блоб vs пара­метр pbk= в ссылке** — оба выглядят как длинная строка из символов
   base64-алфавита, но блоб-кандидат обязан занимать ЦЕЛУЮ строку (`(?m)^...$`), а не быть
   частью строки со схемой/параметрами. Проверено на всех testdata: единственная строка,
   целиком состоящая из base64-алфавита (32+ символов), — это и есть содержимое
   `subscription_b64.txt`; `pbk=TESTPBK...` внутри vless-строки не проходит, потому что вокруг
   него в той же строке есть `vless://`, `?`, `&`, `#`.

6. **Секция Clash YAML (`TestSampleClashYAML`, ожидается ровно один блок с `Raw`, начинающимся
   на `proxies:`)** — регэксп `(?m)^proxies:[ \t]*\r?\n(?:[ \t]+[^\r\n]*\r?\n?)*`: строка
   `proxies:` плюс все следующие строки, начинающиеся с отступа, до первого
   не-отступленного верхнеуровневого ключа (`proxy-groups:`).

7. **Подписки vs реклама/обычная ссылка (`TestSampleSubscriptionURLs`)** — эвристика по
   ключевым словам (`sub`, `clash`, `config`, `token=`) и расширениям (`.txt`, `.yaml`, `.yml`)
   в самой ссылке. `.../about` и `.../buy?ref=...` ни под одно не подходят и в кандидаты не
   попадают вовсе (не как отказ — как то, что харвестер даже не пытался их взять).

8. **`guardModelCandidates` — проверка формы по Raw или по Normalized?** Решил: по
   Normalized. `TestModelOnlyCandidatesGoLast` специально даёт модели ссылку с
   HTML-числовой сущностью вместо двоеточия (`vless&#58;//...`) — по построению НЕ содержит
   литеральной `://`, поэтому её обязана найти именно модель, а не regex. Guard прогоняет
   substring-проверку (I-2) по СЫРОМУ `Raw` (иначе выдумку было бы не поймать), а определение
   схемы/формы — по уже нормализованному тексту (иначе эта ссылка модели попала бы в отказ
   `bad_shape`, хотя весь смысл теста — что она валидна ПОСЛЕ раскрытия сущности).

9. **`SecretsFromNodes` — что считается «слишком общим, не секретом»
   (`TestSanitizeShortAndGenericValuesNotRedacted`)** — помимо порога длины (`< 6` не режется,
   это ловит `"123"`), завёл список общеупотребительных значений (`password`, имена шифров
   `aes-256-gcm`/`chacha20-ietf-poly1305` и т.п.), которые не режутся, даже если длиннее
   порога — иначе метод шифрования узла считался бы секретом.

10. **`Report.Duplicate`** — ни один тест не проверяет точное значение этого поля напрямую;
    считаю в него все `RejectedItem` с `Reason == ReasonDuplicate`, из обоих источников
    (детерминированного дедупа и guard'а модели) — соответствует комментарию в types.go
    («повторы, снятые харвестером»).

## Подтверждение

`go test ./internal/harvester/ -count=1` печатает `FAIL` из-за ОДНОГО теста budget.go
(см. выше) — все тесты, относящиеся к файлам, которые я реализовывал, зелёные. `-race` и
`go vet` чисты.
