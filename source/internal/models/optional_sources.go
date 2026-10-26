// optional_sources.go — встроенные источники узлов, которые в сборке есть, но ВЫКЛЮЧЕНЫ до
// явного решения пользователя (лот L5, решение владельца 2026-10-21: «сделать возможность
// включения в интерфейсе», по умолчанию не включать).
//
// Почему не включены. Это чужие публичные списки (бесплатные узлы сторонних операторов):
// трафик через них могут читать или подменять, а доля узлов, реально проходящих пробу APF,
// пока не измерена. Включать их надо осознанно — переключателем в «Каталоге серверов»
// (Web, окно ПК, Android).
//
// Только ссылки. Сами списки в репозиторий APF, тестовые фикстуры и релизы не копируются
// (лицензия источника и принцип «не раздавать чужие узлы»); в тестах — синтетические данные.
package models

import "strings"

// igareckRawBase — корень сырых файлов репозитория igareck/vpn-configs-for-russia (GPL-3.0).
// Имена файлов у автора иногда меняются (его issue #317): тогда загрузка вернёт 404, источник
// покажет ошибку в журнале каталога, а остальные продолжат работать.
const igareckRawBase = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"

// igareckNote — пояснение в карточке источника. Частота обновления у автора меняется, поэтому
// числа здесь нет. «Обновить каталог» названо явно: включение источника само загрузку не запускает.
const igareckNote = "Сторонний список (igareck, GPL-3.0). Выключен по умолчанию: бесплатные узлы чужих операторов, " +
	"трафик через них могут читать. После включения нажмите «Обновить каталог»; при выключении узлы " +
	"источника убираются из пула (кроме закреплённых, избранных, активного)."

// igareckWhiteNote — то же для списков «белых списков» мобильного интернета.
const igareckWhiteNote = igareckNote + " Для мобильных сетей с «белыми списками»."

// OptionalSource — описание встроенного необязательного источника.
type OptionalSource struct {
	ID   string
	Name string
	URL  string
	// Note — пояснение для карточки источника в UI.
	Note string
}

// optionalSources — порядок задаёт порядок показа в каталоге: сначала чёрные списки, потом белые.
// WHITE-SNI-RU-all.txt сознательно не подключён: в нём нет ни одного узла (замер 2026-10-21).
var optionalSources = []OptionalSource{
	{"igareck-black-vless", "igareck: чёрные списки — VLESS", igareckRawBase + "BLACK_VLESS_RUS.txt", igareckNote},
	{"igareck-black-vless-mobile", "igareck: чёрные списки — VLESS (мобильные)", igareckRawBase + "BLACK_VLESS_RUS_mobile.txt", igareckNote},
	{"igareck-black-ss", "igareck: чёрные списки — Shadowsocks", igareckRawBase + "BLACK_SS+All_RUS.txt", igareckNote},
	{"igareck-black-ss-weak-dpi", "igareck: чёрные списки — SS (слабый DPI)", igareckRawBase + "BLACK_SS_WEAK_DPI_RUS.txt", igareckNote},
	{"igareck-white-reality-mobile", "igareck: белые списки — Reality (мобильные)", igareckRawBase + "Vless-Reality-White-Lists-Rus-Mobile.txt", igareckWhiteNote},
	{"igareck-white-cidr-all", "igareck: белые списки — CIDR (все)", igareckRawBase + "WHITE-CIDR-RU-all.txt", igareckWhiteNote},
	{"igareck-white-cidr-checked", "igareck: белые списки — CIDR (проверенные)", igareckRawBase + "WHITE-CIDR-RU-checked.txt", igareckWhiteNote},
}

// OptionalSources возвращает копию списка встроенных необязательных источников.
func OptionalSources() []OptionalSource {
	out := make([]OptionalSource, len(optionalSources))
	copy(out, optionalSources)
	return out
}

// OptionalSourceByID находит необязательный источник по ID (без учёта регистра и пробелов).
func OptionalSourceByID(id string) (OptionalSource, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, o := range optionalSources {
		if o.ID == id {
			return o, true
		}
	}
	return OptionalSource{}, false
}

// Config превращает описание в запись cfg.Sources с заданным состоянием «включён».
func (o OptionalSource) Config(enabled bool) SourceConfig {
	return SourceConfig{
		ID:                  o.ID,
		Name:                o.Name,
		URL:                 o.URL,
		Type:                "subscription",
		Enabled:             enabled,
		AutoUpdate:          true,
		UpdateIntervalHours: 3,
	}
}

// ensureOptionalSources дописывает в cfg.Sources недостающие необязательные источники —
// ВЫКЛЮЧЕННЫМИ. Нужно для всех, кто обновляется поверх старой установки: их config.json хранит
// собственный массив sources, и json.Unmarshal не добавляет в него новые дефолты, так что
// без этого переключателя в каталоге просто не было бы чего показывать (у каталога на Android
// и в окне ПК нет «добавить источник»).
//
// Уже имеющиеся записи: выбор пользователя (Enabled), расписание и отметки содержимого не
// трогаются; ID приводится к каноничному виду (регистр и пробелы), чтобы остальной код сравнивал
// ID строго. Имя и URL обновляются из кода, пока URL записи пуст либо указывает на тот же raw-хостинг
// igareck: автор иногда переименовывает файлы (его issue #317), и без обновления записанный в
// config.json старый адрес вечно отвечал бы 404. Адрес, который пользователь заменил на своё
// зеркало, не перезаписывается.
// Возвращает true, если что-то дописано или изменено.
func (c *AppConfig) ensureOptionalSources() bool {
	if c == nil {
		return false
	}
	index := make(map[string]int, len(c.Sources))
	for i, s := range c.Sources {
		key := strings.ToLower(strings.TrimSpace(s.ID))
		if _, dup := index[key]; !dup {
			index[key] = i
		}
	}
	changed := false
	for _, o := range optionalSources {
		i, have := index[o.ID]
		if !have {
			c.Sources = append(c.Sources, o.Config(false))
			changed = true
			continue
		}
		s := &c.Sources[i]
		if s.ID != o.ID {
			s.ID, changed = o.ID, true
		}
		if s.Name != o.Name {
			s.Name, changed = o.Name, true
		}
		if u := strings.TrimSpace(s.URL); (u == "" || strings.HasPrefix(u, igareckRawBase)) && u != o.URL {
			s.URL, changed = o.URL, true
		}
	}
	return changed
}
