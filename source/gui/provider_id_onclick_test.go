package main

import (
	"regexp"
	"strings"
	"testing"
)

// Дефект (найден ревью лота L5, существовал раньше): ID провайдера вставлялся в onclick внутрь
// JS-строки — onclick="toggleCatalogProvider('<id>', this)" и doRemovePaidProvider('<id>').
// esc() даёт &#39;, но парсер HTML раскодирует его обратно в «'» ДО выполнения JS: ID с
// апострофом ломал строку, а ID вида x');код;// выполнял чужой код. В Wails это полный контроль над
// приложением (см. комментарий к esc() в index.html: CSP у ассет-сервера нет). ID платного
// провайдера может прийти из импортированного config.json или прямого вызова API.
//
// Тест гоняет НАСТОЯЩИЕ функции из frontend/src/index.html под node (как
// server_role_host_ui_20260929_test.go), повторяя шаги браузера: раскодирует значения атрибутов и
// выполняет onclick с подставленным this. Нет node в PATH — тест пропускается.
const providerIDHarness = `
const fs = require('fs')
const src = fs.readFileSync(process.argv[2], 'utf8')
globalThis.window = globalThis
const html = {}
globalThis.document = { getElementById: function(id) {
  return { set innerHTML(v) { html[id] = v }, get innerHTML() { return html[id] } }
} }
globalThis.confirm = function() { return true }
globalThis.addLog = function() {}
globalThis.loadNodes = function() {}
const calls = { catalog: [], remove: [] }
globalThis.App = {
  SetCatalogProviderEnabled: async function(id, en) { calls.catalog.push({ id: id, enabled: en }) },
  RemovePaidProvider: async function(id) { calls.remove.push({ id: id }) },
  GetConfig: async function() { return { paid_providers: [] } },
}
// Исполняется ТОЛЬКО вырезка из собственного исходника страницы (harness под node, ввода извне нет).
eval(src)

// То, что делает HTML-парсер со значением атрибута.
function decode(s) {
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
}
const EVIL = "x');globalThis.pwned=1;//\"><img src=x onerror=alert(1)>&amp; \\"

;(async function() {
  const out = { evil: EVIL, errors: [] }

  renderCatalogList([{ id: EVIL, name: 'n', free: true, node_count: 1, trust_score: 0.5, enabled: false }])
  let m = /<div class="toggle[^"]*"[^>]*?data-id="([^"]*)"[^>]*?onclick="([^"]*)"/.exec(html['catalog-list'] || '')
  if (!m) { out.errors.push('переключатель каталога с data-id/onclick не найден: ' + html['catalog-list']) } else {
    out.catalogOnclick = decode(m[2])
    const fake = { dataset: { id: decode(m[1]) }, classList: { contains: function() { return false }, toggle: function() {} } }
    await new Function(out.catalogOnclick).call(fake)
  }

  renderPaidProviders({ paid_providers: [{ id: EVIL, name: 'n', type: '3x-ui', url: '' }] })
  m = /<button[^>]*?data-id="([^"]*)"[^>]*?onclick="([^"]*)"/.exec(html['paid-providers-list'] || '')
  if (!m) { out.errors.push('кнопка удаления с data-id/onclick не найдена: ' + html['paid-providers-list']) } else {
    out.paidOnclick = decode(m[2])
    await new Function(out.paidOnclick).call({ dataset: { id: decode(m[1]) } })
  }

  await new Promise(function(r) { setTimeout(r, 20) })
  out.pwned = globalThis.pwned === 1
  out.rawImg = (html['catalog-list'] || '').indexOf('<img') >= 0 || (html['paid-providers-list'] || '').indexOf('<img') >= 0
  out.calls = calls
  console.log(JSON.stringify(out))
})().catch(function(e) { console.error(String(e && e.stack || e)); process.exit(1) })
`

type providerIDResult struct {
	Evil           string   `json:"evil"`
	Errors         []string `json:"errors"`
	CatalogOnclick string   `json:"catalogOnclick"`
	PaidOnclick    string   `json:"paidOnclick"`
	Pwned          bool     `json:"pwned"`
	RawImg         bool     `json:"rawImg"`
	Calls          struct {
		Catalog []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"catalog"`
		Remove []struct {
			ID string `json:"id"`
		} `json:"remove"`
	} `json:"calls"`
}

func TestProviderIDIsNotSplicedIntoOnclickJS(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	fnSrc := strings.Join([]string{
		srFunctionSource(t, html, "function esc(s) {"),
		srFunctionSource(t, html, "function renderCatalogList(providers) {"),
		srFunctionSource(t, html, "window.toggleCatalogProvider = async function(id, el) {"),
		srFunctionSource(t, html, "function renderPaidProviders(cfg) {"),
		srFunctionSource(t, html, "window.doRemovePaidProvider = async function(id) {"),
	}, "\n")

	var res providerIDResult
	srRunNodeJSON(t, fnSrc, providerIDHarness, &res)

	for _, e := range res.Errors {
		t.Error(e)
	}
	for name, code := range map[string]string{"каталог": res.CatalogOnclick, "удаление": res.PaidOnclick} {
		if code == "" {
			continue
		}
		if strings.Contains(code, "x'") || strings.Contains(code, "pwned") || strings.Contains(code, res.Evil) {
			t.Errorf("onclick (%s) содержит фрагмент ID: %q", name, code)
		}
	}
	if res.Pwned {
		t.Error("ID провайдера выполнился как код (globalThis.pwned установлен)")
	}
	if res.RawImg {
		t.Error("в HTML остался неэкранированный <img> из ID")
	}
	if len(res.Calls.Catalog) != 1 || res.Calls.Catalog[0].ID != res.Evil || !res.Calls.Catalog[0].Enabled {
		t.Errorf("SetCatalogProviderEnabled получил %+v, ожидался один вызов с исходным ID и enabled=true (был выключен)", res.Calls.Catalog)
	}
	if len(res.Calls.Remove) != 1 || res.Calls.Remove[0].ID != res.Evil {
		t.Errorf("RemovePaidProvider получил %+v, ожидался один вызов с исходным ID", res.Calls.Remove)
	}
}

// Статическая страховка: ID/имя не вставляются в onclick внутри JS-строки ни в одном месте окна.
func TestNoIDSplicedIntoOnclickJS(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	bs := string(rune(92))
	// Любой обработчик on...="..." со СКЛЕЙКОЙ значения в JS-строку (а не только onclick с id первым
	// аргументом: формы fn(this,'id'), onchange, oninput и т.п. устроены так же опасно). Склейка выглядит
	// как «обратная косая, кавычка, кавычка, плюс» (или плюс, кавычка, обратная косая, кавычка) внутри
	// значения атрибута; строковые константы вроде fetch(B+<кавычка>/api/x<кавычка>) - не склейка.
	q := regexp.QuoteMeta(bs)
	bad := regexp.MustCompile(`on[a-z]+="[^"]*(` + q + `''\s*\+|\+\s*'` + q + `')`)
	if locs := bad.FindAllStringIndex(html, -1); len(locs) > 0 {
		first := html[locs[0][0]:min(locs[0][0]+120, len(html))]
		t.Errorf("в index.html осталось %d мест, где значение вставляется в onclick внутри JS-строки, например: %s", len(locs), first)
	}
}
