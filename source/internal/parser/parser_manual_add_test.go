package parser

// Тесты разбора ссылок, добавляемых ВРУЧНУЮ (жалоба пользователя 2026-08-24: «не получилось
// ввести вручную узел и добавить»). Каждый кейс здесь — форма ссылки, которая работает в
// других клиентах и до правок этого дня отвергалась или разбиралась в мусор.

import (
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ss:// в СТАРОМ формате: весь адрес внутри base64, без «@» в открытом виде.
// Раньше url.Parse клал весь блоб в host → Port=0 → ValidateNode отвергал узел.
func TestParseShadowsocks_LegacyWholeBodyBase64(t *testing.T) {
	// base64("aes-256-gcm:TestPass123@198.51.100.7:8388")
	link := "ss://YWVzLTI1Ni1nY206VGVzdFBhc3MxMjNAMTk4LjUxLjEwMC43OjgzODg=#Legacy%20Node"

	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("legacy ss:// должен разбираться, получено: %v", err)
	}
	if node.Address != "198.51.100.7" {
		t.Errorf("address = %q, ожидался 198.51.100.7", node.Address)
	}
	if node.Port != 8388 {
		t.Errorf("port = %d, ожидался 8388", node.Port)
	}
	if node.Method != "aes-256-gcm" {
		t.Errorf("method = %q, ожидался aes-256-gcm", node.Method)
	}
	if node.Password != "TestPass123" {
		t.Errorf("password = %q, ожидался TestPass123", node.Password)
	}
	if node.Name != "Legacy Node" {
		t.Errorf("name = %q, ожидался %q (percent-decoded)", node.Name, "Legacy Node")
	}
	if err := models.ValidateNode(node); err != nil {
		t.Fatalf("узел из валидной legacy-ссылки не прошёл валидацию: %v", err)
	}
}

// ss:// SIP002 с ОТКРЫТЫМИ method:password (без base64) — тоже встречается в дикой природе.
func TestParseShadowsocks_PlainUserInfo(t *testing.T) {
	node, err := ParseLink("ss://chacha20-ietf-poly1305:pa$$w0rd@example.org:443#Plain")
	if err != nil {
		t.Fatalf("plain SIP002 должен разбираться: %v", err)
	}
	if node.Method != "chacha20-ietf-poly1305" || node.Password != "pa$$w0rd" {
		t.Errorf("учётка разобрана неверно: method=%q password=%q", node.Method, node.Password)
	}
	if node.Address != "example.org" || node.Port != 443 {
		t.Errorf("адрес разобран неверно: %s:%d", node.Address, node.Port)
	}
}

// Пароль с «+» и «/» обязан дойти до узла БУКВАЛЬНО.
//
// Регрессия, внесённая и пойманная 2026-08-24 при переписывании разбора ss://: пароль
// прогонялся через url.QueryUnescape, а тот трактует «+» как пробел (правило query-строк).
// Пароли часто генерируют base64-алфавитом, где «+» и «/» — обычные символы, поэтому
// «pa+ss» молча превращался в «pa ss»: узел не аутентифицировался, и увидеть причину было
// неоткуда.
func TestParseShadowsocks_PasswordKeepsPlusAndSlash(t *testing.T) {
	// base64("aes-256-gcm:pa+ss/w0rd")
	node, err := ParseLink("ss://YWVzLTI1Ni1nY206cGErc3MvdzByZA==@198.51.100.5:8388#T")
	if err != nil {
		t.Fatalf("разбор не должен падать: %v", err)
	}
	if node.Password != "pa+ss/w0rd" {
		t.Errorf("пароль искажён: %q, ожидался %q", node.Password, "pa+ss/w0rd")
	}
	if node.Method != "aes-256-gcm" {
		t.Errorf("method = %q", node.Method)
	}
}

// В ОТКРЫТОЙ форме процент-последовательности наоборот обязаны раскодироваться.
func TestParseShadowsocks_PlainPasswordPercentDecoded(t *testing.T) {
	node, err := ParseLink("ss://aes-256-gcm:p%40ss%2Fword@198.51.100.5:8388#T")
	if err != nil {
		t.Fatalf("разбор не должен падать: %v", err)
	}
	if node.Password != "p@ss/word" {
		t.Errorf("пароль = %q, ожидался %q (процент-декодирование открытой формы)",
			node.Password, "p@ss/word")
	}
}

// VLESS + Reality: параметр fp (uTLS-отпечаток) раньше молча терялся, а config_builder
// безусловно подставлял "chrome" — узел, чей сервер ждёт другой отпечаток, не поднимался.
func TestParseVLESS_KeepsRealityFingerprint(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.9:443" +
		"?type=tcp&security=reality&pbk=xkQjHs0m7DdpF0pTVCz1s8H0oQ8Qb3xVYo6oKcHnFhI" +
		"&sid=ab12&fp=firefox&sni=www.microsoft.com&flow=xtls-rprx-vision#Reality"

	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("vless+reality должен разбираться: %v", err)
	}
	if node.TLS == nil || node.TLS.Reality == nil {
		t.Fatal("Reality-конфиг не собран")
	}
	if node.TLS.Fingerprint != "firefox" {
		t.Errorf("fingerprint = %q, ожидался firefox (параметр fp из ссылки)", node.TLS.Fingerprint)
	}
	if node.TLS.ServerName != "www.microsoft.com" {
		t.Errorf("sni = %q", node.TLS.ServerName)
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q", node.Flow)
	}
	if err := models.ValidateNode(node); err != nil {
		t.Fatalf("валидный reality-узел не прошёл валидацию: %v", err)
	}
}

// Схема с заглавной буквы: экранная клавиатура Android автокапитализирует первый символ.
func TestParseLink_SchemeIsCaseInsensitive(t *testing.T) {
	for _, link := range []string{
		"VLESS://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.9:443#Upper",
		"Ss://YWVzLTI1Ni1nY206cGFzcw==@203.0.113.9:8388#Mixed",
		"TROJAN://secret@203.0.113.9:443#Upper",
	} {
		if _, err := ParseLink(link); err != nil {
			t.Errorf("ссылка %q должна разбираться независимо от регистра схемы: %v", link, err)
		}
	}
}

// Неканонический идентификатор пользователя: sing-box/Xray отображают ЛЮБУЮ строку в UUIDv5,
// такие конфиги массово встречаются у публичных провайдеров. Раньше отвергались.
func TestValidateNode_AcceptsNonCanonicalUUID(t *testing.T) {
	node, err := ParseLink("vless://my-custom-user-id@203.0.113.9:443#NonCanonical")
	if err != nil {
		t.Fatalf("разбор не должен падать: %v", err)
	}
	if err := models.ValidateNode(node); err != nil {
		t.Fatalf("неканонический UUID должен приниматься (sing-box его принимает): %v", err)
	}
}

// Мусор по-прежнему обязан отвергаться — послабление UUID не должно открыть дорогу всему.
func TestValidateNode_StillRejectsGarbage(t *testing.T) {
	cases := map[string]*models.Node{
		"пустой UUID": {
			Protocol: models.ProtoVLESS, Address: "203.0.113.9", Port: 443, UUID: "",
		},
		"UUID с пробелом": {
			Protocol: models.ProtoVLESS, Address: "203.0.113.9", Port: 443, UUID: "abc def",
		},
		"порт вне диапазона": {
			Protocol: models.ProtoVLESS, Address: "203.0.113.9", Port: 0, UUID: "user",
		},
	}
	for name, n := range cases {
		if err := models.ValidateNode(n); err == nil {
			t.Errorf("%s: ожидался отказ, узел принят", name)
		}
	}
}

// Ключевая находка: ID ОБЯЗАН зависеть от учётных данных. Иначе рабочая ссылка, добавляемая
// вручную, отвергается как «already exists» из-за чужого мёртвого узла на том же host:port.
func TestGenerateID_DistinguishesCredentials(t *testing.T) {
	base := "vless://%s@203.0.113.9:443#Node"

	mine, err := ParseLink(strings.Replace(base, "%s", "b831381d-6324-4d53-ad4f-8cda48b30811", 1))
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := ParseLink(strings.Replace(base, "%s", "ffffffff-1111-2222-3333-444444444444", 1))
	if err != nil {
		t.Fatal(err)
	}
	if mine.ID == stranger.ID {
		t.Fatalf("узлы с одинаковым адресом, но РАЗНЫМИ учётками получили один ID (%s) — "+
			"именно из-за этого рабочая ссылка отвергалась как already exists", mine.ID)
	}

	// И наоборот: одна и та же ссылка обязана давать стабильный ID (дедупликация подписок).
	again, err := ParseLink(strings.Replace(base, "%s", "b831381d-6324-4d53-ad4f-8cda48b30811", 1))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != mine.ID {
		t.Errorf("ID не стабилен между разборами одной ссылки: %s != %s", again.ID, mine.ID)
	}
}

// Регрессия-сценарий из самого комментария generateID (parser.go): для VLESS+Reality именно
// pbk (публичный ключ Reality-сервера) — единственный различитель, если UUID у старой и новой
// конфигурации один и тот же. До этого теста сценарий был только описан в комментарии, но не
// проверен: TestGenerateID_DistinguishesCredentials и TestGenerateID_ShadowsocksCredentialsMatter
// покрывают только UUID/method/password, TLS/Reality-поля не затрагивают ни один существующий
// тест. Смена ключа на сервере (частая практика при компрометации/ротации) с прежней (до этого
// комментария и уже отменённой) реализацией давала ТОТ ЖЕ ID — пользователь вставлял рабочую
// ссылку с новым ключом, попадал в ветку «already exists», и в пуле оставался узел со СТАРЫМ,
// нерабочим ключом.
func TestGenerateID_RealityKeyChangeMatters(t *testing.T) {
	base := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.9:443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&pbk=%s&sid=ab12#Reality"

	oldKey, err := ParseLink(strings.Replace(base, "%s", "oldPublicKey000000000000000000000000000", 1))
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := ParseLink(strings.Replace(base, "%s", "newPublicKey111111111111111111111111111", 1))
	if err != nil {
		t.Fatal(err)
	}
	if oldKey.ID == newKey.ID {
		t.Fatalf("один и тот же UUID с РАЗНЫМИ Reality public_key получил один ID (%s) — "+
			"ссылка с новым ключом сервера была бы отвергнута как already exists, а в пуле "+
			"остался бы узел со старым нерабочим ключом", oldKey.ID)
	}

	// short_id (sid) тоже должен различать узлы — сервер может выдавать несколько sid на один pbk.
	base2 := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.9:443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&pbk=samePublicKey00000000000000000000000&sid=%s#Reality"
	sidA, _ := ParseLink(strings.Replace(base2, "%s", "aaaa", 1))
	sidB, _ := ParseLink(strings.Replace(base2, "%s", "bbbb", 1))
	if sidA.ID == sidB.ID {
		t.Error("разные Reality short_id на одном public_key получили одинаковый ID")
	}
}

// Тот же контракт для shadowsocks: разные пароли на одном адресе — разные узлы.
func TestGenerateID_ShadowsocksCredentialsMatter(t *testing.T) {
	a, err := ParseLink("ss://YWVzLTI1Ni1nY206cGFzc0E=@203.0.113.9:8388")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseLink("ss://YWVzLTI1Ni1nY206cGFzc0I=@203.0.113.9:8388")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Error("узлы с разными паролями на одном адресе получили одинаковый ID")
	}
}
