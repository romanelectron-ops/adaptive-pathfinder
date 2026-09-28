package relay

import "testing"

// Тестовый вектор посчитан отдельно (не переиспользует продакшен-XOR из stun.go, иначе тест
// проверял бы только то, что функция равна сама себе): STUN Binding Success Response,
// XOR-MAPPED-ADDRESS для IPv4 203.0.113.5:12345 (RFC 5769-стиль сборки заголовка вручную).
func TestStunParseXorMappedAddress_ValidResponse(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	resp := []byte{
		0x01, 0x01, 0x00, 0x0c, // Binding Success Response, length=12
		0x21, 0x12, 0xa4, 0x42, // magic cookie
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, // transaction ID
		0x00, 0x20, 0x00, 0x08, // XOR-MAPPED-ADDRESS, length=8
		0x00, 0x01, 0x11, 0x2b, // family=IPv4, x-port
		0xea, 0x12, 0xd5, 0x47, // x-address
	}

	ip, port, err := stunParseXorMappedAddress(resp, txID)
	if err != nil {
		t.Fatalf("stunParseXorMappedAddress() err = %v, ожидался nil", err)
	}
	if ip.String() != "203.0.113.5" {
		t.Errorf("ip = %v, ожидался 203.0.113.5", ip)
	}
	if port != 12345 {
		t.Errorf("port = %d, ожидался 12345", port)
	}
}

func TestStunParseXorMappedAddress_WrongTransactionID_Rejected(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	resp := []byte{
		0x01, 0x01, 0x00, 0x0c,
		0x21, 0x12, 0xa4, 0x42,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // чужой txID
		0x00, 0x20, 0x00, 0x08,
		0x00, 0x01, 0x11, 0x2b,
		0xea, 0x12, 0xd5, 0x47,
	}
	if _, _, err := stunParseXorMappedAddress(resp, txID); err == nil {
		t.Error("stunParseXorMappedAddress() принял ответ с чужим transaction ID")
	}
}

func TestStunParseXorMappedAddress_WrongMagicCookie_Rejected(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	resp := []byte{
		0x01, 0x01, 0x00, 0x0c,
		0x00, 0x00, 0x00, 0x00, // неверный cookie
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		0x00, 0x20, 0x00, 0x08,
		0x00, 0x01, 0x11, 0x2b,
		0xea, 0x12, 0xd5, 0x47,
	}
	if _, _, err := stunParseXorMappedAddress(resp, txID); err == nil {
		t.Error("stunParseXorMappedAddress() принял ответ с неверным magic cookie")
	}
}

func TestStunParseXorMappedAddress_TooShort_Rejected(t *testing.T) {
	var txID [12]byte
	if _, _, err := stunParseXorMappedAddress([]byte{0x01, 0x01}, txID); err == nil {
		t.Error("stunParseXorMappedAddress() принял заведомо короткий ответ")
	}
}

func TestStunBindingRequest_WellFormed(t *testing.T) {
	req, txID, err := stunBindingRequest()
	if err != nil {
		t.Fatalf("stunBindingRequest() err = %v", err)
	}
	if len(req) != 20 {
		t.Fatalf("len(req) = %d, ожидалось 20 (заголовок без атрибутов)", len(req))
	}
	if req[0] != 0x00 || req[1] != 0x01 {
		t.Errorf("тип сообщения = %x%x, ожидался 0001 (Binding Request)", req[0], req[1])
	}
	for i := 0; i < 12; i++ {
		if req[8+i] != txID[i] {
			t.Fatalf("transaction ID в пакете не совпадает с возвращённым")
		}
	}
}
