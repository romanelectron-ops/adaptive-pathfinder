package relay

import (
	"context"
	"errors"
	"testing"
)

// fakeUPnPClient — управляемая заглушка upnpPortMappingClient для тестов (реальный
// discoverUPnPClients бьёт в SSDP-широковещание, недопустимо под `go test`).
type fakeUPnPClient struct {
	addErr    error
	extIP     string
	extIPErr  error
	deleteErr error
	deleted   bool
}

func (f *fakeUPnPClient) AddPortMapping(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error {
	return f.addErr
}
func (f *fakeUPnPClient) GetExternalIPAddress(context.Context) (string, error) {
	return f.extIP, f.extIPErr
}
func (f *fakeUPnPClient) DeletePortMapping(context.Context, string, uint16, string) error {
	f.deleted = true
	return f.deleteErr
}

func withFakeUPnPClients(t *testing.T, clients ...upnpPortMappingClient) {
	t.Helper()
	orig := discoverUPnPClientsFn
	discoverUPnPClientsFn = func(context.Context) ([]upnpPortMappingClient, error) {
		return clients, nil
	}
	t.Cleanup(func() { discoverUPnPClientsFn = orig })
}

// [консилиум, HIGH, находка №12, TZ_RELAY_HARDENING_2026-08-29.md кластер F] Сердце фикса:
// AddPortMapping локально отрабатывает без ошибки, но роутер честно возвращает СВОЙ (тоже
// приватный/CGNAT) WAN-адрес — живой случай 2026-08-28. Это НЕ должно считаться успехом.
func TestUpnpAddPortMapping_CGNATExternalIP_NotTreatedAsSuccess(t *testing.T) {
	client := &fakeUPnPClient{extIP: "100.85.30.12"} // CGNAT, RFC 6598
	withFakeUPnPClients(t, client)

	_, err := upnpAddPortMapping(context.Background(), "192.168.1.50", 8443)
	if err == nil {
		t.Fatal("upnpAddPortMapping с CGNAT-адресом от роутера должен был отказать")
	}
}

// Обычный RFC 1918 адрес роутера (двойной NAT через мостовой Wi-Fi-расширитель со своим UPnP,
// упомянутый в комментарии Fail-safe) — тоже не публичный, тоже не считается успехом.
func TestUpnpAddPortMapping_RFC1918ExternalIP_NotTreatedAsSuccess(t *testing.T) {
	client := &fakeUPnPClient{extIP: "192.168.1.1"}
	withFakeUPnPClients(t, client)

	_, err := upnpAddPortMapping(context.Background(), "192.168.1.50", 8443)
	if err == nil {
		t.Fatal("upnpAddPortMapping с приватным адресом от роутера должен был отказать")
	}
}

// Настоящий публичный внешний IP — обычный, не сломанный этим фиксом путь.
func TestUpnpAddPortMapping_PublicExternalIP_Succeeds(t *testing.T) {
	client := &fakeUPnPClient{extIP: "203.0.113.42"}
	withFakeUPnPClients(t, client)

	ip, err := upnpAddPortMapping(context.Background(), "192.168.1.50", 8443)
	if err != nil {
		t.Fatalf("upnpAddPortMapping с публичным IP отказал: %v", err)
	}
	if ip != "203.0.113.42" {
		t.Errorf("upnpAddPortMapping вернул %q, ожидался 203.0.113.42", ip)
	}
}

// Первый клиент вернул CGNAT-адрес, второй — настоящий публичный: как и с обычными ошибками,
// один "плохой" клиент не должен блокировать успех через следующего (комментарий Fail-safe
// у upnpAddPortMapping — несколько IGD-устройств в сети, редко, но бывает).
func TestUpnpAddPortMapping_FirstClientCGNAT_SecondClientPublic_TriesNext(t *testing.T) {
	bad := &fakeUPnPClient{extIP: "100.64.0.1"}
	good := &fakeUPnPClient{extIP: "203.0.113.42"}
	withFakeUPnPClients(t, bad, good)

	ip, err := upnpAddPortMapping(context.Background(), "192.168.1.50", 8443)
	if err != nil {
		t.Fatalf("upnpAddPortMapping отказал, хотя второй клиент был рабочим: %v", err)
	}
	if ip != "203.0.113.42" {
		t.Errorf("upnpAddPortMapping вернул %q, ожидался 203.0.113.42 (от второго клиента)", ip)
	}
}

// [консилиум, MEDIUM, находка №20] RemoveUPnPMapping — счастливый путь: снятие маппинга
// реально доходит до DeletePortMapping клиента.
func TestRemoveUPnPMapping_Succeeds(t *testing.T) {
	client := &fakeUPnPClient{}
	withFakeUPnPClients(t, client)

	if err := RemoveUPnPMapping(context.Background(), 8443); err != nil {
		t.Fatalf("RemoveUPnPMapping отказал: %v", err)
	}
	if !client.deleted {
		t.Error("DeletePortMapping не был вызван")
	}
}

// RemoveUPnPMapping — отсутствие IGD-устройства (или маппинг уже забыт роутером) — не паника,
// понятная ошибка, вызывающая сторона (StopServerRole) сама решает логировать-и-игнорировать.
func TestRemoveUPnPMapping_NoDeviceFound_ReturnsError(t *testing.T) {
	orig := discoverUPnPClientsFn
	discoverUPnPClientsFn = func(context.Context) ([]upnpPortMappingClient, error) {
		return nil, errors.New("upnp: ни одного IGD-устройства не найдено")
	}
	t.Cleanup(func() { discoverUPnPClientsFn = orig })

	if err := RemoveUPnPMapping(context.Background(), 8443); err == nil {
		t.Fatal("RemoveUPnPMapping без IGD-устройства должен был вернуть ошибку")
	}
}

func TestRemoveUPnPMapping_ClientErrors_ReturnsError(t *testing.T) {
	client := &fakeUPnPClient{deleteErr: errors.New("NoSuchEntryInArray")}
	withFakeUPnPClients(t, client)

	if err := RemoveUPnPMapping(context.Background(), 8443); err == nil {
		t.Fatal("RemoveUPnPMapping должен был вернуть ошибку клиента")
	}
	if !client.deleted {
		t.Error("DeletePortMapping должен был быть вызван (и вернуть ошибку), а не пропущен")
	}
}
