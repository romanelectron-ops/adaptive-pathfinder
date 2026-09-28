// dpapi_test.go — S-5 (TZ_APF_v1.4_FINAL.md), лот L1b-SEC2, контракт ящика A.
//
// Принимает: произвольные байты. Выводит: контейнер APFDP1:<base64>. Игнорирует: ничего.
// Отвергает: вход без маркера (ErrNotProtected), нерасшифровываемый контейнер
// (ErrSecretUnreadable), платформу без DPAPI (ErrDPAPIUnavailable).
package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestV14_DPAPI_RoundtripAndMarker(t *testing.T) {
	if !DPAPIAvailable() {
		t.Skip("DPAPI недоступен на этой платформе")
	}
	secret := []byte("private-key-L1bSEC2-\x00\xff-двоичные байты тоже")

	container, err := ProtectBytes(secret)
	if err != nil {
		t.Fatalf("ProtectBytes: %v", err)
	}
	if !IsDPAPIProtected(container) {
		t.Fatalf("нет маркера: %.20s", container)
	}
	if bytes.Contains(container, secret) {
		t.Fatal("секрет виден в контейнере")
	}
	got, err := UnprotectBytes(container)
	if err != nil {
		t.Fatalf("UnprotectBytes: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("круговой прогон исказил данные: %q", got)
	}

	// Формат Store (APFENC1:) и формат DPAPI (APFDP1:) — разные слои, путать нельзя.
	if IsEncrypted(container) {
		t.Error("контейнер DPAPI не должен опознаваться как формат Store")
	}
	if IsDPAPIProtected([]byte("APFENC1:xxx")) {
		t.Error("формат Store не должен опознаваться как контейнер DPAPI")
	}
}

// Пустой вход — не сценарий продукта (identity и креды всегда непустой JSON, пустые поля
// config.json пропускаются до вызова), но ошибка обязана быть внятной, а не «The parameter
// is incorrect» из crypt32, и одинаковой на всех платформах.
func TestV14_DPAPI_EmptyInputRejectedClearly(t *testing.T) {
	out, err := ProtectBytes(nil)
	if !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("ожидался ErrEmptySecret, получено %v", err)
	}
	if out != nil {
		t.Errorf("при отказе не должно быть данных на выходе: %q", out)
	}
	if _, err := ProtectBytes([]byte{}); !errors.Is(err, ErrEmptySecret) {
		t.Errorf("пустой срез: ожидался ErrEmptySecret, получено %v", err)
	}
}

func TestV14_DPAPI_RejectsUnmarkedAndBrokenInput(t *testing.T) {
	if _, err := UnprotectBytes([]byte(`{"открытый":"json"}`)); !errors.Is(err, ErrNotProtected) {
		t.Errorf("данные без маркера — это ErrNotProtected (сигнал к миграции), получено: %v", err)
	}
	if _, err := UnprotectBytes(nil); !errors.Is(err, ErrNotProtected) {
		t.Errorf("пустой вход: ожидался ErrNotProtected, получено %v", err)
	}
	_, err := UnprotectBytes([]byte(DPAPIMarker + "не base64 !!!"))
	if !errors.Is(err, ErrSecretUnreadable) {
		t.Errorf("битый base64: ожидался ErrSecretUnreadable, получено %v", err)
	}
}

// Ветка «не смог расшифровать» через шов — воспроизводится на любой платформе.
func TestV14_DPAPI_UnprotectFailureIsWrapped(t *testing.T) {
	prev := dpapiUnprotectFn
	t.Cleanup(func() { dpapiUnprotectFn = prev })
	dpapiUnprotectFn = func([]byte) ([]byte, error) {
		return nil, errors.New("ключ этой машины не подходит")
	}

	_, err := UnprotectBytes([]byte(DPAPIMarker + "YmxvYg=="))
	if !errors.Is(err, ErrSecretUnreadable) {
		t.Fatalf("ожидался ErrSecretUnreadable, получено %v", err)
	}
	if !strings.Contains(err.Error(), "ключ этой машины не подходит") {
		t.Errorf("исходная причина потеряна: %v", err)
	}
}

// Отказ защиты не должен возвращать «полуготовый» контейнер.
func TestV14_DPAPI_ProtectFailureReturnsNothing(t *testing.T) {
	prev := dpapiProtectFn
	t.Cleanup(func() { dpapiProtectFn = prev })
	dpapiProtectFn = func([]byte) ([]byte, error) { return nil, ErrDPAPIUnavailable }

	out, err := ProtectBytes([]byte("secret"))
	if !errors.Is(err, ErrDPAPIUnavailable) {
		t.Fatalf("ожидался ErrDPAPIUnavailable, получено %v", err)
	}
	if out != nil {
		t.Errorf("при отказе не должно быть данных на выходе: %q", out)
	}
}
