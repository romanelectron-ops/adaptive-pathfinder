package chain

import (
	"context"
	"errors"
	"testing"
)

// Контракт Этапа 0: Diagnose отказывает ЯВНО, а не возвращает пустой (и потому похожий
// на «всё ок, звеньев нет») список диагностик.
func TestStubDiagnoser_ExplicitlyNotImplemented(t *testing.T) {
	d := NewDiagnoser()

	c := Chain{Links: []Link{
		{Label: "Звено 1: Европа", RawLink: "vless://a@example.com:443"},
	}}

	diags, err := d.Diagnose(context.Background(), c)
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Diagnose() err = %v, ожидался ErrNotImplemented", err)
	}
	if diags != nil {
		t.Errorf("Diagnose() diags = %v, ожидался nil при ошибке", diags)
	}
}

// Пустая цепочка (Links == nil) — тоже честный ErrNotImplemented, а не паника
// на пустом срезе и не молчаливое "OK, звеньев нет".
func TestStubDiagnoser_EmptyChain_StillExplicit(t *testing.T) {
	d := NewDiagnoser()
	diags, err := d.Diagnose(context.Background(), Chain{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Diagnose(пустая цепочка) err = %v, ожидался ErrNotImplemented", err)
	}
	if diags != nil {
		t.Errorf("Diagnose(пустая цепочка) diags = %v, ожидался nil", diags)
	}
}

// Комментарий пакета — контракт: одиночное подключение это цепочка длиной 1,
// а не особый случай. Проверяем, что структура Chain это действительно
// позволяет представить без специального ветвления.
func TestChain_SingleLinkIsChainOfLengthOne(t *testing.T) {
	c := Chain{Links: []Link{{Label: "Прямое подключение", RawLink: "vless://a@example.com:443"}}}
	if len(c.Links) != 1 {
		t.Fatalf("len(c.Links) = %d, want 1", len(c.Links))
	}
	if c.Links[0].Label != "Прямое подключение" {
		t.Errorf("Links[0].Label = %q, неожиданно изменилось при конструировании", c.Links[0].Label)
	}
}

// NewDiagnoser обязан возвращать нескучный ненулевой Diagnoser (используется
// напрямую вызывающим кодом без проверки на nil).
func TestNewDiagnoser_ReturnsNonNil(t *testing.T) {
	d := NewDiagnoser()
	if d == nil {
		t.Fatal("NewDiagnoser() вернул nil")
	}
}
