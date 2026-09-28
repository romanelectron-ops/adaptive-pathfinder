package security

import (
	"context"
	"errors"
	"testing"
)

// Контракт Этапа 0: обе операции Guard отказывают ЯВНО, а не возвращают пустой Report
// (который выглядел бы как «проверено, находок нет» — опаснее, чем честный отказ).
func TestStubGuard_ScanConfigExplicitlyNotImplemented(t *testing.T) {
	g := NewGuard()

	report, err := g.ScanConfig(context.Background())
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ScanConfig() err = %v, ожидался ErrNotImplemented", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("ScanConfig() report = %+v, ожидался пустой Report при ошибке", report)
	}
}

func TestStubGuard_WatchConnectionsExplicitlyNotImplemented(t *testing.T) {
	g := NewGuard()

	ch, err := g.WatchConnections(context.Background())
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("WatchConnections() err = %v, ожидался ErrNotImplemented", err)
	}
	if ch != nil {
		t.Error("WatchConnections() вернул ненулевой канал вместе с ошибкой")
	}
}
