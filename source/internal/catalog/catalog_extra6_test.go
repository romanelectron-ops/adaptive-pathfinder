package catalog

import (
	"context"
	"net/http"
	"testing"
)

// ─── HiddifyProvider.Fetch: io.ReadAll error (line 247) ─────────────────────

// TestHiddifyProvider_Fetch_ReadError covers panel_providers.go line 247-249
// (the error path when io.ReadAll fails on a 200 response body).
// We reuse errBodyTransport / errReadCloser from catalog_extra5_test.go —
// they are in the same package test compilation unit.
func TestHiddifyProvider_Fetch_ReadError(t *testing.T) {
	p := &HiddifyProvider{
		cfg: PaidProviderConfig{
			ID:              "hid-read-err",
			Name:            "TestHiddify",
			SubscriptionURL: "https://does-not-matter.example.com/sub",
		},
		client: &http.Client{Transport: &errBodyTransport{}},
	}

	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected an error from io.ReadAll failure in HiddifyProvider.Fetch, got nil")
	}
	t.Logf("got expected error: %v", err)
}
