package catalog

import (
	"context"
	"net/http"
	"testing"
)

// ─── ThreeXUI.Fetch — login NewRequestWithContext error (line 59-61) ──────────

func TestThreeXUIProvider_Fetch_LoginRequestError(t *testing.T) {
	// URL with null byte causes http.NewRequestWithContext to fail before any I/O.
	p := &ThreeXUIProvider{
		cfg:    PaidProviderConfig{ID: "x0", Name: "X0", URL: "\x00://bad"},
		client: &http.Client{},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error for invalid login request URL")
	}
	t.Logf("OK: ThreeXUI login NewRequest error → %v", err)
}

// ─── MarzbanProvider.Fetch — token NewRequestWithContext error (line 133-137) ─

func TestMarzbanProvider_Fetch_TokenRequestError(t *testing.T) {
	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: "\x00://bad"},
		client: &http.Client{},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error for invalid token request URL")
	}
	t.Logf("OK: Marzban token NewRequest error → %v", err)
}

// ─── HiddifyProvider.Fetch — NewRequestWithContext error (line 231-234) ───────

func TestHiddifyProvider_Fetch_RequestError(t *testing.T) {
	p := &HiddifyProvider{
		cfg:    PaidProviderConfig{SubscriptionURL: "\x00://bad"},
		client: &http.Client{},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error for invalid Hiddify request URL")
	}
	t.Logf("OK: Hiddify NewRequest error → %v", err)
}
