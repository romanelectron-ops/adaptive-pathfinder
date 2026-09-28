package catalog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// ─── shared error transport ───────────────────────────────────────────────────

type alwaysErrTransport struct{ err error }

func (t *alwaysErrTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

// countingTransport succeeds for the first N requests, then returns an error.
type countingTransport struct {
	base    http.RoundTripper
	failOn  int32 // fail when call count reaches this (1-indexed)
	count   atomic.Int32
	failErr error
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	n := c.count.Add(1)
	if n >= c.failOn {
		return nil, c.failErr
	}
	return c.base.RoundTrip(r)
}

// ─── ThreeXUIProvider.Fetch error paths ──────────────────────────────────────

func TestThreeXUIProvider_Fetch_LoginDoError(t *testing.T) {
	// Transport fails immediately → covers lines 64-66 (login c.Do error).
	p := &ThreeXUIProvider{
		cfg:    PaidProviderConfig{ID: "x", Name: "X", URL: "http://127.0.0.1:9"},
		client: &http.Client{Transport: &alwaysErrTransport{err: errors.New("conn refused")}},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when login Do fails")
	}
	t.Logf("OK: ThreeXUI login Do error → %v", err)
}

func TestThreeXUIProvider_Fetch_ListDoError(t *testing.T) {
	// Login succeeds (call 1), GET inbounds fails (call 2) → covers lines 75-77.
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer loginSrv.Close()

	ct := &countingTransport{
		base:    loginSrv.Client().Transport,
		failOn:  2, // fail on 2nd call
		failErr: errors.New("list request refused"),
	}
	p := &ThreeXUIProvider{
		cfg:    PaidProviderConfig{ID: "x2", Name: "X2", URL: loginSrv.URL},
		client: &http.Client{Transport: ct},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when list Do fails")
	}
	t.Logf("OK: ThreeXUI list Do error → %v", err)
}

func TestThreeXUIProvider_Fetch_ListJSONError(t *testing.T) {
	// Login succeeds; /panel/api/inbounds/list returns invalid JSON → covers lines 84-86.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
		default:
			w.Write([]byte("INVALID JSON {{{"))
		}
	}))
	defer srv.Close()

	p := &ThreeXUIProvider{
		cfg:    PaidProviderConfig{ID: "x3", Name: "X3", URL: srv.URL},
		client: srv.Client(),
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on JSON parse failure")
	}
	t.Logf("OK: ThreeXUI JSON parse error → %v", err)
}

// ─── MarzbanProvider.Fetch error paths ───────────────────────────────────────

func TestMarzbanProvider_Fetch_TokenDoError(t *testing.T) {
	// Transport fails → covers lines 141-143.
	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: "http://127.0.0.1:9"},
		client: &http.Client{Transport: &alwaysErrTransport{err: errors.New("refused")}},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when token Do fails")
	}
	t.Logf("OK: Marzban token Do error → %v", err)
}

func TestMarzbanProvider_Fetch_EmptyToken(t *testing.T) {
	// Token endpoint returns 200 but access_token = "" → covers lines 153-155.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": ""})
	}))
	defer srv.Close()

	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: srv.URL},
		client: srv.Client(),
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error for empty access_token")
	}
	t.Logf("OK: Marzban empty token → %v", err)
}

func TestMarzbanProvider_Fetch_InboundsDoError(t *testing.T) {
	// Token POST succeeds (call 1), inbounds GET fails (call 2) → covers lines 165-167.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	}))
	defer tokenSrv.Close()

	ct := &countingTransport{
		base:    tokenSrv.Client().Transport,
		failOn:  2,
		failErr: errors.New("inbounds refused"),
	}
	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: tokenSrv.URL},
		client: &http.Client{Transport: ct},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when inbounds Do fails")
	}
	t.Logf("OK: Marzban inbounds Do error → %v", err)
}

func TestMarzbanProvider_Fetch_InboundsHTTPError(t *testing.T) {
	// Token succeeds, inbounds returns 401 → covers lines 171-173.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/token" {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: srv.URL},
		client: srv.Client(),
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on inbounds HTTP 401")
	}
	t.Logf("OK: Marzban inbounds 401 → %v", err)
}

func TestMarzbanProvider_Fetch_InboundsJSONError(t *testing.T) {
	// Token succeeds, inbounds returns invalid JSON → covers lines 177-179.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/token" {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		w.Write([]byte("NOT JSON AT ALL {{{"))
	}))
	defer srv.Close()

	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: srv.URL},
		client: srv.Client(),
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on inbounds JSON parse failure")
	}
	t.Logf("OK: Marzban inbounds JSON error → %v", err)
}

// ─── HiddifyProvider.Fetch error paths ───────────────────────────────────────

func TestHiddifyProvider_Fetch_SubURLFromURLAndToken(t *testing.T) {
	// SubscriptionURL = "" → sub URL is built from URL + Token + "/sub/"  (lines 225-228).
	vlessURI := "vless://12345678-1234-1234-1234-123456789012@10.0.0.1:443?type=tcp#hid-tok"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(vlessURI))
	}))
	defer srv.Close()

	p := &HiddifyProvider{
		cfg: PaidProviderConfig{
			ID:    "hid-tok",
			Name:  "HiddifyToken",
			URL:   srv.URL,
			Token: "mytoken",
			// SubscriptionURL intentionally left empty
		},
		client: srv.Client(),
	}
	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Logf("OK: Hiddify sub from URL+Token → %d node(s)", len(nodes))
}

func TestHiddifyProvider_Fetch_DoError(t *testing.T) {
	// Transport fails → covers lines 238-240.
	p := &HiddifyProvider{
		cfg:    PaidProviderConfig{SubscriptionURL: "http://127.0.0.1:9/sub"},
		client: &http.Client{Transport: &alwaysErrTransport{err: errors.New("refused")}},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when Hiddify Do fails")
	}
	t.Logf("OK: Hiddify Do error → %v", err)
}

func TestHiddifyProvider_Fetch_Base64Body(t *testing.T) {
	// Response is base64-encoded → tryBase64Decode succeeds (lines 253-255).
	vlessURI := "vless://12345678-1234-1234-1234-123456789012@10.0.0.1:443?type=tcp#hid-b64"
	b64body := base64.StdEncoding.EncodeToString([]byte(vlessURI))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(b64body))
	}))
	defer srv.Close()

	p := &HiddifyProvider{
		cfg:    PaidProviderConfig{ID: "hid-b64", SubscriptionURL: srv.URL},
		client: srv.Client(),
	}
	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch base64 body: %v", err)
	}
	t.Logf("OK: Hiddify base64 body → %d node(s)", len(nodes))
}
