package iprep

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── checkIPAPI mock tests ──────────────────────────────────────────────────────

func TestCheckIPAPI_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"proxy":       false,
			"hosting":     false,
			"isp":         "Test ISP",
			"org":         "Test Org",
			"asname":      "AS12345",
			"countryCode": "US",
			"query":       "1.2.3.4",
		})
	}))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	c := newTestChecker()
	info, err := c.checkIPAPI(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("checkIPAPI: unexpected error: %v", err)
	}
	if info.ISP != "Test ISP" {
		t.Errorf("ISP = %q, want %q", info.ISP, "Test ISP")
	}
	if info.Country != "US" {
		t.Errorf("Country = %q, want %q", info.Country, "US")
	}
	if info.Source != "ip-api.com" {
		t.Errorf("Source = %q, want %q", info.Source, "ip-api.com")
	}
	if info.IsDatacenter {
		t.Error("IsDatacenter should be false")
	}
}

func TestCheckIPAPI_ProxyHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"proxy":       true,
			"hosting":     true,
			"isp":         "DigitalOcean",
			"org":         "DigitalOcean LLC",
			"asname":      "AS14061",
			"countryCode": "US",
			"query":       "8.8.8.8",
		})
	}))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	c := newTestChecker()
	info, err := c.checkIPAPI(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsProxy {
		t.Error("IsProxy should be true")
	}
	if !info.IsDatacenter {
		t.Error("IsDatacenter should be true")
	}
	if info.RiskScore < 40 {
		t.Errorf("RiskScore = %d, want >= 40 for datacenter proxy", info.RiskScore)
	}
}

func TestCheckIPAPI_FailStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "fail",
			"message": "invalid query",
		})
	}))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	c := newTestChecker()
	_, err := c.checkIPAPI(context.Background(), "999.999.999.999")
	if err == nil {
		t.Error("expected error for status=fail, got nil")
	}
}

func TestCheckIPAPI_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json at all{{{")
	}))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	c := newTestChecker()
	_, err := c.checkIPAPI(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("expected error for bad JSON, got nil")
	}
}

// ── checkProxyCheck mock tests ─────────────────────────────────────────────────

func TestCheckProxyCheck_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"1.2.3.4": map[string]interface{}{
				"proxy":        "no",
				"vpn":          "no",
				"type":         "Residential",
				"isp":          "TestISP",
				"asn":          "AS123",
				"country":      "RU",
				"organisation": "TestOrg",
			},
		})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	info, err := c.checkProxyCheck(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("checkProxyCheck: unexpected error: %v", err)
	}
	if info.ISP != "TestISP" {
		t.Errorf("ISP = %q, want %q", info.ISP, "TestISP")
	}
	if info.Country != "RU" {
		t.Errorf("Country = %q, want %q", info.Country, "RU")
	}
	if !info.IsResidential {
		t.Error("IsResidential should be true for type=Residential")
	}
	if info.Source != "proxycheck.io" {
		t.Errorf("Source = %q, want %q", info.Source, "proxycheck.io")
	}
}

func TestCheckProxyCheck_Datacenter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"5.5.5.5": map[string]interface{}{
				"proxy":        "yes",
				"vpn":          "yes",
				"type":         "Datacenter",
				"isp":          "Hetzner",
				"asn":          "AS24940",
				"country":      "DE",
				"organisation": "Hetzner Online GmbH",
			},
		})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	info, err := c.checkProxyCheck(context.Background(), "5.5.5.5")
	if err != nil {
		t.Fatalf("checkProxyCheck: unexpected error: %v", err)
	}
	if !info.IsDatacenter {
		t.Error("IsDatacenter should be true for type=Datacenter")
	}
	if !info.IsProxy {
		t.Error("IsProxy should be true for proxy=yes")
	}
	if !info.IsVPN {
		t.Error("IsVPN should be true for vpn=yes")
	}
}

func TestCheckProxyCheck_Business(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"3.3.3.3": map[string]interface{}{
				"proxy":        "no",
				"vpn":          "no",
				"type":         "Business",
				"isp":          "Corp ISP",
				"asn":          "AS999",
				"country":      "US",
				"organisation": "Corp",
			},
		})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	info, err := c.checkProxyCheck(context.Background(), "3.3.3.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.IsDatacenter {
		t.Error("IsDatacenter should be false for type=Business")
	}
}

func TestCheckProxyCheck_WithAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"1.1.1.1": map[string]interface{}{
				"proxy": "no", "vpn": "no", "type": "Residential",
				"isp": "ISP", "asn": "AS1", "country": "US", "organisation": "Org",
			},
		})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	c.SetAPIKey("mykey123")
	_, err := c.checkProxyCheck(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotKey != "mykey123" {
		t.Errorf("API key in request = %q, want %q", gotKey, "mykey123")
	}
}

func TestCheckProxyCheck_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error"})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	_, err := c.checkProxyCheck(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("expected error for status=error, got nil")
	}
}

func TestCheckProxyCheck_NoIPData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	_, err := c.checkProxyCheck(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("expected error when IP data missing, got nil")
	}
}

func TestCheckProxyCheck_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{{invalid json")
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	_, err := c.checkProxyCheck(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("expected error for bad JSON, got nil")
	}
}

// ── Full CheckIP via mock API ──────────────────────────────────────────────────

func TestCheckIP_ViaMockAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"proxy":       false,
			"hosting":     false,
			"isp":         "Home ISP",
			"org":         "Home Org",
			"asname":      "AS11111",
			"countryCode": "RU",
			"query":       "10.0.0.1",
		})
	}))
	defer srv.Close()

	orig := ipAPIBaseURL
	ipAPIBaseURL = srv.URL
	defer func() { ipAPIBaseURL = orig }()

	c := newTestChecker()
	info, err := c.CheckIP(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if info.Source != "ip-api.com" {
		t.Errorf("Source = %q, want ip-api.com", info.Source)
	}

	// Second call should return from cache
	info2, err := c.CheckIP(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("CheckIP (cached): %v", err)
	}
	if info2.IP != info.IP {
		t.Error("cached result differs")
	}
}

func TestCheckIP_FallbackToProxyCheck(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "fail"})
	}))
	defer ipSrv.Close()

	pcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"2.2.2.2": map[string]interface{}{
				"proxy": "no", "vpn": "no", "type": "Residential",
				"isp": "FallbackISP", "asn": "AS222", "country": "DE",
				"organisation": "FallbackOrg",
			},
		})
	}))
	defer pcSrv.Close()

	origIPAPI := ipAPIBaseURL
	origPC := proxyCheckBaseURL
	ipAPIBaseURL = ipSrv.URL
	proxyCheckBaseURL = pcSrv.URL
	defer func() {
		ipAPIBaseURL = origIPAPI
		proxyCheckBaseURL = origPC
	}()

	c := newTestChecker()
	info, err := c.CheckIP(context.Background(), "2.2.2.2")
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if info.Source != "proxycheck.io" {
		t.Errorf("Source = %q, want proxycheck.io (fallback)", info.Source)
	}
}

func TestCheckIP_BothFail(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ipSrv.Close()

	pcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer pcSrv.Close()

	origIPAPI := ipAPIBaseURL
	origPC := proxyCheckBaseURL
	ipAPIBaseURL = ipSrv.URL
	proxyCheckBaseURL = pcSrv.URL
	defer func() {
		ipAPIBaseURL = origIPAPI
		proxyCheckBaseURL = origPC
	}()

	c := newTestChecker()
	c.client = &http.Client{Timeout: 2 * time.Second}

	info, err := c.CheckIP(context.Background(), "3.3.3.3")
	if err != nil {
		t.Fatalf("CheckIP should not return error on both-fail: %v", err)
	}
	if info.Source != "unavailable" {
		t.Errorf("Source = %q, want unavailable", info.Source)
	}
}

func TestCheckProxyCheck_HostingType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"9.9.9.9": map[string]interface{}{
				"proxy":        "no",
				"vpn":          "no",
				"type":         "Hosting",
				"isp":          "SomeHost",
				"asn":          "AS9999",
				"country":      "US",
				"organisation": "SomeHosting Inc",
			},
		})
	}))
	defer srv.Close()

	orig := proxyCheckBaseURL
	proxyCheckBaseURL = srv.URL
	defer func() { proxyCheckBaseURL = orig }()

	c := newTestChecker()
	info, err := c.checkProxyCheck(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsHosting {
		t.Error("IsHosting should be true for type=Hosting")
	}
}
