package detector

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ─── reusable mock transports ────────────────────────────────────────────────

// sniErrorTransport returns an error containing "tls" → isSNIBlocked returns true.
type sniErrorTransport struct{}

func (s *sniErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("tls: certificate verify failed")
}

// resetErrorTransport returns an error containing "connection reset" → isSNIBlocked true.
type resetErrorTransport struct{}

func (r *resetErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("read tcp: connection reset by peer")
}

// timeoutErrorTransport returns an error containing "timeout" → isSNIBlocked true.
type timeoutErrorTransport struct{}

func (t *timeoutErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: i/o timeout")
}

// okTransport returns HTTP 200 → isSNIBlocked returns false.
// Note: mockRoundTripper is already defined in detector_extra2_test.go.

// ─── Diagnose → BlockageDNS ──────────────────────────────────────────────────

func TestDiagnose_BlockageDNS(t *testing.T) {
	d := New()
	// TCP works, DNS fails
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return false }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageDNS {
		t.Errorf("expected BlockageDNS, got %s", bt)
	}
	t.Logf("OK: Diagnose → BlockageDNS")
}

// ─── Diagnose → BlockageSNI ──────────────────────────────────────────────────

func TestDiagnose_BlockageSNI_TLSError(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	d.httpClient = &http.Client{Transport: &sniErrorTransport{}, Timeout: 3 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageSNI {
		t.Errorf("expected BlockageSNI, got %s", bt)
	}
	t.Logf("OK: Diagnose → BlockageSNI (TLS error)")
}

func TestDiagnose_BlockageSNI_ConnectionReset(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	d.httpClient = &http.Client{Transport: &resetErrorTransport{}, Timeout: 3 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageSNI {
		t.Errorf("expected BlockageSNI, got %s", bt)
	}
	t.Logf("OK: Diagnose → BlockageSNI (connection reset)")
}

func TestDiagnose_BlockageSNI_Timeout(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	d.httpClient = &http.Client{Transport: &timeoutErrorTransport{}, Timeout: 3 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageSNI {
		t.Errorf("expected BlockageSNI, got %s", bt)
	}
	t.Logf("OK: Diagnose → BlockageSNI (timeout)")
}

// ─── Diagnose → BlockageIP ───────────────────────────────────────────────────

func TestDiagnose_BlockageIP(t *testing.T) {
	d := New()
	// TCP works for 1.1.1.1 but not for 8.8.8.8
	d.tcpDialer = func(ctx context.Context, addr string) bool {
		return !strings.HasPrefix(addr, "8.8.8.8")
	}
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	// HTTP 200 → SNI not blocked
	d.httpClient = &http.Client{
		Transport: &mockRoundTripper{},
		Timeout:   3 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageIP {
		t.Errorf("expected BlockageIP, got %s", bt)
	}
	t.Logf("OK: Diagnose → BlockageIP")
}

// ─── Diagnose → BlockageNone ─────────────────────────────────────────────────

func TestDiagnose_BlockageNone(t *testing.T) {
	d := New()
	// All network paths work
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	// HTTP 200 → SNI not blocked
	d.httpClient = &http.Client{
		Transport: &mockRoundTripper{},
		Timeout:   3 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageNone {
		t.Errorf("expected BlockageNone, got %s", bt)
	}
	t.Logf("OK: Diagnose → BlockageNone")
}

// ─── DiagnoseAndRecommend with injected hooks ────────────────────────────────

func TestDiagnoseAndRecommend_BlockageNone(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	d.httpClient = &http.Client{
		Transport: &mockRoundTripper{},
		Timeout:   3 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, strategy, report := d.DiagnoseAndRecommend(ctx)
	if bt != BlockageNone {
		t.Errorf("expected BlockageNone, got %s", bt)
	}
	if strategy.Primary == "" {
		t.Error("strategy.Primary must not be empty")
	}
	if report == "" {
		t.Error("report must not be empty")
	}
	t.Logf("OK: DiagnoseAndRecommend → BlockageNone, strategy=%s", strategy.Primary)
}

func TestDiagnoseAndRecommend_BlockageDNS(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	d.dnsResolver = func(ctx context.Context, domain string) bool { return false }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bt, strategy, report := d.DiagnoseAndRecommend(ctx)
	if bt != BlockageDNS {
		t.Errorf("expected BlockageDNS, got %s", bt)
	}
	if strategy.Primary == "" {
		t.Error("strategy.Primary must not be empty")
	}
	if report == "" {
		t.Error("report must not be empty")
	}
	t.Logf("OK: DiagnoseAndRecommend → BlockageDNS")
}

// ─── isSNIBlocked — error NOT matching SNI patterns ──────────────────────────

// genericErrorTransport returns a plain error not containing tls/reset/timeout.
type genericErrorTransport struct{}

func (g *genericErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("some generic network error")
}

func TestIsSNIBlocked_GenericError_ReturnsFalse(t *testing.T) {
	d := New()
	d.httpClient = &http.Client{
		Transport: &genericErrorTransport{},
		Timeout:   3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := d.isSNIBlocked(ctx)
	if result {
		t.Error("generic error (not tls/reset/timeout) should return false")
	}
	t.Logf("OK: isSNIBlocked generic error → false")
}

// ─── canTCPConnect — injection hook returns true ─────────────────────────────

func TestCanTCPConnect_InjectedTrue(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return true }
	ctx := context.Background()
	if !d.canTCPConnect(ctx, "any:address") {
		t.Error("injected tcpDialer returning true should make canTCPConnect return true")
	}
}

func TestCanTCPConnect_InjectedFalse(t *testing.T) {
	d := New()
	d.tcpDialer = func(ctx context.Context, addr string) bool { return false }
	ctx := context.Background()
	if d.canTCPConnect(ctx, "any:address") {
		t.Error("injected tcpDialer returning false should make canTCPConnect return false")
	}
}

// ─── canResolveDNS — injection hook ─────────────────────────────────────────

func TestCanResolveDNS_InjectedTrue(t *testing.T) {
	d := New()
	d.dnsResolver = func(ctx context.Context, domain string) bool { return true }
	ctx := context.Background()
	if !d.canResolveDNS(ctx, "any.domain") {
		t.Error("injected dnsResolver returning true should make canResolveDNS return true")
	}
}

func TestCanResolveDNS_InjectedFalse(t *testing.T) {
	d := New()
	d.dnsResolver = func(ctx context.Context, domain string) bool { return false }
	ctx := context.Background()
	if d.canResolveDNS(ctx, "any.domain") {
		t.Error("injected dnsResolver returning false should make canResolveDNS return false")
	}
}

// ─── buildReport via direct call — BlockageDeep path ─────────────────────────

func TestBuildReport_BlockageDeep(t *testing.T) {
	d := New()
	s := SelectStrategy(BlockageDeep)
	report := d.buildReport(BlockageDeep, s)
	if report == "" {
		t.Error("buildReport(BlockageDeep) returned empty string")
	}
	if !strings.Contains(report, s.Primary) {
		t.Errorf("report should contain primary strategy %q, got: %q", s.Primary, report)
	}
	t.Logf("OK: buildReport BlockageDeep → %q", report)
}

// ─── isSNIBlocked reads response body and closes it ─────────────────────────

// bodyReadTransport returns a 200 with a body to ensure resp.Body.Close() runs.
type bodyReadTransport struct{}

func (b *bodyReadTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("hello")),
	}, nil
}

func TestIsSNIBlocked_200WithBody_ReturnsFalse(t *testing.T) {
	d := New()
	d.httpClient = &http.Client{
		Transport: &bodyReadTransport{},
		Timeout:   3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := d.isSNIBlocked(ctx)
	if result {
		t.Error("200 response with body should return false (not SNI blocked)")
	}
	t.Logf("OK: isSNIBlocked 200 with body → false")
}
