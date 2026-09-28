package detector

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mockRoundTripper returns a successful 200 response for any request.
// Used to reach the resp.Body.Close() + "return false" path in isSNIBlocked.
type mockRoundTripper struct{}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func TestIsSNIBlocked_MockHTTPSuccess(t *testing.T) {
	d := New()
	d.httpClient = &http.Client{
		Transport: &mockRoundTripper{},
		Timeout:   3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Mock returns 200 → resp != nil → reaches resp.Body.Close() and "return false"
	result := d.isSNIBlocked(ctx)
	if result {
		t.Error("isSNIBlocked with mock 200 should return false")
	}
	t.Logf("OK: isSNIBlocked mock 200 → sniBlocked=%v", result)
}
