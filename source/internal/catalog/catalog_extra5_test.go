package catalog

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// ─── errBodyTransport — returns a 200 response with a body that errors on Read ──

type errBodyTransport struct{}

func (e *errBodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       &errReadCloser{},
		Header:     make(http.Header),
	}, nil
}

type errReadCloser struct{}

func (e *errReadCloser) Read(p []byte) (int, error) {
	return 0, errors.New("simulated read error")
}
func (e *errReadCloser) Close() error { return nil }

// ─── FreeSubscriptionProvider.Fetch: io.ReadAll error ────────────────────────

// TestFreeProvider_Fetch_ReadError covers providers.go line 101-103
// (the error path when io.ReadAll fails).
// We inject a custom RoundTripper that returns a 200 response whose body
// immediately errors on Read, triggering the `if err != nil` branch.
func TestFreeProvider_Fetch_ReadError(t *testing.T) {
	p := NewFreeProvider("test-read-err", "Test", "https://does-not-matter.example.com/sub")
	// Override the unexported client field (accessible within package catalog).
	p.client = &http.Client{Transport: &errBodyTransport{}}

	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected an error from ReadAll, got nil")
	}
	// Confirm the error message wraps the read failure.
	t.Logf("got expected error: %v", err)
}
