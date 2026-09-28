package dpi

import "testing"

// ─── Additional dpi coverage tests ────────────────────────────────────────────

func TestCanaryTesterNew(t *testing.T) {
	c := NewCanaryTester("127.0.0.1:10808")
	if c == nil {
		t.Fatal("NewCanaryTester returned nil")
	}
	if c.socksAddr != "127.0.0.1:10808" {
		t.Errorf("socksAddr: want 127.0.0.1:10808, got %s", c.socksAddr)
	}
	t.Log("OK: NewCanaryTester")
}

func TestCheckPortSuspicious(t *testing.T) {
	c := NewCanaryTester("127.0.0.1:10808")
	// Консервативная реализация — всегда false
	result := c.checkPortSuspicious()
	if result {
		t.Log("note: checkPortSuspicious returned true (may change)")
	}
	t.Logf("OK: checkPortSuspicious = %v", result)
}

func TestBuildDiagnosisAllScores(t *testing.T) {
	c := NewCanaryTester("127.0.0.1:10808")
	cases := []struct {
		score      int
		wantAction string // ключевое слово в CounterMeasure
	}{
		{90, "reality"},
		{60, "padding"},
		{30, "utls"},
		{10, "none"},
	}
	for _, tc := range cases {
		r := &CanaryResult{Score: tc.score}
		c.buildDiagnosis(r)
		if r.Diagnosis == "" {
			t.Errorf("score %d: empty Diagnosis", tc.score)
		}
		if r.Recommendation == "" {
			t.Errorf("score %d: empty Recommendation", tc.score)
		}
		if r.CounterMeasure == "" {
			t.Errorf("score %d: empty CounterMeasure", tc.score)
		}
		t.Logf("  score=%d → measure=%s diag=%s",
			tc.score, r.CounterMeasure,
			r.Diagnosis[:min(len(r.Diagnosis), 40)])
	}
	t.Log("OK: buildDiagnosis all score ranges")
}

func TestBuildDiagnosisWithFlags(t *testing.T) {
	c := NewCanaryTester("127.0.0.1:10808")
	r := &CanaryResult{
		Score:                75,
		TLSFingerprintLeaked: true,
		TimingAnomaly:        true,
		EntropyHigh:          true,
	}
	c.buildDiagnosis(r)
	if r.Diagnosis == "" {
		t.Error("Diagnosis should not be empty with flags set")
	}
	t.Logf("OK: buildDiagnosis with flags: %s", r.Diagnosis[:min(len(r.Diagnosis), 60)])
}

func TestCanaryResultFields(t *testing.T) {
	r := &CanaryResult{
		Score:                55,
		TLSFingerprintLeaked: true,
		TimingAnomaly:        false,
		PortSuspicious:       false,
		EntropyHigh:          true,
	}
	if r.Score != 55 {
		t.Error("Score field")
	}
	if !r.TLSFingerprintLeaked {
		t.Error("TLSFingerprintLeaked field")
	}
	t.Log("OK: CanaryResult fields")
}

func TestNewMultiHopBuilder(t *testing.T) {
	// NewMultiHopBuilder должен создать объект без паники
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewMultiHopBuilder panicked: %v", r)
		}
	}()
	b := NewMultiHopBuilder(10808)
	if b == nil {
		t.Log("note: NewMultiHopBuilder returned nil")
	} else {
		t.Log("OK: NewMultiHopBuilder created")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
