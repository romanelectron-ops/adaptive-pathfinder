package detector

import (
	"testing"
)

// ── BlockageType.String ───────────────────────────────────────────────────────

func TestBlockageType_String(t *testing.T) {
	tests := []struct {
		b    BlockageType
		want string
	}{
		{BlockageNone, "none"},
		{BlockageDNS, "dns"},
		{BlockageIP, "ip"},
		{BlockageSNI, "sni"},
		{BlockageDeep, "deep_dpi"},
		{BlockageComplete, "complete"},
		{BlockageType(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.b.String()
		if got != tt.want {
			t.Errorf("BlockageType(%d).String() = %q, want %q", int(tt.b), got, tt.want)
		}
	}
}

// ── SelectStrategy ────────────────────────────────────────────────────────────

func TestSelectStrategy_None(t *testing.T) {
	s := SelectStrategy(BlockageNone)
	if s.Primary == "" {
		t.Error("BlockageNone strategy Primary should not be empty")
	}
	if s.UseReality || s.UseChain {
		t.Error("BlockageNone should not use Reality or chain")
	}
	if s.Reason == "" {
		t.Error("strategy should have a reason")
	}
}

func TestSelectStrategy_DNS(t *testing.T) {
	s := SelectStrategy(BlockageDNS)
	if s.Primary == "" {
		t.Error("DNS strategy Primary should not be empty")
	}
	if s.Reason == "" {
		t.Error("DNS strategy should have a reason")
	}
	if s.Fallback == "" {
		t.Error("DNS strategy should have a fallback")
	}
}

func TestSelectStrategy_IP(t *testing.T) {
	s := SelectStrategy(BlockageIP)
	if !s.UseCDN {
		t.Error("IP blockage should recommend CDN")
	}
}

func TestSelectStrategy_SNI(t *testing.T) {
	s := SelectStrategy(BlockageSNI)
	if !s.UseReality {
		t.Error("SNI blockage should recommend Reality")
	}
	if s.Primary == "" {
		t.Error("SNI strategy Primary should not be empty")
	}
}

func TestSelectStrategy_Deep(t *testing.T) {
	s := SelectStrategy(BlockageDeep)
	if !s.UseReality && !s.UseChain {
		t.Error("deep DPI should use Reality or chain")
	}
}

func TestSelectStrategy_Complete(t *testing.T) {
	s := SelectStrategy(BlockageComplete)
	if s.Fallback == "" {
		t.Error("complete blockage should have fallback strategy")
	}
	if s.Primary == "" {
		t.Error("complete blockage should have primary strategy")
	}
}

func TestSelectStrategy_AllHaveRequiredFields(t *testing.T) {
	blockageTypes := []BlockageType{
		BlockageNone, BlockageDNS, BlockageIP,
		BlockageSNI, BlockageDeep, BlockageComplete,
	}
	for _, bt := range blockageTypes {
		s := SelectStrategy(bt)
		if s.Reason == "" {
			t.Errorf("SelectStrategy(%s) has empty Reason", bt)
		}
		if s.Primary == "" {
			t.Errorf("SelectStrategy(%s) has empty Primary", bt)
		}
		if s.Fallback == "" {
			t.Errorf("SelectStrategy(%s) has empty Fallback", bt)
		}
	}
}

// ── buildReport (через DiagnoseAndRecommend) ──────────────────────────────────
// buildReport приватная, тестируем косвенно через DiagnoseAndRecommend
// (передаём пресинтез, игнорируем ошибки сети — тест просто проверяет что не паникует)

func TestBuildReport_ViaSelectStrategy(t *testing.T) {
	d := New()
	blockageTypes := []BlockageType{
		BlockageNone, BlockageDNS, BlockageIP,
		BlockageSNI, BlockageDeep, BlockageComplete,
	}
	for _, bt := range blockageTypes {
		s := SelectStrategy(bt)
		report := d.buildReport(bt, s)
		if report == "" {
			t.Errorf("buildReport for %s returned empty string", bt)
		}
	}
}

// ── GoodRealitySNI ───────────────────────────────────────────────────────────

func TestGoodRealitySNI_NotEmpty(t *testing.T) {
	if len(GoodRealitySNI) == 0 {
		t.Error("GoodRealitySNI list should not be empty")
	}
	for _, sni := range GoodRealitySNI {
		if sni == "" {
			t.Error("GoodRealitySNI contains empty string")
		}
		hasDot := false
		for _, c := range sni {
			if c == '.' {
				hasDot = true
				break
			}
		}
		if !hasDot {
			t.Errorf("GoodRealitySNI entry %q is not a valid domain", sni)
		}
	}
}

func TestGoodRealitySNI_NoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, sni := range GoodRealitySNI {
		if seen[sni] {
			t.Errorf("duplicate SNI entry: %s", sni)
		}
		seen[sni] = true
	}
}

// ── New ───────────────────────────────────────────────────────────────────────

func TestNew_NotNil(t *testing.T) {
	d := New()
	if d == nil {
		t.Fatal("New() returned nil")
	}
}

// ── Strategy constants ────────────────────────────────────────────────────────

func TestBlockageConstants_Order(t *testing.T) {
	// Проверяем что константы имеют ожидаемые значения для сериализации
	if BlockageNone != 0 {
		t.Errorf("BlockageNone should be 0, got %d", BlockageNone)
	}
	if BlockageDNS != 1 {
		t.Errorf("BlockageDNS should be 1, got %d", BlockageDNS)
	}
	if BlockageSNI != 3 {
		t.Errorf("BlockageSNI should be 3, got %d", BlockageSNI)
	}
	if BlockageComplete != 5 {
		t.Errorf("BlockageComplete should be 5, got %d", BlockageComplete)
	}
}
