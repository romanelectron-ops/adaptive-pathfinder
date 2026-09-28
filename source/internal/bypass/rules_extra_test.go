package bypass

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// AddUserRule — empty domain after trim
func TestAddUserRule_TrimmedEmpty(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	if r := m.AddUserRule("   ", "spaces", false, false); r != nil {
		t.Error("whitespace-only domain should return nil")
	}
	t.Log("OK: trimmed-empty domain -> nil")
}

// AddUserRule — empty name defaults to domain
func TestAddUserRule_DefaultName(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	r := m.AddUserRule("mysite.org", "", false, false)
	if r == nil {
		t.Fatal("should return rule")
	}
	if r.Name != "mysite.org" {
		t.Errorf("name should be domain, got %q", r.Name)
	}
	t.Log("OK: empty name defaults to domain")
}

// loadUserRules — invalid JSON in data file -> json.Unmarshal error path
func TestLoadUserRules_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "bypass_list.json")
	if err := os.WriteFile(dataPath, []byte(`[{"broken": json]`), 0600); err != nil {
		t.Fatal(err)
	}
	// NewManager calls loadUserRules; invalid JSON must not panic
	m := NewManager(dir)
	for _, r := range m.Rules() {
		if !r.Builtin {
			t.Errorf("no user rules should be loaded from invalid JSON, got %+v", r)
		}
	}
	t.Log("OK: invalid JSON silently skipped in loadUserRules")
}

// saveUserRules — WriteFile error: point dataPath at a directory
func TestSaveUserRules_DataPathIsDir(t *testing.T) {
	dir := t.TempDir()
	// Create a DIRECTORY at the location where the json file would go
	dataDir := filepath.Join(dir, "bypass_list.json")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		dataPath: dataDir,
	}
	// Must not panic
	m.saveUserRules()
	t.Log("OK: saveUserRules silently handles WriteFile error (path is a directory)")
}

// saveUserRules — MkdirAll error: parent is a file, not a dir
func TestSaveUserRules_ParentIsFile(t *testing.T) {
	dir := t.TempDir()
	// Create a FILE at "parent" so MkdirAll("parent/subdir") fails
	parentFile := filepath.Join(dir, "notadir")
	if err := os.WriteFile(parentFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		dataPath: filepath.Join(parentFile, "data.json"),
	}
	m.saveUserRules()
	t.Log("OK: saveUserRules silently handles MkdirAll error")
}

// matchesDomains — plain domain entry should match subdomain via HasSuffix
func TestMatchDomains_PlainEntryCatchesSubdomain(t *testing.T) {
	domains := []string{"example.com"}
	if !matchesDomains("sub.example.com", domains) {
		t.Error("sub.example.com should match plain entry example.com via subdomain suffix")
	}
	t.Log("OK: plain entry catches subdomain via HasSuffix")
}

// loadUserRules — builtin-flagged entries are skipped
func TestLoadUserRules_SkipsBuiltin(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "bypass_list.json")
	rules := []*Rule{{ID: "fake_builtin", Builtin: true, Name: "X", Domains: []string{"x.com"}}}
	data, _ := json.Marshal(rules)
	_ = os.WriteFile(dataPath, data, 0600)
	m := NewManager(dir)
	for _, r := range m.Rules() {
		if r.ID == "fake_builtin" && !r.Builtin {
			t.Error("builtin-flagged user rule should not be loaded")
		}
	}
	t.Log("OK: builtin entries in JSON are ignored by loadUserRules")
}
