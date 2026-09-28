package config

import (
	"errors"
	"testing"
)

// ── DataDir android branch ────────────────────────────────────────────────────

func TestDataDir_Android_WithEnvVar(t *testing.T) {
	orig := runtimeGOOS
	defer func() { runtimeGOOS = orig }()

	runtimeGOOS = "android"
	t.Setenv("APF_DATA_DIR", "/custom/android/path")

	dir := DataDir()
	if dir != "/custom/android/path" {
		t.Errorf("expected /custom/android/path, got %q", dir)
	}
}

func TestDataDir_Android_NoEnvVar(t *testing.T) {
	orig := runtimeGOOS
	defer func() { runtimeGOOS = orig }()

	runtimeGOOS = "android"
	t.Setenv("APF_DATA_DIR", "")

	dir := DataDir()
	if dir != "/data/data/com.apf.app/files" {
		t.Errorf("expected default android path, got %q", dir)
	}
}

// ── DataDir default (linux/macOS) branch ─────────────────────────────────────

func TestDataDir_Default_Linux(t *testing.T) {
	orig := runtimeGOOS
	defer func() { runtimeGOOS = orig }()

	runtimeGOOS = "linux"
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir() must not be empty for linux")
	}
	// Should end in .config/apf
	if len(dir) < 10 {
		t.Errorf("DataDir() seems too short for linux: %q", dir)
	}
}

// ── BinDir error path ─────────────────────────────────────────────────────────

func TestBinDir_ExecutableError(t *testing.T) {
	orig := osExecutableFn
	defer func() { osExecutableFn = orig }()

	osExecutableFn = func() (string, error) {
		return "", errors.New("injected executable error")
	}

	dir := BinDir()
	if dir != "./bin" {
		t.Errorf("expected fallback './bin', got %q", dir)
	}
}
