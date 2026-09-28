package version

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestVersionFormat_V14 checks that Version has a semver-like shape:
// MAJOR.MINOR.PATCH with an optional "-label" suffix (TZ v1.4 I-6: single
// source of truth for the project version).
func TestVersionFormat_V14(t *testing.T) {
	re := regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
	if !re.MatchString(Version) {
		t.Fatalf("Version %q does not look like semver (MAJOR.MINOR.PATCH[-label])", Version)
	}
}

// TestVersionSingleSource_V14 checks that other build artifacts which are
// supposed to mirror internal/version.Version actually do (TZ v1.4 I-6, I-9:
// "версия задаётся в одном месте, все потребители берут её оттуда").
//
// installer/apf.nsi lives inside this Go module (owned by lot L3-PC, read
// only here) and is always present in this checkout, so a mismatch there is
// a hard failure.
//
// android build.gradle lives outside this module, in a sibling directory
// that is not owned by this lot ("Android build.gradle — не в владении,
// только зафиксировать расхождение"). If it cannot be found at the expected
// relative path (e.g. a checkout that only contains the "source" tree) the
// cross-check is skipped rather than failed; if it IS found, a mismatch is
// still reported so future drift does not go unnoticed.
func TestVersionSingleSource_V14(t *testing.T) {
	nsiPath := filepath.Join("..", "..", "installer", "apf.nsi")
	data, err := os.ReadFile(nsiPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", nsiPath, err)
	}
	nsiRe := regexp.MustCompile(`(?m)^!define\s+APP_VERSION\s+"([^"]+)"`)
	m := nsiRe.FindSubmatch(data)
	if m == nil {
		t.Fatalf("APP_VERSION not found in %s", nsiPath)
	}
	if got := string(m[1]); got != Version {
		t.Errorf("installer/apf.nsi APP_VERSION=%q does not match internal/version.Version=%q", got, Version)
	}

	gradlePath := filepath.Join("..", "..", "..", "android", "android-project", "app", "build.gradle")
	gdata, gerr := os.ReadFile(gradlePath)
	if gerr != nil {
		t.Logf("android build.gradle not found at %s (outside this lot's ownership) - skipping cross-check: %v", gradlePath, gerr)
		return
	}
	gradleRe := regexp.MustCompile(`versionName\s+"([^"]+)"`)
	gm := gradleRe.FindSubmatch(gdata)
	if gm == nil {
		t.Logf("versionName not found in %s - skipping cross-check", gradlePath)
		return
	}
	if got := string(gm[1]); got != Version {
		t.Errorf("android build.gradle versionName=%q does not match internal/version.Version=%q (recorded mismatch, not fixable by this lot)", got, Version)
	}
}
