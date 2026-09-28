//go:build windows

package killswitch

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// DEF-03: EnableWithUAC должен быть реализован и проходить через инъекционные швы.

func TestEnableWithUAC_NonAdmin_Success(t *testing.T) {
	origAdmin, origShell := isAdminFn, shellExecNetshFn
	defer func() { isAdminFn, shellExecNetshFn = origAdmin, origShell }()
	isAdminFn = func() bool { return false }
	var gotArgs string
	shellExecNetshFn = func(args string) error { gotArgs = args; return nil }

	ks := &windowsKS{}
	if err := ks.EnableWithUAC("203.0.113.7", 1080); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !ks.IsEnabled() {
		t.Error("expected enabled after success")
	}
	if !strings.Contains(gotArgs, "-f ") {
		t.Errorf("expected 'netsh -f <script>' invocation, got %q", gotArgs)
	}
}

func TestEnableWithUAC_UACCancelled(t *testing.T) {
	origAdmin, origShell := isAdminFn, shellExecNetshFn
	defer func() { isAdminFn, shellExecNetshFn = origAdmin, origShell }()
	isAdminFn = func() bool { return false }
	shellExecNetshFn = func(args string) error { return ErrUACCancelled }

	ks := &windowsKS{}
	err := ks.EnableWithUAC("", 1080)
	if !errors.Is(err, ErrUACCancelled) {
		t.Fatalf("expected ErrUACCancelled, got %v", err)
	}
	if ks.IsEnabled() {
		t.Error("must NOT be enabled after UAC cancel (fail-safe)")
	}
}

func TestEnableWithUAC_AdminPath_Success(t *testing.T) {
	origAdmin, origRun := isAdminFn, netshCombinedOutputFn
	defer func() { isAdminFn, netshCombinedOutputFn = origAdmin, origRun }()
	isAdminFn = func() bool { return true }
	ranNetsh := false
	netshCombinedOutputFn = func(cmd *exec.Cmd) ([]byte, error) { ranNetsh = true; return []byte("Ok."), nil }

	ks := &windowsKS{}
	if err := ks.EnableWithUAC("198.51.100.9", 443); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !ranNetsh {
		t.Error("expected direct netsh execution in admin path")
	}
	if !ks.IsEnabled() {
		t.Error("expected enabled after admin success")
	}
}

func TestEnableWithUAC_Error_NotEnabled(t *testing.T) {
	origAdmin, origShell := isAdminFn, shellExecNetshFn
	defer func() { isAdminFn, shellExecNetshFn = origAdmin, origShell }()
	isAdminFn = func() bool { return false }
	shellExecNetshFn = func(args string) error { return errors.New("netsh boom") }

	ks := &windowsKS{}
	if err := ks.EnableWithUAC("203.0.113.7", 1080); err == nil {
		t.Fatal("expected error")
	}
	if ks.IsEnabled() {
		t.Error("must NOT be enabled after error (fail-safe)")
	}
}

func TestBuildKSNetshScript_Content(t *testing.T) {
	s := buildKSNetshScript("203.0.113.7")
	for _, want := range []string{
		ksRuleName + "-allow-loopback",
		ksRuleName + "-allow-lan",
		ksRuleName + "-allow-vpn",
		ksRuleName + "-block-tcp",
		ksRuleName + "-block-udp",
		"remoteip=203.0.113.7",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q", want)
		}
	}
	// Строка delete -allow-vpn присутствует всегда (идемпотентная очистка),
	// а вот ADD-правило -allow-vpn должно отсутствовать при пустом vpnIP.
	if strings.Contains(buildKSNetshScript(""), "add rule name="+ksRuleName+"-allow-vpn") {
		t.Error("allow-vpn ADD rule must be absent when vpnIP empty")
	}
}
