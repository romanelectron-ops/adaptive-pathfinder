//go:build windows

package sysproxy

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// targetHive (P0.2, docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md) — служба (LocalSystem) под
// registry.CURRENT_USER жёстко попадала в куст SYSTEM (S-1-5-18), изолированный от профиля
// реального пользователя: запись «успешна», а браузер пользователя её не видел вообще. Дальше,
// если Kill Switch включён без TUN-режима, он душит весь трафик системы без единой рабочей цели.

func TestTargetHive_NotService_ReturnsCurrentUser(t *testing.T) {
	origSvc := isWindowsServiceFn
	defer func() { isWindowsServiceFn = origSvc }()
	isWindowsServiceFn = func() (bool, error) { return false, nil }

	base, prefix, err := targetHive()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base != registry.CURRENT_USER || prefix != "" {
		t.Errorf("got base=%v prefix=%q, want CURRENT_USER/\"\"", base, prefix)
	}
}

func TestTargetHive_Service_WithConsoleSession_ReturnsUsersHive(t *testing.T) {
	origSvc, origSID := isWindowsServiceFn, consoleUserSIDFn
	defer func() { isWindowsServiceFn, consoleUserSIDFn = origSvc, origSID }()
	isWindowsServiceFn = func() (bool, error) { return true, nil }
	consoleUserSIDFn = func() (string, error) { return "S-1-5-21-1-2-3-1001", nil }

	base, prefix, err := targetHive()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base != registry.USERS || prefix != `S-1-5-21-1-2-3-1001\` {
		t.Errorf("got base=%v prefix=%q, want USERS/SID+backslash", base, prefix)
	}
}

// Fail-closed: раньше setHTTPProxy()/disable() под службой без активной консольной сессии
// «успешно» писали в куст SYSTEM молча. Теперь — явная ошибка, не тихий no-op.
func TestTargetHive_Service_NoConsoleSession_ReturnsError(t *testing.T) {
	origSvc, origSID := isWindowsServiceFn, consoleUserSIDFn
	defer func() { isWindowsServiceFn, consoleUserSIDFn = origSvc, origSID }()
	isWindowsServiceFn = func() (bool, error) { return true, nil }
	consoleUserSIDFn = func() (string, error) { return "", errors.New("активной консольной сессии нет") }

	_, _, err := targetHive()
	if err == nil {
		t.Fatal("ожидалась явная ошибка при отсутствии консольной сессии под службой, получен nil")
	}
}
