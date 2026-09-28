package relay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ExitCredentials — exit-id + relay-token одной пары, персистентно хранимая на диске
// (docs/TZ_APF_RELAY_v1.0.md §2.1, §3). Общий для Windows (internal/engine) и Android
// (mobile/androidbridge) формат: обе платформы читают/пишут один и тот же JSON под своим
// путём (config.DataDir()/server_relay_credentials.json) — раньше это были две копии одной
// и той же логики load-or-generate-and-save.
type ExitCredentials struct {
	ExitID     string `json:"exit_id"`
	RelayToken string `json:"relay_token"`
}

// EnsureExitCredentials загружает сохранённую пару exit-id/relay-token по path, либо
// генерирует новую (GenerateExitCredentials) и сохраняет её при первом использовании
// relay-режима. relay-token — секрет: файл создаётся с правами 0600.
func EnsureExitCredentials(path string) (exitID, relayToken string, err error) {
	if data, readErr := os.ReadFile(path); readErr == nil {
		var creds ExitCredentials
		if err := json.Unmarshal(data, &creds); err == nil && creds.ExitID != "" && creds.RelayToken != "" {
			return creds.ExitID, creds.RelayToken, nil
		}
	}
	exitID, relayToken, err = GenerateExitCredentials()
	if err != nil {
		return "", "", fmt.Errorf("EnsureExitCredentials: %w", err)
	}
	data, err := json.MarshalIndent(ExitCredentials{ExitID: exitID, RelayToken: relayToken}, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("EnsureExitCredentials: сериализация: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", "", fmt.Errorf("EnsureExitCredentials: каталог данных: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", "", fmt.Errorf("EnsureExitCredentials: сохранение: %w", err)
	}
	return exitID, relayToken, nil
}
