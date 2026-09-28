package leakguard

import "sync/atomic"

// enabled — atomic.Bool по той же причине, что в IPv6Guard: пишется в Enable/Disable, читается в
// IsEnabled/Status из разных горутин (Start||Stop движка). Гонка данных 2026-09-14.
type WebRTCGuard struct {
	enabled atomic.Bool
}

func NewWebRTCGuard() *WebRTCGuard {
	return &WebRTCGuard{}
}

func (g *WebRTCGuard) Enable() error {
	g.enabled.Store(true)
	return nil
}

func (g *WebRTCGuard) Disable() error {
	g.enabled.Store(false)
	return nil
}

func (g *WebRTCGuard) IsEnabled() bool {
	return g.enabled.Load()
}

// WebRTCStatus — честный статус WebRTC-защиты (T-13).
type WebRTCStatus struct {
	Enabled  bool   `json:"enabled"`
	Enforced string `json:"enforced"` // "partial" | "none" — НИКОГДА не "full"
	Note     string `json:"note"`
}

// Status возвращает ЧЕСТНЫЙ статус: APF не может закрыть WebRTC-утечку браузера из
// внешнего процесса, поэтому защита всегда лишь частичная (инструкции для браузера).
// T-13(б): не выдаём no-op-флаг за полноценную защиту. UI должен показывать "partial",
// а не "защищено".
func (g *WebRTCGuard) Status() WebRTCStatus {
	if !g.enabled.Load() {
		return WebRTCStatus{
			Enabled:  false,
			Enforced: "none",
			Note:     "WebRTC-защита выключена.",
		}
	}
	return WebRTCStatus{
		Enabled:  true,
		Enforced: "partial",
		Note: "APF не закрывает WebRTC-утечку браузера из внешнего процесса. " +
			"Примените инструкции для вашего браузера (см. browser-instructions) — " +
			"только они реально блокируют не-проксированный UDP/STUN.",
	}
}

type BrowserInstruction struct {
	Name   string   `json:"name"`
	Method string   `json:"method"`
	Steps  []string `json:"steps"`
}

func GetBrowserInstructions() map[string]BrowserInstruction {
	return map[string]BrowserInstruction{
		"chrome": {
			Name:   "Chrome",
			Method: "Extension",
			Steps: []string{
				"Install WebRTC Network Limiter extension",
				"Set IP handling policy to Disable non-proxied UDP",
				"Restart browser",
			},
		},
		"edge": {
			Name:   "Edge",
			Method: "Extension",
			Steps: []string{
				"Install WebRTC control extension",
				"Disable non-proxied UDP",
				"Restart browser",
			},
		},
		"brave": {
			Name:   "Brave",
			Method: "Internal settings",
			Steps: []string{
				"Open brave://settings/privacy",
				"Set WebRTC IP handling to Disable non-proxied UDP",
				"Restart browser",
			},
		},
		"firefox": {
			Name:   "Firefox",
			Method: "about:config",
			Steps: []string{
				"Open about:config",
				"Set media.peerconnection.enabled to false",
				"Restart browser",
			},
		},
	}
}

func GenerateFirefoxUserJS() string {
	return `// APF WebRTC hardening
user_pref("media.peerconnection.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("network.proxy.socks_remote_dns", true);
`
}
