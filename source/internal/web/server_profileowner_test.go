package web

import "testing"

func TestProfileOwnerFromPath(t *testing.T) {
	cases := map[string]string{
		`C:\Users\Ivan\AppData\Roaming\APF\webui_token`:                       "Ivan",
		`C:\Windows\System32\config\systemprofile\AppData\Roaming\APF\x`: "",
		`C:\Users\Public\x`:                                                  "",
	}
	for p, want := range cases {
		if got := profileOwnerFromPath(p); got != want {
			t.Errorf("profileOwnerFromPath(%q) = %q, want %q", p, got, want)
		}
	}
}
