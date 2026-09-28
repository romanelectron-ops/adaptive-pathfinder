package killswitch

import (
	"strings"
	"testing"
)

// B-0402.4 · Я-41.2 — чистый план WFP-фильтров (тестируется на любой ОС).

func specByName(specs []wfpFilterSpec, name string) *wfpFilterSpec {
	for i := range specs {
		if specs[i].Name == name {
			return &specs[i]
		}
	}
	return nil
}

func TestWFPBuildPlan_FullSet(t *testing.T) {
	specs := wfpBuildPlan("203.0.113.7", 0x1234)
	// обязателен block-all
	block := specByName(specs, ksRuleName+"-block-all")
	if block == nil || block.Action != wfpActionBlock {
		t.Fatal("block-all filter missing")
	}
	// permit loopback/vpn/tun присутствуют
	for _, n := range []string{"-permit-loopback", "-permit-vpn-0", "-permit-tun", "-permit-lan-0"} {
		if specByName(specs, ksRuleName+n) == nil {
			t.Errorf("missing filter %q", ksRuleName+n)
		}
	}
	// все permit имеют вес СТРОГО больше block
	for _, s := range specs {
		if s.Action == wfpActionPermit && s.Weight <= block.Weight {
			t.Errorf("permit %q weight %d must be > block weight %d", s.Name, s.Weight, block.Weight)
		}
	}
}

func TestWFPBuildPlan_NoVPN_NoTUN(t *testing.T) {
	specs := wfpBuildPlan("", 0)
	if specByName(specs, ksRuleName+"-permit-vpn-0") != nil {
		t.Error("permit-vpn must be absent when vpnIP empty")
	}
	if specByName(specs, ksRuleName+"-permit-tun") != nil {
		t.Error("permit-tun must be absent when LUID=0")
	}
	if specByName(specs, ksRuleName+"-permit-loopback") == nil || specByName(specs, ksRuleName+"-block-all") == nil {
		t.Error("loopback and block-all must always be present")
	}
}

func TestWFPBuildPlan_VPNAddr(t *testing.T) {
	specs := wfpBuildPlan("1.2.3.4", 0)
	v := specByName(specs, ksRuleName+"-permit-vpn-0")
	if v == nil {
		t.Fatal("permit-vpn missing")
	}
	if v.Condition.Kind != wfpCondRemoteAddrV4Equal || v.Condition.Addr != 0x01020304 {
		t.Errorf("vpn cond = kind %d addr %#x, want equal 0x01020304", v.Condition.Kind, v.Condition.Addr)
	}
}

func TestWFPBuildPlan_V6Set(t *testing.T) {
	specs := wfpBuildPlan("203.0.113.7", 0x1234)
	// v6-фильтры присутствуют и помечены V6
	for _, n := range []string{"-permit-loopback6", "-permit-lan6-0", "-permit-tun6", "-block-all6"} {
		s := specByName(specs, ksRuleName+n)
		if s == nil {
			t.Errorf("missing v6 filter %q", ksRuleName+n)
			continue
		}
		if !s.V6 {
			t.Errorf("filter %q must have V6=true", s.Name)
		}
	}
	// loopback6 = ::1/128
	lb := specByName(specs, ksRuleName+"-permit-loopback6")
	if lb.Condition.Kind != wfpCondRemoteAddrV6Range || lb.Condition.Prefix6 != 128 || lb.Condition.Addr6[15] != 1 {
		t.Errorf("loopback6 cond = %+v, want ::1/128", lb.Condition)
	}
}

func TestWFPVpnSpecs(t *testing.T) {
	// v4
	v4 := wfpVpnSpecs("1.2.3.4")
	if len(v4) != 1 || v4[0].Name != ksRuleName+"-permit-vpn-0" || v4[0].V6 || v4[0].Condition.Addr != 0x01020304 {
		t.Errorf("v4 vpn specs wrong: %+v", v4)
	}
	// v6
	v6 := wfpVpnSpecs("2001:db8::1")
	if len(v6) != 1 || v6[0].Name != ksRuleName+"-permit-vpn6-0" || !v6[0].V6 || v6[0].Condition.Prefix6 != 128 {
		t.Errorf("v6 vpn specs wrong: %+v", v6)
	}
	if v6[0].Condition.Addr6[0] != 0x20 || v6[0].Condition.Addr6[1] != 0x01 || v6[0].Condition.Addr6[15] != 0x01 {
		t.Errorf("v6 vpn addr bytes wrong: %v", v6[0].Condition.Addr6)
	}
	// empty / invalid
	if wfpVpnSpecs("") != nil || wfpVpnSpecs("not-an-ip") != nil {
		t.Error("empty/invalid vpnIP must yield nil specs")
	}
}

func TestWFPBuildPlan_V6VPN(t *testing.T) {
	specs := wfpBuildPlan("2001:db8::99", 0)
	if specByName(specs, ksRuleName+"-permit-vpn6-0") == nil {
		t.Error("v6 vpnIP must produce permit-vpn6")
	}
	if specByName(specs, ksRuleName+"-permit-vpn-0") != nil {
		t.Error("v6 vpnIP must NOT produce v4 permit-vpn")
	}
}

// R-2.3 (C-5): узел с несколькими A/AAAA-записями → permit-фильтр на КАЖДЫЙ адрес,
// имена уникальны, все начинаются с wfpVpnNamePrefix (по нему их снимает targeted-switch).
func TestWFPVpnSpecs_MultiFamily(t *testing.T) {
	specs := wfpVpnSpecs("1.2.3.4,5.6.7.8,2001:db8::1")
	if len(specs) != 3 {
		t.Fatalf("got %d specs, want 3: %+v", len(specs), specs)
	}
	names := map[string]bool{}
	nV4, nV6 := 0, 0
	for _, s := range specs {
		if names[s.Name] {
			t.Errorf("duplicate filter name %q", s.Name)
		}
		names[s.Name] = true
		if !strings.HasPrefix(s.Name, wfpVpnNamePrefix) {
			t.Errorf("name %q must start with %q (targeted-switch removes by prefix)", s.Name, wfpVpnNamePrefix)
		}
		if s.V6 {
			nV6++
		} else {
			nV4++
		}
	}
	if nV4 != 2 || nV6 != 1 {
		t.Errorf("families: v4=%d v6=%d, want 2/1", nV4, nV6)
	}
}

func TestCidrToRange(t *testing.T) {
	cases := []struct {
		cidr       string
		addr, mask uint32
	}{
		{"127.0.0.0/8", 0x7F000000, 0xFF000000},
		{"10.0.0.0/8", 0x0A000000, 0xFF000000},
		{"172.16.0.0/12", 0xAC100000, 0xFFF00000},
		{"192.168.0.0/16", 0xC0A80000, 0xFFFF0000},
		{"169.254.0.0/16", 0xA9FE0000, 0xFFFF0000},
	}
	for _, c := range cases {
		r := cidrToRange(c.cidr)
		if r.addr != c.addr || r.mask != c.mask {
			t.Errorf("%s -> addr %#x mask %#x, want %#x/%#x", c.cidr, r.addr, r.mask, c.addr, c.mask)
		}
	}
}
