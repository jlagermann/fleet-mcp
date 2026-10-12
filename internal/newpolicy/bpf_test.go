package newpolicy

import (
	"strings"
	"testing"
)

func TestCheckExclusionFilter(t *testing.T) {
	for _, ok := range []string{
		"tcp port 22",
		"tcp port 22 or net 192.168.0.0/16",
		"host 198.51.100.1 and net 203.0.113.0/24 and port 22",
		"src or dst host 10.1.1.1",
		"(dst and src net 10.0.0.0/8) and not port 53",
		"tcp portrange 1000-2000 or host backup-1.example.com",
	} {
		if p := CheckExclusionFilter(ok, true); len(p) > 0 {
			t.Errorf("%q: unexpected problems %v", ok, p)
		}
	}
	for filter, want := range map[string]string{
		"src host 10.1.1.1":              `leave out "src" (for example "host 10.1.1.1")`,
		"tcp and dst port 443":           `"dst port 443" is a one-direction filter`,
		"vlan 100 and host 10.1.1.1":     "VLAN tagging",
		"tcp[13] & 2 != 0":               "inside packets",
		"greater 1000":                   "packet length",
		"host 10.1.1.1 and src net 10/8": `"src net 10/8"`,
	} {
		got := strings.ToLower(strings.Join(CheckExclusionFilter(filter, true), "\n"))
		if !strings.Contains(got, strings.ToLower(want)) {
			t.Errorf("%q: got %q, want it to mention %q", filter, got, want)
		}
	}
	if p := CheckExclusionFilter("src host 10.1.1.1", false); len(p) > 0 {
		t.Errorf("restrictive BPF off: %v", p)
	}
	b := Build(Spec{Name: "x", Profile: NoProfile, TrafficFilter: "dst port 53"}, props(), nil)
	if !strings.Contains(strings.Join(b.Errors, " "), "one-direction") {
		t.Errorf("build errors %v", b.Errors)
	}
}
