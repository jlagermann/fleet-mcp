package tools

import (
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleets"
)

func TestMaintTargetRefusesReadOnly(t *testing.T) {
	d := &Deps{Fleets: fleets.NewStatic(
		&fleets.Conn{Fleet: fleets.Fleet{Name: "prod", URL: "https://198.51.100.7", ReadOnly: true, Source: "fleets.json"}},
		&fleets.Conn{Fleet: fleets.Fleet{Name: "lab", URL: "https://198.51.100.8:8443"}},
	)}
	for _, a := range []maintArgs{{Host: "198.51.100.7"}, {Fleet: "prod"}, {Fleet: "lab", Host: "198.51.100.7"}} {
		if _, _, err := d.maintTarget(a); err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Errorf("%+v: err = %v", a, err)
		}
	}
	h, f, err := d.maintTarget(maintArgs{Fleet: "lab"})
	if err != nil || h != "198.51.100.8" || f == nil || f.Name != "lab" {
		t.Fatalf("lab: %q %+v %v", h, f, err)
	}
	h, f, err = d.maintTarget(maintArgs{Host: "198.51.100.8"})
	if err != nil || f == nil || f.Name != "lab" || h != "198.51.100.8" {
		t.Fatalf("by host: %q %+v %v", h, f, err)
	}
	if _, f, err = d.maintTarget(maintArgs{Host: "198.51.100.9"}); err != nil || f != nil {
		t.Fatalf("unknown host: %+v %v", f, err)
	}
	if _, _, err = d.maintTarget(maintArgs{}); err == nil {
		t.Fatal("no host or fleet accepted")
	}
}
