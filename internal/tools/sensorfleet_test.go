package tools

import (
	"strings"
	"testing"
)

func TestFleetSteps(t *testing.T) {
	detach := fleetSteps("detach", "", "")
	if len(detach) != 1 || !strings.HasSuffix(detach[0].cmd, "--fleet.enable=false") {
		t.Errorf("detach: %+v", detach)
	}
	attach := fleetSteps("attach", "CS", "fm.example:1443")
	if len(attach) != 3 {
		t.Fatalf("attach: %+v", attach)
	}
	if !strings.HasSuffix(attach[0].cmd, "--fleet.enable=false") || !strings.HasSuffix(attach[2].cmd, "--fleet.enable=true") {
		t.Errorf("attach must disable first and enable last: %+v", attach)
	}
	for _, want := range []string{"--fleet.community_string='CS'", "--fleet.server='fm.example:1443'", "--fleet.server_sslname=''"} {
		if !strings.Contains(attach[1].cmd, want) {
			t.Errorf("attach step 2 %q lacks %s", attach[1].cmd, want)
		}
	}
	for _, steps := range [][]sensorStep{detach, attach} {
		for _, s := range steps {
			for _, bad := range []string{"factory", "shutdown", "flush", "stop"} {
				if strings.Contains(s.cmd, bad) {
					t.Errorf("%s runs %q", s.label, s.cmd)
				}
			}
		}
	}
}
