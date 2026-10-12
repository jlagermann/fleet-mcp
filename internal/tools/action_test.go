package tools

import (
	"strings"
	"testing"
)

func TestSensorActions(t *testing.T) {
	for name, a := range sensorActions {
		for _, bad := range []string{"factory", "shutdown", "flush", "stop", "configuration"} {
			if strings.Contains(a.cmd, bad) {
				t.Errorf("%s runs %q", name, a.cmd)
			}
		}
	}
	if _, ok := sensorActions["apply_updates"]; !ok || sensorActions["apply_updates"].dryRun {
		t.Error("apply_updates must not dry-run: a dry run of apply may still download updates")
	}

	busy := "  done_downloading   True\n  updating           True\n"
	idle := "  message            Update completed\n  updating           False\n"
	if b := actionBlockers("reboot", busy, "No entries."); len(b) != 1 || !strings.Contains(b[0], "in progress") {
		t.Errorf("reboot during an update: %v", b)
	}
	if b := actionBlockers("reboot", idle, "No entries."); len(b) != 0 {
		t.Errorf("reboot when idle: %v", b)
	}
	if b := actionBlockers("apply_updates", idle, "No entries."); len(b) != 1 || !strings.Contains(b[0], "no software updates are pending") {
		t.Errorf("apply with nothing pending: %v", b)
	}
	if b := actionBlockers("apply_updates", idle, "  version  29.2.3\n"); len(b) != 0 {
		t.Errorf("apply with an update pending: %v", b)
	}
}

func TestNewerThan(t *testing.T) {
	for _, c := range []struct {
		a, b      string
		newer, ok bool
	}{
		{"29.3.0-ca1", "29.2.2-1", true, true},
		{"29.2.2-ca1", "29.2.2-16847904621", false, true},
		{"29.2.1", "29.2.2-1", false, true},
		{"30.0.0", "29.9.9", true, true},
		{"", "29.2.2", false, false},
	} {
		if n, ok := newerThan(c.a, c.b); n != c.newer || ok != c.ok {
			t.Errorf("newerThan(%q, %q) = %v, %v", c.a, c.b, n, ok)
		}
	}
}
