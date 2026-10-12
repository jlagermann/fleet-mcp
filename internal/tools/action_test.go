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
