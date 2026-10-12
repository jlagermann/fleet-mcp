package tools_test

import (
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleettest"
)

func TestSensorDiagnose(t *testing.T) {
	fm := fleettest.New(t)
	svc := func(id, status, msg string) map[string]any {
		return map[string]any{"id": id, "name": id, "status": status, "message": msg}
	}
	healthy := func(name, uid string) map[string]any {
		return map[string]any{"uid": uid, "name": name, "health.status": "healthy", "fleet.connected": true, "policy.id": 17.0, "policy.name": "lab",
			"configuration.apply.status": "success",
			"services.status":            []any{svc("ngs_status", "Running", ""), svc("ngs_upgrade_status", "Running", ""), svc("zeek", "Running", "")}}
	}
	broken := map[string]any{"uid": "0a-0b-0c-0d-0e-0f-10-11", "name": "Lab-Sensor3", "health.status": "failed", "fleet.connected": true,
		"policy.id": 17.0, "policy.name": "lab", "ping.last": "2026-10-12T12:18:37.372394621-05:00",
		"extendedinformation.status": map[string]any{"os.version": "29.2.2-ca1", "network.address.v4": "192.0.2.23", "doc-password": "leak-me"},
		"configuration.apply.status": "failed", "configuration.apply.error-message": "bad value", "configuration.apply.failed-fields": []any{"bro.site.local_nets"},
		"exceptions.current": map[string]any{"bro.export.files.enable": false},
		"exceptions.data":    map[string]any{"bro.export.files.enable": map[string]any{"created-by": "admin", "created-at": "2026-10-05T21:53:25Z"}},
		"services.status": []any{
			svc("ngs_status", "Warning", "info: Warning - ngs version '29.2.2-ca1 (5b2f93b4)' does not match deployed version '29.2.1-rc02+dev.1'"),
			svc("ngs_upgrade_status", "Failed", "NGS pre-flight checks failed. Contact Corelight Support."),
			svc("zeek", "Running", ""),
		}}
	other := healthy("Lab-Sensor1", "1a-1b-1c-1d-1e-1f-20-21")
	offline := map[string]any{"uid": "00000000-0000-4000-8000-000000000001", "name": "Lab-Soft", "health.status": "unknown", "fleet.connected": false,
		"ping.last": "2026-09-25T11:50:54.812537692-05:00"}
	fm.Route("GET /fleet/v1/sensor/catalog", map[string]any{"list": []any{broken, other, healthy("Lab-Sensor2", "2a-2b-2c-2d-2e-2f-30-31"), offline}})
	fm.Route("GET /fleet/v1/sensor-update/status", []any{map[string]any{"uid": "0a-0b-0c-0d-0e-0f-10-11", "message": "Update completed", "original_os": ":29.2.1-a2", "update_status": "idle"}})
	cs := session(t, fm)

	out, isErr := call(t, cs, "fm_sensor_diagnose", map[string]any{})
	if isErr {
		t.Fatal(out)
	}
	for _, want := range []string{
		`"deployed_ngs_version":"29.2.1-rc02+dev.1"`, "still runs NGS 29.2.1-rc02+dev.1",
		"NGS pre-flight checks failed", "only this sensor: running on the other 2 sensors",
		"2 other sensors on policy lab took the same update and are healthy",
		"the last configuration apply is failed: bad value", "bro.export.files.enable", "by admin",
		`"from":"29.2.1-a2"`, "fm_sensor_shell",
		"Lab-Soft", "not connected to Fleet Manager",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diagnosis lacks %q", want)
		}
	}
	if strings.Contains(out, "Lab-Sensor1\"") && strings.Contains(out, `"name":"Lab-Sensor1"`) {
		t.Error("a healthy sensor was diagnosed without being asked for")
	}
	if strings.Contains(out, "leak-me") {
		t.Error("diagnosis leaks a secret")
	}

	out, _ = call(t, cs, "fm_sensor_diagnose", map[string]any{"sensor": "Lab-Sensor1"})
	if !strings.Contains(out, "reports nothing wrong") {
		t.Errorf("healthy sensor: %s", out)
	}
}
