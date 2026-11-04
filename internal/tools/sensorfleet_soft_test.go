package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

// fm_sensor_fleet moves appliance sensors only; a Software Sensor is
// refused before any SSH.
func TestSensorFleetRefusesSoftwareSensor(t *testing.T) {
	fm := fleettest.New(t)
	fm.Route("GET /fleet/v1/sensor/catalog", map[string]any{"list": []any{map[string]any{
		"uid": "00000000-0000-4000-8000-000000000001", "name": "Lab-Soft", "fleet.connected": true,
		"extendedinformation.status": map[string]any{"platform": "Software Sensor", "network.address.v4": "192.0.2.20"}}}})
	store, err := secrets.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	deps := &tools.Deps{Fleets: fleets.NewStatic(conn(t, "lab", fm, false)), EnableWrites: true, Audit: log, Secrets: store}
	s := mcp.NewServer(&mcp.Implementation{Name: "fleet-mcp", Version: "test"}, nil)
	tools.Register(s, deps)
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	for _, action := range []string{"detach", "attach"} {
		out, isErr := call(t, cs, "fm_sensor_fleet", map[string]any{"fleet": "lab", "sensor": "Lab-Soft", "action": action})
		if !isErr || !strings.Contains(out, "is a Software Sensor") || !strings.Contains(out, "appliance sensors only") {
			t.Errorf("%s: %v %s", action, isErr, out)
		}
	}
}
