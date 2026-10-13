package tools_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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

func TestSupportAccessFleet(t *testing.T) {
	const uid = "0a-0b-0c-0d-0e-0f-10-11"
	fm := fleettest.New(t)
	fm.Route("GET /fleet/v1/sensor/catalog", map[string]any{"list": []any{map[string]any{"uid": uid, "name": "Lab-Sensor3",
		"health.status": "failed", "fleet.connected": true, "configuration.apply.status": "success"}}})
	fm.Route("GET /fleet/v1/sensor/instance/"+uid+"/api/configuration/exceptions", map[string]any{"bro.export.files.enable": false})
	applied := false
	var putBody string
	fm.Handle("PUT /fleet/v1/sensor/instance/"+uid+"/api/configuration", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		putBody, applied = string(b), true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	})
	fm.Handle("GET /fleet/v1/sensor/catalog/"+uid, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"configuration.live": map[string]any{"remote.enable": true, "remote.management": applied},
			"configuration.delta": map[string]any{"a": "", "b": ""}})
	})

	store, err := secrets.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	deps := &tools.Deps{Fleets: fleets.NewStatic(conn(t, "lab", fm, false), conn(t, "ro", fm, true)), EnableWrites: true, Audit: log, Secrets: store}
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

	for _, a := range []map[string]any{{"sensor": "Lab-Sensor3", "state": "maybe"}, {"sensor": "Lab-Sensor3", "state": "on", "method": "ssh"}} {
		if out, _ := call(t, cs, "fm_sensor_support_access", a); !strings.Contains(out, "must be") {
			t.Errorf("%v accepted: %s", a, out)
		}
	}

	// A read-only Fleet Manager refuses the fleet route.
	out, _ := call(t, cs, "fm_sensor_support_access", map[string]any{"fleet": "ro", "sensor": "Lab-Sensor3", "state": "on", "method": "fleet"})
	if !strings.Contains(out, `"ready":false`) || !strings.Contains(out, "read-only") || !strings.Contains(out, "use method sensor") {
		t.Fatalf("read-only fleet: %s", out)
	}

	args := map[string]any{"fleet": "lab", "sensor": "Lab-Sensor3", "state": "on"}
	out, isErr := call(t, cs, "fm_sensor_support_access", args)
	if isErr || !strings.Contains(out, `"method":"fleet"`) || !strings.Contains(out, `"device_uid":"`+uid+`"`) || !strings.Contains(out, "confirm_token") {
		t.Fatalf("preview: %s", out)
	}
	if applied {
		t.Fatal("the preview changed the sensor")
	}
	var p struct {
		Token string `json:"confirm_token"`
	}
	json.Unmarshal([]byte(out), &p)
	args["confirm_token"] = p.Token
	out, isErr = call(t, cs, "fm_sensor_support_access", args)
	if isErr || !applied || putBody != `{"remote.management":true}` || !strings.Contains(out, `"applied":true`) || !strings.Contains(out, "state off") {
		t.Fatalf("execute (body %s): %s", putBody, out)
	}
}
