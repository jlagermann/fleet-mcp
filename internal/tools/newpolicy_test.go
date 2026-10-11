package tools_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/newpolicy"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

func TestPolicyCreate(t *testing.T) {
	fm := fakeFleet(t)
	props := map[string]any{}
	for _, p := range newpolicy.Packages {
		props[p.Key] = map[string]any{}
	}
	for _, k := range []string{"security.ssh.enable", "security.http.enable", "corelight.ml.enable", "bro.pkgs.corelight.ml_package.loaded",
		"corelight.anomaly_detection.enable", "network.management.proxy.server", "network.management.proxy.username", "network.management.proxy.password",
		"network.management.ntp.server"} {
		props[k] = map[string]any{}
	}
	fm.Route("GET /fleet/v1/sensor/policy/metadata", map[string]any{"configuration.metadata": map[string]any{"properties": props}, "exporter.metadata": map[string]any{}})
	fm.Route("GET /fleet/v1/sensor/policy/list", []any{map[string]any{"id": 1, "name": "existing"}})
	fm.Route("POST /fleet/v1/sensor/policy/1/validation", map[string]any{"errors": map[string]any{}})
	fm.Route("POST /fleet/v1/sensor/policy", map[string]any{"id": 7})
	fm.Route("GET /fleet/v1/sensor/policy/7", map[string]any{"id": 7, "configuration": map[string]any{}})

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

	args := map[string]any{"fleet": "lab", "name": "edge", "profile": "north-south",
		"proxy_server": "http://proxy:3128", "proxy_username": "svc", "ntp_servers": "time.example.com"}
	out, isErr := call(t, cs, "fm_policy_create", args)
	if isErr || !strings.Contains(out, `"ready":false`) || !strings.Contains(out, "fleet-mcp secret set-setting network.management.proxy.password") {
		t.Fatalf("preview without the secret: %s", out)
	}
	if err := store.SetSetting("network.management.proxy.password", "Pr0xy-S3cret"); err != nil {
		t.Fatal(err)
	}
	out, isErr = call(t, cs, "fm_policy_create", args)
	if isErr || !strings.Contains(out, `"ready":true`) {
		t.Fatalf("preview: %s", out)
	}
	if strings.Contains(out, "Pr0xy-S3cret") {
		t.Fatal("preview shows the secret")
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(out), &p)
	for _, want := range []string{"security.ssh.enable", "corelight.anomaly_detection.enable", "Sliver", "left_at_default"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview lacks %s", want)
		}
	}
	args["confirm_token"] = p["confirm_token"]
	out, isErr = call(t, cs, "fm_policy_create", args)
	if isErr || !strings.Contains(out, `"policy_id":7`) {
		t.Fatalf("create: %s", out)
	}
	if !strings.Contains(strings.Join(fm.BodyLog(), "\n"), "Pr0xy-S3cret") {
		t.Error("the secret was not sent to Fleet Manager")
	}
	if store.HasSetting("network.management.proxy.password") {
		t.Error("used secret kept in the store")
	}
	if strings.Contains(out, "Pr0xy-S3cret") {
		t.Error("result shows the secret")
	}
}
