package tools_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
	"github.com/jlagermann/fleet-mcp/internal/migrate"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

// migrateSession serves "alpha" (writable) and "beta" (read-only) with a
// packages directory holding one policy-only package named "pkg1".
func migrateSession(t *testing.T) (*mcp.ClientSession, *fleettest.Server, string) {
	t.Helper()
	a, b := fakeFleet(t), fakeFleet(t)
	pkgs := t.TempDir()
	m := migrate.Manifest{
		Format: migrate.Format, ExportedAt: time.Now().UTC(),
		Source: migrate.Source{Fleet: "beta", Version: "29.2.0-5", PolicyID: 3},
		Policy: migrate.Policy{Name: "lab", Configuration: map[string]any{"bro.analyzers.mqtt.enable": true}},
	}
	if err := os.MkdirAll(filepath.Join(pkgs, "pkg1"), 0o700); err != nil {
		t.Fatal(err)
	}
	mb, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(pkgs, "pkg1", migrate.ManifestFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	// pkg2 has an exporter, which alpha (no sensors) cannot take yet.
	m.Policy.Configuration = map[string]any{"bro.exporters.instances": "abcdefghij", "bro.exporters.abcdefghij.type": "hec", "bro.exporters.abcdefghij.name": "Splunk"}
	m.Features.Exporters = []string{"hec"}
	if err := os.MkdirAll(filepath.Join(pkgs, "pkg2"), 0o700); err != nil {
		t.Fatal(err)
	}
	mb, _ = json.Marshal(m)
	if err := os.WriteFile(filepath.Join(pkgs, "pkg2", migrate.ManifestFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	a.Route("GET /fleet/v1/sensor/policy/metadata", map[string]any{
		"configuration.metadata": map[string]any{"properties": map[string]any{"bro.analyzers.mqtt.enable": map[string]any{"cl:type": "Boolean"}}},
		"exporter.metadata":      map[string]any{},
	})
	a.Route("GET /fleet/v1/sensor/policy/list", []any{})
	a.Route("GET /fleet/v1/suricata/policies", []any{})
	a.Route("GET /fleet/v1/sensor/bundle", []any{})
	a.Route("GRAPHQL", map[string]any{"data": map[string]any{
		"yaraRulesets": map[string]any{"rulesets": []any{}}, "yaraSources": map[string]any{"sources": []any{}},
		"fileCollections": map[string]any{"collections": []any{}}, "fileSources": map[string]any{"sources": []any{}},
	}})
	a.Route("POST /fleet/v1/sensor/policy", map[string]any{"id": 9})
	a.Route("GET /fleet/v1/sensor/policy/9", map[string]any{"id": 9, "configuration": map[string]any{"bro.analyzers.mqtt.enable": true}})

	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	deps := &tools.Deps{Fleets: fleets.NewStatic(conn(t, "alpha", a, false), conn(t, "beta", b, true)),
		EnableWrites: true, Audit: log, PackagesDir: pkgs}
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
	t.Cleanup(func() { cs.Close() })
	return cs, a, log.Path()
}

func TestPolicyImportPreviewConfirm(t *testing.T) {
	cs, a, auditPath := migrateSession(t)
	args := map[string]any{"fleet": "alpha", "package": "pkg1", "name": "copied"}
	out, isErr := call(t, cs, "fm_policy_import", args)
	if isErr {
		t.Fatal(out)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if p["ready"] != true || p["confirm_token"] == nil {
		t.Fatalf("preview: %s", out)
	}
	for _, r := range a.RequestLog() {
		if strings.HasPrefix(r, "POST /fleet/v1/sensor/policy") {
			t.Fatal("preview created something")
		}
	}

	args["confirm_token"] = "wrong"
	if out, isErr := call(t, cs, "fm_policy_import", args); !isErr || !strings.Contains(out, "does not match") {
		t.Fatalf("wrong token: %s", out)
	}
	args["confirm_token"] = p["confirm_token"]
	out, isErr = call(t, cs, "fm_policy_import", args)
	if isErr || !strings.Contains(out, `"policy_id":9`) {
		t.Fatalf("confirm: %s", out)
	}
	if !strings.Contains(strings.Join(a.BodyLog(), "\n"), `"name":"copied"`) {
		t.Errorf("bodies %v", a.BodyLog())
	}
	if b, _ := os.ReadFile(auditPath); !strings.Contains(string(b), `"tool":"fm_policy_import"`) {
		t.Errorf("audit %s", b)
	}
}

func TestPolicyImportGuards(t *testing.T) {
	cs, _, _ := migrateSession(t)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"fm_policy_import", map[string]any{"fleet": "beta", "package": "pkg1"}, "read-only"},
		{"fm_policy_import", map[string]any{"fleet": "alpha", "package": "../pkg1"}, "invalid package name"},
		{"fm_policy_copy", map[string]any{"fleet": "alpha", "source_fleet": "beta", "policy": "lab", "confirm_token": "x"}, "needs the package"},
		{"fm_policy_copy", map[string]any{"fleet": "beta", "source_fleet": "alpha", "policy": "lab"}, "read-only"},
		{"fm_policy_copy", map[string]any{"fleet": "alpha", "source_fleet": "alpha", "policy": "lab"}, "same Fleet Manager"},
		{"fm_policy_copy", map[string]any{"fleet": "alpha", "source_fleet": "beta", "policy": "lab", "complete": true}, "fm_policy_import with complete"},
		{"fm_policy_import", map[string]any{"fleet": "alpha", "package": "pkg1", "complete": true}, "nothing to complete"},
	} {
		out, isErr := call(t, cs, tc.tool, tc.args)
		if !isErr || !strings.Contains(out, tc.want) {
			t.Errorf("%s %v: %s", tc.tool, tc.args, out)
		}
	}
}

func TestPolicyPackages(t *testing.T) {
	cs, _, _ := migrateSession(t)
	out, isErr := call(t, cs, "fm_policy_packages", nil)
	if isErr || !strings.Contains(out, `"package":"pkg1"`) || !strings.Contains(out, `"source_fleet":"beta"`) {
		t.Fatalf("packages: %s", out)
	}
}

func TestPolicyImportAsksAboutExporters(t *testing.T) {
	cs, _, _ := migrateSession(t)
	out, isErr := call(t, cs, "fm_policy_import", map[string]any{"fleet": "alpha", "package": "pkg2"})
	if isErr {
		t.Fatal(out)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if p["ready"] != false || p["confirm_token"] != nil || !strings.Contains(p["next"].(string), "Ask the user") || !strings.Contains(out, `"id":"exporters"`) {
		t.Fatalf("preview: %s", out)
	}
	out, isErr = call(t, cs, "fm_policy_import", map[string]any{"fleet": "alpha", "package": "pkg2", "exclude": []string{"exporters"}})
	if isErr || !strings.Contains(out, `"ready":true`) || !strings.Contains(out, "complete: true") {
		t.Fatalf("after yes: %s", out)
	}
}
