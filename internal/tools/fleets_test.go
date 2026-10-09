package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
	"github.com/jlagermann/fleet-mcp/internal/spec"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

func conn(t *testing.T, name string, fm *fleettest.Server, readOnly bool) *fleets.Conn {
	t.Helper()
	c, err := fleet.New(fleet.Options{BaseURL: fm.URL, Username: fleettest.Username, PasswordFile: fm.PasswordFile, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return &fleets.Conn{
		Fleet:  fleets.Fleet{Name: name, URL: fm.URL, Username: fleettest.Username, PasswordFile: fm.PasswordFile, ReadOnly: readOnly, Source: "test"},
		Client: c, Specs: spec.NewStore(t.TempDir(), c),
	}
}

// twoFleets serves "alpha" (writable) and "beta" (read-only), with no default.
func twoFleets(t *testing.T) (*mcp.ClientSession, *fleettest.Server, *fleettest.Server) {
	t.Helper()
	a, b := fakeFleet(t), fakeFleet(t)
	a.Route("GET /fleet/v1/sensor/catalog", map[string]any{"list": []any{map[string]any{"uid": "aa-aa-aa-aa-aa-aa-aa-aa", "name": "Alpha-Sensor"}}})
	b.Route("GET /fleet/v1/sensor/catalog", map[string]any{"list": []any{map[string]any{"uid": "bb-bb-bb-bb-bb-bb-bb-bb", "name": "Beta-Sensor"}}})
	b.Route("PUT /fleet/v1/sensor/policy/5", map[string]any{})
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	deps := &tools.Deps{Fleets: fleets.NewStatic(conn(t, "alpha", a, false), conn(t, "beta", b, true)), EnableWrites: true, Audit: log}
	s := mcp.NewServer(&mcp.Implementation{Name: "fleet-mcp", Version: "test"}, &mcp.ServerOptions{Instructions: tools.Instructions(true)})
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
	return cs, a, b
}

func TestFleetArgumentRoutes(t *testing.T) {
	cs, _, _ := twoFleets(t)
	out, isErr := call(t, cs, "fm_sensors_list", map[string]any{"fleet": "alpha"})
	if isErr || !strings.Contains(out, "Alpha-Sensor") || strings.Contains(out, "Beta-Sensor") {
		t.Fatalf("alpha: %s", out)
	}
	out, isErr = call(t, cs, "fm_sensors_list", map[string]any{"fleet": "beta"})
	if isErr || !strings.Contains(out, "Beta-Sensor") {
		t.Fatalf("beta: %s", out)
	}
	out, isErr = call(t, cs, "fm_sensors_list", nil)
	if !isErr || !strings.Contains(out, "alpha, beta") {
		t.Fatalf("no default should ask for a fleet: %s", out)
	}
	out, isErr = call(t, cs, "fm_sensors_list", map[string]any{"fleet": "gamma"})
	if !isErr || !strings.Contains(out, "unknown fleet") {
		t.Fatalf("unknown fleet: %s", out)
	}
}

func TestReadOnlyFleetRefusesWrites(t *testing.T) {
	cs, _, b := twoFleets(t)
	out, isErr := call(t, cs, "fm_api_write", map[string]any{"fleet": "beta", "method": "PUT", "path": "/fleet/v1/sensor/policy/5", "body": map[string]any{"x": 1}})
	if !isErr || !strings.Contains(out, "read-only") {
		t.Fatalf("read-only fleet accepted a write: %s", out)
	}
	if len(b.BodyLog()) != 0 {
		t.Fatal("request reached the read-only Fleet Manager")
	}
	// Reads still work there.
	if out, isErr := call(t, cs, "fm_info", map[string]any{"fleet": "beta"}); isErr || !strings.Contains(out, `"fleet":"beta"`) {
		t.Fatalf("read on read-only fleet: %s", out)
	}
}

func TestConfirmTokenBoundToFleet(t *testing.T) {
	cs, a, _ := twoFleets(t)
	a.Route("GET /fleet/v1/sensor/policy/5", map[string]any{"id": 5})
	a.Route("PUT /fleet/v1/sensor/policy/5", map[string]any{})
	p := preview(t, cs, "fm_api_write", map[string]any{"fleet": "alpha", "method": "PUT", "path": "/fleet/v1/sensor/policy/5", "body": map[string]any{"x": 1}})
	// The same token presented for another fleet (beta is read-only, so use
	// a fresh writable pair) must not execute: tokens include the host.
	if tools.ConfirmToken("other-host", "fm_api_write", "PUT", "/fleet/v1/sensor/policy/5", "", map[string]any{"x": 1}) == p["confirm_token"] {
		t.Fatal("token does not depend on the Fleet Manager")
	}
}

func TestFleetsTool(t *testing.T) {
	cs, _, _ := twoFleets(t)
	out, isErr := call(t, cs, "fm_fleets", map[string]any{"check": true})
	if isErr || !strings.Contains(out, `"name":"alpha"`) || !strings.Contains(out, `"name":"beta"`) ||
		!strings.Contains(out, `"read_only":true`) || !strings.Contains(out, `"version":"29.2.2-1"`) {
		t.Fatalf("fm_fleets: %s", out)
	}
}
