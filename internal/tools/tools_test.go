package tools_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
	"github.com/jlagermann/fleet-mcp/internal/spec"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

func session(t *testing.T, fm *fleettest.Server) *mcp.ClientSession {
	t.Helper()
	c, err := fleet.New(fleet.Options{
		BaseURL: fm.URL, Username: fleettest.Username, PasswordFile: fm.PasswordFile, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "fleet-mcp", Version: "test"}, &mcp.ServerOptions{Instructions: tools.Instructions})
	tools.Register(s, &tools.Deps{Client: c, Specs: spec.NewStore(t.TempDir(), c)})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError
}

func fakeFleet(t *testing.T) *fleettest.Server {
	fm := fleettest.New(t)
	fm.Route("GET /fleet/v1/info", map[string]any{"server_version": "29.2.2-1"})
	fm.Route("GET /fleet/v1/userinfo", map[string]any{"username": "claude", "permission_actions": "a,b,c"})
	fm.Route("GET /fleet/v1/sensor/catalog", map[string]any{
		"information": map[string]any{"total.count": 2},
		"list": []any{
			map[string]any{
				"uid": "0a-1b-2c-3d-4e-5f-60-71", "name": "Lab-Sensor1", "health.status": "healthy",
				"extendedinformation.status": map[string]any{"os.version": "29.2.2", "doc-password": "leak-me"},
				"tethering_token": "tok-leak", "services.failed": []any{},
			},
			map[string]any{"uid": "aa-bb-cc-dd-ee-ff-00-11", "name": "Lab-Sensor2", "health.status": "failure"},
		},
	})
	fm.Route("GET /fleet/v1/sensor/catalog/0a-1b-2c-3d-4e-5f-60-71", map[string]any{
		"information": map[string]any{
			"uid": "0a-1b-2c-3d-4e-5f-60-71", "name": "Lab-Sensor1",
			"services.status":            []any{map[string]any{"name": "Zeek", "status": "Running", "id": "z"}},
			"extendedinformation.status": map[string]any{"doc-password": "leak-me"},
		},
		"configuration.delta": map[string]any{},
	})
	fm.Route("GET /fleet/v1/diagnostic", []byte{0x1f, 0x8b, 0x08, 0x00})
	fm.Route("GET /fleet/v1/server/backup", make([]byte, 9<<20))
	fm.Route("HEAD /fleet/v1/server/backup", map[string]any{})
	fm.Route("GET /fleet/v1/server/backup/schedule", map[string]any{"enable": false})
	fm.Route("GET /fleet/v1/notifications", []any{
		map[string]any{"uid": "1", "type": "license", "severity": "failed", "timestamp": "2026-09-25T00:00:00Z", "dismissed": true},
		map[string]any{"uid": "2", "type": "disk", "severity": "warning", "timestamp": "2026-10-01T00:00:00Z", "dismissed": false},
	})
	return fm
}

func TestBackupsDoesNotDownloadImage(t *testing.T) {
	fm := fakeFleet(t)
	cs := session(t, fm)
	out, isErr := call(t, cs, "fm_backups", nil)
	if isErr || !strings.Contains(out, `"image":{`) || !strings.Contains(out, `"schedule":{"enable":false}`) {
		t.Fatalf("got %s", out)
	}
	for _, r := range fm.RequestLog() {
		if r == "GET /fleet/v1/server/backup" {
			t.Fatal("fm_backups downloaded the backup image")
		}
	}
	out, isErr = call(t, cs, "fm_api_get", map[string]any{"path": "/fleet/v1/server/backup"})
	if isErr || !strings.Contains(out, "larger than 8 MiB") {
		t.Fatalf("large download: %q", out)
	}
}

func TestNotifications(t *testing.T) {
	cs := session(t, fakeFleet(t))
	out, _ := call(t, cs, "fm_notifications", nil)
	if !strings.Contains(out, "2 notifications in total, 1 dismissed") || strings.Contains(out, `"uid":"1"`) || !strings.Contains(out, `"uid":"2"`) {
		t.Fatalf("got %s", out)
	}
	out, _ = call(t, cs, "fm_notifications", map[string]any{"include_dismissed": true, "severity": "failed"})
	if !strings.Contains(out, `"uid":"1"`) || strings.Contains(out, `"uid":"2"`) {
		t.Fatalf("got %s", out)
	}
}

func TestAllToolsReadOnly(t *testing.T) {
	cs := session(t, fakeFleet(t))
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) < 10 {
		t.Fatalf("only %d tools", len(res.Tools))
	}
	for _, tl := range res.Tools {
		if !strings.HasPrefix(tl.Name, "fm_") {
			t.Errorf("tool %s lacks fm_ prefix", tl.Name)
		}
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Errorf("tool %s is not marked read-only", tl.Name)
		}
	}
}

func TestSensorsListRedactsAndFilters(t *testing.T) {
	cs := session(t, fakeFleet(t))
	out, isErr := call(t, cs, "fm_sensors_list", map[string]any{"health": "failure"})
	if isErr || !strings.Contains(out, "Lab-Sensor2") || strings.Contains(out, "Lab-Sensor1") {
		t.Fatalf("filter: %s", out)
	}
	out, _ = call(t, cs, "fm_sensors_list", nil)
	if strings.Contains(out, "leak-me") || strings.Contains(out, "tok-leak") {
		t.Fatalf("secret leaked: %s", out)
	}
	if !strings.Contains(out, `"version":"29.2.2"`) {
		t.Fatalf("summary missing version: %s", out)
	}
}

func TestSensorGetByNameWithSelect(t *testing.T) {
	cs := session(t, fakeFleet(t))
	out, isErr := call(t, cs, "fm_sensor_get", map[string]any{"sensor": "lab-sensor1", "select": "/information/services.status", "fields": []any{"name", "status"}})
	if isErr || out != `[{"name":"Zeek","status":"Running"}]` {
		t.Fatalf("got %q (isErr %v)", out, isErr)
	}
	out, isErr = call(t, cs, "fm_sensor_get", map[string]any{"sensor": "nope"})
	if !isErr || !strings.Contains(out, "Lab-Sensor1") {
		t.Fatalf("unknown sensor: %q", out)
	}
	out, _ = call(t, cs, "fm_sensor_get", map[string]any{"sensor": "0a-1b-2c-3d-4e-5f-60-71"})
	if strings.Contains(out, "leak-me") {
		t.Fatalf("leaked: %s", out)
	}
}

func TestAPIGet(t *testing.T) {
	cs := session(t, fakeFleet(t))
	out, isErr := call(t, cs, "fm_api_get", map[string]any{"path": "/fleet/v1/info"})
	if isErr || !strings.Contains(out, "29.2.2-1") {
		t.Fatalf("got %q", out)
	}
	out, isErr = call(t, cs, "fm_api_get", map[string]any{"path": "/fleet/v1/logout"})
	if !isErr {
		t.Fatalf("logout allowed: %q", out)
	}
	out, isErr = call(t, cs, "fm_api_get", map[string]any{"path": "/fleet/v1/diagnostic"})
	if isErr || !strings.Contains(out, "binary response not returned") {
		t.Fatalf("binary: %q", out)
	}
	_, isErr = call(t, cs, "fm_api_get", map[string]any{"path": "/fleet/v1/missing"})
	if !isErr {
		t.Fatal("404 should be a tool error")
	}
}

func TestGraphQLQuery(t *testing.T) {
	cs := session(t, fakeFleet(t))
	out, isErr := call(t, cs, "fm_graphql_query", map[string]any{"query": "{ hello { message } }"})
	if isErr || out != `{"hello":{"message":"hi"}}` {
		t.Fatalf("got %q", out)
	}
	out, isErr = call(t, cs, "fm_graphql_query", map[string]any{"query": "mutation { deleteYaraSources(ids: [1]) }"})
	if !isErr || !strings.Contains(out, "queries only") {
		t.Fatalf("mutation allowed: %q", out)
	}
	out, isErr = call(t, cs, "fm_graphql_query", map[string]any{"query": "{ invalidField }"})
	if !isErr || !strings.Contains(out, "Cannot query field") {
		t.Fatalf("validation error: %q", out)
	}
}

func TestInfoAndDescribeWithoutSchemas(t *testing.T) {
	cs := session(t, fakeFleet(t))
	out, isErr := call(t, cs, "fm_info", nil)
	if isErr || !strings.Contains(out, `"permission_count":3`) || !strings.Contains(out, "unavailable") {
		t.Fatalf("info: %s", out)
	}
	out, isErr = call(t, cs, "fm_api_describe", map[string]any{"search": "policy"})
	if isErr || !strings.Contains(out, "does not expose its REST spec") {
		t.Fatalf("describe: %s", out)
	}
}

func TestCheckReadOnlyGraphQL(t *testing.T) {
	for doc, ok := range map[string]bool{
		"{ a }":                         true,
		"query Q { a }":                 true,
		"query A { a } query B { b }":   true,
		"mutation { x }":                false,
		"query A { a } mutation B { b }": false,
		"subscription { s }":            false,
		"{ unclosed":                    false,
		"":                              false,
	} {
		if err := tools.CheckReadOnlyGraphQL(doc); (err == nil) != ok {
			t.Errorf("CheckReadOnlyGraphQL(%q) = %v, want ok=%v", doc, err, ok)
		}
	}
}
