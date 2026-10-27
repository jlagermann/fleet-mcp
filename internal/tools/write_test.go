package tools_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

func writeSession(t *testing.T) (*mcp.ClientSession, *fleettest.Server, string) {
	t.Helper()
	fm := fakeFleet(t)
	fm.Route("GET /fleet/v1/sensor/policy/5", map[string]any{
		"id": 5, "name": "lab", "description": "old", "configuration": map[string]any{"a": true, "b": "x"}, "groups": []any{},
	})
	fm.Route("PUT /fleet/v1/sensor/policy/5", map[string]any{"id": 5, "token": "resp-secret"})
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cs := sessionWith(t, fm, func(d *tools.Deps) {
		d.EnableWrites = true
		d.Audit = log
	})
	return cs, fm, logPath
}

func preview(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) map[string]any {
	t.Helper()
	out, isErr := call(t, cs, tool, args)
	if isErr {
		t.Fatalf("preview error: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("preview not JSON: %s", out)
	}
	if m["preview"] != true || m["confirm_token"] == "" {
		t.Fatalf("not a preview: %s", out)
	}
	return m
}

func countPrefix(ss []string, p string) int {
	n := 0
	for _, s := range ss {
		if strings.HasPrefix(s, p) {
			n++
		}
	}
	return n
}

func TestWriteToolsOnlyWhenEnabled(t *testing.T) {
	ro := session(t, fakeFleet(t))
	roTools, err := ro.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range roTools.Tools {
		if !tl.Annotations.ReadOnlyHint {
			t.Fatalf("read-only server registers %s", tl.Name)
		}
	}
	cs, _, _ := writeSession(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, tl := range res.Tools {
		if tl.Name == "fm_api_write" || tl.Name == "fm_graphql_mutate" {
			found++
			if tl.Annotations.ReadOnlyHint || tl.Annotations.DestructiveHint == nil || !*tl.Annotations.DestructiveHint {
				t.Errorf("%s annotations: %+v", tl.Name, tl.Annotations)
			}
		}
	}
	if found != 2 {
		t.Fatalf("write tools found: %d", found)
	}
}

func TestAPIWritePreviewConfirm(t *testing.T) {
	cs, fm, logPath := writeSession(t)
	args := map[string]any{
		"method": "PUT", "path": "/fleet/v1/sensor/policy/5",
		"body": map[string]any{"description": "new", "configuration": map[string]any{"a": false, "b": "x"}, "password": "hunter2"},
	}
	p := preview(t, cs, "fm_api_write", args)
	b, _ := json.Marshal(p)
	ps := string(b)
	for _, want := range []string{`"path":"/description"`, `"from":"old"`, `"to":"new"`, `"/configuration/a"`, "sensors in its groups receive the change", "omits"} {
		if !strings.Contains(ps, want) {
			t.Errorf("preview lacks %s: %s", want, ps)
		}
	}
	if strings.Contains(ps, "hunter2") {
		t.Errorf("preview leaks body secret: %s", ps)
	}
	if n := countPrefix(fm.BodyLog(), "PUT "); n != 0 {
		t.Fatalf("preview sent %d PUTs", n)
	}

	// A token for a different request is refused.
	bad := map[string]any{"method": "PUT", "path": "/fleet/v1/sensor/policy/5", "body": map[string]any{"description": "other"}, "confirm_token": p["confirm_token"]}
	if out, isErr := call(t, cs, "fm_api_write", bad); !isErr || !strings.Contains(out, "does not match") {
		t.Fatalf("mismatched token accepted: %s", out)
	}
	if n := countPrefix(fm.BodyLog(), "PUT "); n != 0 {
		t.Fatal("mismatched token sent a PUT")
	}

	args["confirm_token"] = p["confirm_token"]
	out, isErr := call(t, cs, "fm_api_write", args)
	if isErr || !strings.Contains(out, `"executed":true`) || strings.Contains(out, "resp-secret") {
		t.Fatalf("confirm: %s", out)
	}
	bodies := fm.BodyLog()
	if countPrefix(bodies, "PUT /fleet/v1/sensor/policy/5 ") != 1 || !strings.Contains(bodies[len(bodies)-1], `"description":"new"`) {
		t.Fatalf("bodies = %v", bodies)
	}

	// The token works once: a second confirmation needs a new preview.
	if out, isErr := call(t, cs, "fm_api_write", args); !isErr || !strings.Contains(out, "already used") {
		t.Fatalf("token reused: %s", out)
	}
	if n := countPrefix(fm.BodyLog(), "PUT "); n != 1 {
		t.Fatalf("reused token sent %d PUTs", n)
	}
	preview(t, cs, "fm_api_write", map[string]any{"method": args["method"], "path": args["path"], "body": args["body"]})
	if out, isErr := call(t, cs, "fm_api_write", args); isErr {
		t.Fatalf("confirm after a new preview: %s", out)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	if !strings.Contains(log, `"method":"PUT"`) || !strings.Contains(log, `"status":200`) || strings.Contains(log, "hunter2") || strings.Contains(log, "resp-secret") {
		t.Fatalf("audit log: %s", log)
	}
}

func TestAPIWriteGuards(t *testing.T) {
	cs, fm, _ := writeSession(t)
	for _, a := range []map[string]any{
		{"method": "GET", "path": "/fleet/v1/info"},
		{"method": "POST", "path": "/fleet/v1/current/password-reset"},
		{"method": "POST", "path": "/fleet/v1/logout"},
		{"method": "POST", "path": "/graph/query"},
		{"method": "DELETE", "path": "//evil/x"},
	} {
		if out, isErr := call(t, cs, "fm_api_write", a); !isErr {
			t.Errorf("%v allowed: %s", a, out)
		}
	}
	p := preview(t, cs, "fm_api_write", map[string]any{"method": "DELETE", "path": "/fleet/v1/token/global_key"})
	b, _ := json.Marshal(p["warnings"])
	if !strings.Contains(string(b), "revokes ALL sensor tokens") || !strings.Contains(string(b), "cannot be undone") {
		t.Fatalf("warnings = %s", b)
	}
	if len(fm.BodyLog()) != 0 {
		t.Fatal("guarded calls reached Fleet Manager")
	}
}

func TestGraphQLMutate(t *testing.T) {
	cs, fm, logPath := writeSession(t)
	if out, isErr := call(t, cs, "fm_graphql_mutate", map[string]any{"query": "{ hello { message } }"}); !isErr || !strings.Contains(out, "no mutation") {
		t.Fatalf("query accepted: %s", out)
	}
	q := `mutation Del($ids: [ID!]!) { deleteYaraSources(ids: $ids) }`
	vars := map[string]any{"ids": []any{"7"}}
	p := preview(t, cs, "fm_graphql_mutate", map[string]any{"query": q, "variables": vars})
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"mutations":["deleteYaraSources"]`) || !strings.Contains(string(b), "deletes data") {
		t.Fatalf("preview: %s", b)
	}
	if fm.LastGraphQL() != "" {
		t.Fatal("preview sent the mutation")
	}
	out, isErr := call(t, cs, "fm_graphql_mutate", map[string]any{"query": q, "variables": vars, "confirm_token": p["confirm_token"]})
	if isErr || !strings.Contains(out, `"executed":true`) || fm.LastGraphQL() != q {
		t.Fatalf("confirm: %s (sent %q)", out, fm.LastGraphQL())
	}
	raw, _ := os.ReadFile(logPath)
	if !strings.Contains(string(raw), "fm_graphql_mutate") {
		t.Fatalf("audit log: %s", raw)
	}
}

func TestConfirmTokenStable(t *testing.T) {
	a := tools.ConfirmToken("h", "t", "PUT", "/p", "", map[string]any{"b": 1, "a": 2})
	b := tools.ConfirmToken("h", "t", "PUT", "/p", "", map[string]any{"a": 2, "b": 1})
	c := tools.ConfirmToken("other", "t", "PUT", "/p", "", map[string]any{"a": 2, "b": 1})
	if a != b || a == c || len(a) != 16 {
		t.Fatalf("tokens %s %s %s", a, b, c)
	}
}
