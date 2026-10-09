package spec

import (
	"os"
	"path/filepath"
	"testing"
)

// A tiny hand-written Swagger 2.0 document in Fleet Manager's style.
const restFixture = `{
 "swagger": "2.0",
 "paths": {
  "/fleet/v1/sensor/policy/{id}": {
   "get": {"summary": "get a sensor policy", "tags": ["policy"],
           "parameters": [{"name": "id", "in": "path", "type": "integer", "required": true}]},
   "put": {"summary": "update a sensor policy", "tags": ["policy"],
           "parameters": [{"name": "id", "in": "path", "type": "integer", "required": true},
                          {"name": "body", "in": "body", "schema": {"$ref": "#/definitions/rest.Policy"}}]}
  },
  "/fleet/v1/sensor/policy/list": {
   "get": {"summary": "list sensor policies", "tags": ["policy"]}
  },
  "/fleet/v1/server/backup/restore": {
   "post": {"summary": "restore a backup", "tags": ["backup"]}
  }
 }
}`

const gqlFixture = `{"data":{"__schema":{
 "queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
 "types":[
  {"kind":"OBJECT","name":"Query","fields":[
    {"name":"yaraSources","description":"list YARA sources","args":[{"name":"limit","type":{"kind":"SCALAR","name":"Int"}}],
     "type":{"kind":"NON_NULL","ofType":{"kind":"LIST","ofType":{"kind":"OBJECT","name":"YaraSource"}}}}]},
  {"kind":"OBJECT","name":"Mutation","fields":[
    {"name":"deleteYaraSources","args":[{"name":"ids","type":{"kind":"LIST","ofType":{"kind":"SCALAR","name":"ID"}}}],
     "type":{"kind":"SCALAR","name":"Boolean"}}]},
  {"kind":"OBJECT","name":"YaraSource","fields":[{"name":"id","args":[],"type":{"kind":"SCALAR","name":"ID"}}]},
  {"kind":"OBJECT","name":"__Type","fields":[]}
 ]}}}`

func TestRESTMatch(t *testing.T) {
	idx, err := ParseREST([]byte(restFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Ops) != 4 {
		t.Fatalf("ops = %d", len(idx.Ops))
	}
	if op := idx.Match("GET", "/fleet/v1/sensor/policy/17"); op == nil || op.Path != "/fleet/v1/sensor/policy/{id}" {
		t.Fatalf("templated match = %+v", op)
	}
	// The literal path wins over the {id} template.
	if op := idx.Match("get", "/fleet/v1/sensor/policy/list"); op == nil || op.Path != "/fleet/v1/sensor/policy/list" {
		t.Fatalf("literal match = %+v", op)
	}
	if op := idx.Match("DELETE", "/fleet/v1/sensor/policy/17"); op != nil {
		t.Fatalf("unexpected DELETE match %+v", op)
	}
	if ms := idx.PathKnown("/fleet/v1/server/backup/restore"); len(ms) != 1 || ms[0] != "POST" {
		t.Fatalf("PathKnown = %v", ms)
	}
	put := idx.Match("PUT", "/fleet/v1/sensor/policy/3")
	if put == nil || len(put.Params) != 2 || put.Params[1].Ref != "rest.Policy" {
		t.Fatalf("params = %+v", put)
	}
}

func TestRESTSearch(t *testing.T) {
	idx, _ := ParseREST([]byte(restFixture))
	if got := idx.Search("backup restore", 0); len(got) != 1 {
		t.Fatalf("search = %v", got)
	}
	if got := idx.Search("policy", 2); len(got) != 2 {
		t.Fatalf("limit not applied: %d", len(got))
	}
}

func TestGraphQL(t *testing.T) {
	g, err := ParseGraphQL([]byte(gqlFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Fields) != 2 {
		t.Fatalf("fields = %d", len(g.Fields))
	}
	f := g.Search("yara list", 0)
	if len(f) != 1 || f[0].Kind != "query" || f[0].Returns != "[YaraSource]!" || f[0].Args[0] != "limit: Int" {
		t.Fatalf("search = %+v", f)
	}
	if _, ok := g.Types["__Type"]; ok {
		t.Fatal("introspection types should be skipped")
	}
	if names := g.TypeNames("yara"); len(names) != 1 || names[0] != "YaraSource" {
		t.Fatalf("TypeNames = %v", names)
	}
}

func TestFromDirPrefersVersion(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"rest-29.1.0-1.json", "rest-29.2.2-5.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(restFixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{dir: dir, version: "29.2.2-5"}
	_, src, err := s.fromDir("rest")
	if err != nil || src != "file "+filepath.Join(dir, "rest-29.2.2-5.json") {
		t.Fatalf("src = %q, err = %v", src, err)
	}
	s.version = "30.0.0-1"
	_, src, err = s.fromDir("rest")
	if err != nil || src == "" {
		t.Fatalf("fallback: %q %v", src, err)
	}
}

func TestFileName(t *testing.T) {
	if got := FileName("rest", "29.2.2-168/x"); got != "rest-29.2.2-168_x.json" {
		t.Fatalf("got %q", got)
	}
}
