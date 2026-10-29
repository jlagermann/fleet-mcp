package policyedit_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
)

// fakeFM models the policy, group, catalog, bundle, Suricata and
// collection APIs the way Fleet Manager 29.2 behaved in testing: a policy
// PUT merges configuration and null deletes a key; a group PUT merges.
type fakeFM struct {
	*fleettest.Server
	client *fleet.Client

	next        int64
	props       map[string]any
	pkgsMeta    []any
	policies    map[int64]map[string]any
	groups      map[int64]map[string]any
	sensors     []map[string]any
	bundles     map[int64]map[string]any
	suricata    map[int64]map[string]any
	rulesets    map[int64]string
	collections map[int64]map[string]any
	deleted     []string

	// For fm_collection_manage: file sources (with "type"), YARA sources,
	// each ruleset's source ids, and the mutations received.
	fileSources []map[string]any
	yaraSources []map[string]any
	rulesetSrc  map[int64][]int64
	mutations   []string
}

func newFake(t *testing.T) *fakeFM {
	t.Helper()
	f := &fakeFM{Server: fleettest.New(t), next: 100,
		props: map[string]any{
			"bro.analyzers.modbus.enable":            map[string]any{"cl:type": "Boolean", "cl:default": "1"},
			"bro.analyzers.mqtt.enable":              map[string]any{"cl:type": "Boolean", "cl:default": "0"},
			"bro.site.local_nets":                    map[string]any{"cl:type": "NetworkList", "cl:default": "10.0.0.0/8", "cl:multiValuedCSV": true},
			"suricata.enable":                        map[string]any{"cl:type": "Boolean", "cl:default": "1", "cl:internalController": "system.license.suricata.active"},
			"corelight.yara.enable":                  map[string]any{"cl:type": "Boolean", "cl:default": "0", "cl:internalController": "system.license.yara.active"},
			"proxy.password":                         map[string]any{"cl:type": "Password", "writeOnly": true},
			"bro.pkgs.corelight.ja4.loaded":          map[string]any{"cl:type": "Boolean", "cl:default": "0"},
			"bro.pkgs.corelight.dga_detector.loaded": map[string]any{"cl:type": "Boolean", "cl:default": "1"},
		},
		pkgsMeta: []any{
			map[string]any{"name": "corelight:ja4", "package_name": "JA4"},
			map[string]any{"name": "corelight:dga-detector", "package_name": "DGA Detector"},
		},
		policies: map[int64]map[string]any{}, groups: map[int64]map[string]any{}, bundles: map[int64]map[string]any{},
		suricata: map[int64]map[string]any{}, rulesets: map[int64]string{}, collections: map[int64]map[string]any{},
		rulesetSrc: map[int64][]int64{}}
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		f.Handle(m+" /fleet/v1/", f.rest)
	}
	f.Handle("POST /graph/query", f.graphql)
	c, err := fleet.New(fleet.Options{BaseURL: f.URL, Username: fleettest.Username, PasswordFile: f.PasswordFile, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	f.client = c
	return f
}

func (f *fakeFM) id() int64 { f.next++; return f.next }

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ordered(m map[int64]map[string]any) []any {
	out := []any{}
	for i := int64(0); i <= 1000 && len(out) < len(m); i++ {
		if v, ok := m[i]; ok {
			out = append(out, v)
		}
	}
	return out
}

func (f *fakeFM) groupOut(g map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range g {
		out[k] = v
	}
	var sensors []any
	for _, s := range f.sensors {
		if s["group.id"] == g["id"] {
			sensors = append(sensors, map[string]any{"uid": s["uid"], "name": s["name"]})
		}
	}
	out["sensors"] = sensors
	if pid, ok := g["policy.id"].(int64); ok && pid > 0 {
		out["policy.name"] = f.policies[pid]["name"]
	}
	return out
}

func (f *fakeFM) rest(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/fleet/v1")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	id, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	var body any
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	bm, _ := body.(map[string]any)
	m := r.Method
	switch {
	case m == "GET" && p == "/sensor/policy/list":
		reply(w, 200, ordered(f.policies))
	case m == "POST" && strings.HasSuffix(p, "/validation"):
		errs := map[string]any{}
		for k, v := range bm["config"].(map[string]any) {
			prop, _ := f.props[k].(map[string]any)
			switch {
			case prop == nil:
				errs[k] = "unrecognized configuration settings"
			case prop["cl:type"] == "Boolean":
				if _, ok := v.(bool); !ok {
					errs[k] = "incorrect type, expected Boolean"
				}
			}
		}
		reply(w, 200, map[string]any{"errors": errs})
	case strings.HasPrefix(p, "/sensor/policy/") && id > 0:
		pol := f.policies[id]
		if pol == nil {
			reply(w, 404, map[string]any{"message": "Not Found"})
			return
		}
		switch m {
		case "GET":
			out := map[string]any{"configuration.metadata": map[string]any{"properties": f.props}, "packages.metadata": f.pkgsMeta}
			for k, v := range pol {
				out[k] = v
			}
			reply(w, 200, out)
		case "PUT":
			for k, v := range bm {
				if k == "configuration" {
					cfg, _ := pol["configuration"].(map[string]any)
					if cfg == nil {
						cfg = map[string]any{}
					}
					for ck, cv := range v.(map[string]any) {
						if cv == nil {
							delete(cfg, ck)
						} else {
							cfg[ck] = cv
						}
					}
					pol["configuration"] = cfg
					continue
				}
				pol[k] = v
			}
			pol["record.updated-at"] = "later"
			reply(w, 200, map[string]any{"configuration.delta": bm["configuration"]})
		case "DELETE":
			delete(f.policies, id)
			f.deleted = append(f.deleted, fmt.Sprintf("policy %d", id))
			w.WriteHeader(204)
		}
	case m == "GET" && p == "/sensor/group/list":
		var out []any
		for _, g := range ordered(f.groups) {
			out = append(out, f.groupOut(g.(map[string]any)))
		}
		reply(w, 200, out)
	case m == "POST" && p == "/sensor/group":
		gid := f.id()
		g := map[string]any{"id": gid, "name": bm["name"], "description": bm["description"]}
		if v, ok := bm["policy.id"].(float64); ok {
			g["policy.id"] = int64(v)
		}
		f.groups[gid] = g
		reply(w, 200, map[string]any{"id": gid})
	case strings.HasPrefix(p, "/sensor/group/") && id > 0:
		g := f.groups[id]
		switch m {
		case "PUT":
			for k, v := range bm {
				if k == "id" {
					continue
				}
				if k == "policy.id" {
					if n, ok := v.(float64); ok && n > 0 {
						g[k] = int64(n)
					} else {
						g[k] = int64(0)
					}
					continue
				}
				g[k] = v
			}
			reply(w, 200, map[string]any{})
		case "DELETE":
			delete(f.groups, id)
			for _, s := range f.sensors {
				if s["group.id"] == id {
					s["group.id"] = int64(0)
				}
			}
			w.WriteHeader(204)
		}
	case m == "GET" && p == "/sensor/catalog":
		var list []any
		for _, s := range f.sensors {
			list = append(list, s)
		}
		reply(w, 200, map[string]any{"list": list})
	case m == "PUT" && p == "/sensor/catalog":
		for _, x := range body.([]any) {
			mv := x.(map[string]any)
			for _, s := range f.sensors {
				if s["uid"] == mv["uid"] {
					s["group.id"] = int64(mv["group.id"].(float64))
				}
			}
		}
		w.WriteHeader(204)
	case m == "GET" && p == "/sensor/bundle":
		reply(w, 200, ordered(f.bundles))
	case strings.HasPrefix(p, "/sensor/bundle/") && id > 0:
		if m == "DELETE" {
			delete(f.bundles, id)
			f.deleted = append(f.deleted, fmt.Sprintf("bundle %d", id))
			w.WriteHeader(204)
			return
		}
		reply(w, 200, f.bundles[id])
	case m == "GET" && p == "/suricata/policies":
		reply(w, 200, ordered(f.suricata))
	case strings.HasPrefix(p, "/suricata/") && id > 0 && m == "DELETE":
		delete(f.suricata, id)
		f.deleted = append(f.deleted, fmt.Sprintf("suricata %d", id))
		w.WriteHeader(204)
	default:
		reply(w, 404, map[string]any{"message": "no route " + m + " " + p})
	}
}

func (f *fakeFM) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	data := func(k string, v any) { reply(w, 200, map[string]any{"data": map[string]any{k: v}}) }
	if f.collectionOp(req.Query, req.Variables, data) {
		return
	}
	switch q := req.Query; {
	case strings.Contains(q, "yaraRulesets"):
		var list []any
		for id, n := range f.rulesets {
			var srcs []any
			for _, s := range f.rulesetSrc[id] {
				srcs = append(srcs, map[string]any{"id": s})
			}
			list = append(list, map[string]any{"id": fmt.Sprint(id), "name": n, "sources": srcs})
		}
		data("yaraRulesets", map[string]any{"rulesets": list})
	case strings.Contains(q, "fileCollections"):
		data("fileCollections", map[string]any{"collections": ordered(f.collections)})
	case strings.Contains(q, "deleteFileCollections"), strings.Contains(q, "deleteYaraRulesets"):
		for _, v := range req.Variables["ids"].([]any) {
			n, _ := strconv.ParseInt(fmt.Sprint(v), 10, 64)
			delete(f.collections, n)
			delete(f.rulesets, n)
			f.deleted = append(f.deleted, fmt.Sprintf("graphql %d", n))
		}
		data("x", map[string]any{"message": "ok"})
	default:
		reply(w, 200, map[string]any{"errors": []any{map[string]any{"message": "fake: unknown query"}}})
	}
}
