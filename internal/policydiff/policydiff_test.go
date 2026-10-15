package policydiff

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// fakeAPI serves canned objects by path.
type fakeAPI struct {
	rest map[string]any
	gql  map[string]any // "<field> <id>" -> object
}

func (f *fakeAPI) GetJSON(_ context.Context, path string, _ url.Values, out any) error {
	v, ok := f.rest[path]
	if !ok {
		return fmt.Errorf("404 %s", path)
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}

func (f *fakeAPI) GraphQL(_ context.Context, q string, vars map[string]any) (*fleet.Response, error) {
	field := "yaraRuleset"
	if strings.Contains(q, "fileCollection(") {
		field = "fileCollection"
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{field: f.gql[fmt.Sprintf("%s %v", field, vars["id"])]}})
	return &fleet.Response{Status: 200, Body: b}, nil
}

var props = map[string]any{
	"bro.analyzers.mqtt.enable": map[string]any{"cl:type": "Boolean", "cl:default": "0"},
	"bro.site.local_nets":       map[string]any{"cl:type": "NetworkList", "cl:default": "10.0.0.0/8"},
	"proxy.password":            map[string]any{"cl:type": "Password", "writeOnly": true},
}

func side(name string, cfg map[string]any, enabled map[string]any, suricata map[string]any, mods []any, intelHash string) *fakeAPI {
	return &fakeAPI{
		rest: map[string]any{
			"/fleet/v1/sensor/policy/list": []any{map[string]any{"id": 1, "name": name}},
			"/fleet/v1/sensor/policy/1": map[string]any{"id": 1, "name": name, "configuration": cfg, "configuration.metadata": map[string]any{"properties": props},
				"packages.enabled": enabled, "bundle.id": 5, "suricataPolicyID": 7, "intelCollectionID": 9},
			"/fleet/v1/sensor/bundle/5": map[string]any{"name": "b.bundle", "info": map[string]any{"packages": map[string]any{
				"https:github.com:corelight:ExtendIntel": map[string]any{"version": "v4.1", "revision": "0707d5c7fd09"},
				":home:u:dns-bypass":                     map[string]any{"version": "main", "revision": "dfa99f21aee2"}}}},
			"/fleet/v1/suricata/7":           suricata,
			"/fleet/v1/suricata/7/modifiers": mods,
		},
		gql: map[string]any{"fileCollection 9": map[string]any{"name": "intel", "sources": []any{
			map[string]any{"alias": "feed", "name": "bro_intel.dat", "enabled": true, "file": map[string]any{"name": "intel.dat", "hash": intelHash}}}}},
	}
}

func TestCompare(t *testing.T) {
	sp := func(url string, automation bool) map[string]any {
		return map[string]any{"name": "Lab", "rulesAutomation": automation, "config": map[string]any{"srmEnableFlowBits": true},
			"sources": []any{map[string]any{"name": "ET Pro", "entityType": "url", "enabled": true, "url": url}}}
	}
	mod := []any{map[string]any{"action": "disable", "match": map[string]any{"key": "sid", "value": "2000328"}, "change": map[string]any{"key": "", "value": ""}}}
	a := side("Edge", map[string]any{"bro.analyzers.mqtt.enable": true, "proxy.password": "x"}, map[string]any{"https:github.com:corelight:ExtendIntel": true},
		sp("https://rules.emergingthreatspro.com/SECRETCODE/suricata-8.0/etpro.rules.tar.gz", true), mod, "aaaaaaaaaaaaaaaa")
	b := side("Edge", map[string]any{"bro.site.local_nets": "10.0.0.0/8"}, map[string]any{"https:github.com:corelight:ExtendIntel": true, ":home:u:dns-bypass": true},
		sp("https://rules.emergingthreatspro.com/OTHERCODE/suricata-8.0/etpro.rules.tar.gz", false), nil, "bbbbbbbbbbbbbbbb")
	r, err := Compare(context.Background(), Side{API: a, Fleet: "prod", Policy: "Edge"}, Side{API: b, Fleet: "lab", Policy: "1"})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(r)
	s := string(out)
	if r.Same || strings.Contains(s, "SECRETCODE") || strings.Contains(s, "OTHERCODE") {
		t.Fatalf("result: %s", s)
	}
	for _, want := range []string{
		`"item":"bro.analyzers.mqtt.enable","a":"true","b":"default false"`,
		`"item":"proxy.password","a":"(secret set)","b":"(secret not set)"`,
		`"item":":home:u:dns-bypass","a":"disabled main dfa99f21","b":"enabled main dfa99f21"`,
		`"item":"rulesAutomation","a":"true","b":"false"`,
		`"item":"rule modifier sid:2000328 ","a":"disable","b":"(no modifier)"`,
		`"item":"feed / bro_intel.dat"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("result lacks %s", want)
		}
	}
	if strings.Contains(s, `"item":"bro.site.local_nets"`) {
		t.Error("a value equal to the default is not a difference")
	}
	for _, sec := range r.Sections {
		if sec.Name == "links" && !sec.Same {
			t.Errorf("links have the same names: %+v", sec)
		}
	}
}
