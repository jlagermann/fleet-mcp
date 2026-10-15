// Package policyedit changes, deletes and assigns Fleet Manager sensor
// policies: settings, packages and linked content (fm_policy_update), a
// policy and the objects only it uses (fm_policy_delete), and sensor groups
// with their policy and members (fm_group_manage).
package policyedit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// API is the part of *fleet.Client that policyedit uses.
type API interface {
	Do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (*fleet.Response, error)
	GetJSON(ctx context.Context, path string, query url.Values, out any) error
	GraphQL(ctx context.Context, query string, variables map[string]any) (*fleet.Response, error)
}

var _ API = (*fleet.Client)(nil)

const (
	pathPolicyList = "/fleet/v1/sensor/policy/list"
	pathPolicy     = "/fleet/v1/sensor/policy"
	pathGroupList  = "/fleet/v1/sensor/group/list"
	pathGroup      = "/fleet/v1/sensor/group"
	pathCatalog    = "/fleet/v1/sensor/catalog"
	pathBundle     = "/fleet/v1/sensor/bundle"
	pathSuricata   = "/fleet/v1/suricata"
	pathSuricatas  = "/fleet/v1/suricata/policies"
)

// Ref names an object: its id and name.
type Ref struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (r Ref) String() string { return fmt.Sprintf("%q (%d)", r.Name, r.ID) }

// links are the sensor policy fields that point at other objects.
var links = []struct {
	Field, What, CollectionType string
}{
	{"suricataPolicyID", "Suricata policy", ""},
	{"yaraRulesetID", "YARA ruleset", ""},
	{"intelCollectionID", "intel collection", "INTEL"},
	{"inputCollectionID", "input collection", "INPUT"},
	{"resourceCollectionID", "asset classification (resource) collection", "RESOURCE"},
	{"caBundleCollectionID", "CA bundle collection", "CA_BUNDLES"},
	{"bundle.id", "package bundle", ""},
}

// gql runs a GraphQL query and decodes its data.
func gql(ctx context.Context, api API, query string, vars map[string]any, out any) error {
	resp, err := api.GraphQL(ctx, query, vars)
	if err != nil {
		return err
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return fmt.Errorf("GraphQL response is not JSON: %w", err)
	}
	if len(env.Errors) > 0 {
		var m []string
		for _, e := range env.Errors {
			m = append(m, e.Message)
		}
		return errors.New("GraphQL: " + strings.Join(m, "; "))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func idOf(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func show(v any) string {
	switch x := v.(type) {
	case nil:
		return "(unset)"
	case string:
		if len(x) > 160 {
			return fmt.Sprintf("%q", x[:157]+"...")
		}
		return fmt.Sprintf("%q", x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func sameJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// policies returns the sensor policy list (id, name, links).
func policies(ctx context.Context, api API) ([]map[string]any, error) {
	var list []map[string]any
	if err := api.GetJSON(ctx, pathPolicyList, nil, &list); err != nil {
		return nil, fmt.Errorf("listing sensor policies: %w", err)
	}
	return list, nil
}

// resolvePolicy finds a sensor policy by id or exact name and returns its
// full record.
func resolvePolicy(ctx context.Context, api API, ref string) (Ref, map[string]any, error) {
	list, err := policies(ctx, api)
	if err != nil {
		return Ref{}, nil, err
	}
	ref = strings.TrimSpace(ref)
	id, _ := strconv.ParseInt(ref, 10, 64)
	var names []string
	for _, p := range list {
		names = append(names, str(p["name"]))
		if (id > 0 && idOf(p["id"]) == id) || str(p["name"]) == ref {
			r := Ref{ID: idOf(p["id"]), Name: str(p["name"])}
			var full map[string]any
			if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, r.ID), nil, &full); err != nil {
				return Ref{}, nil, fmt.Errorf("reading sensor policy %d: %w", r.ID, err)
			}
			return r, full, nil
		}
	}
	return Ref{}, nil, fmt.Errorf("no sensor policy %q; policies: %s", ref, strings.Join(names, ", "))
}

// groupsUsing lists the sensor groups whose policy is id, with their
// member sensor names.
func groupsUsing(ctx context.Context, api API, id int64) ([]GroupInfo, error) {
	groups, err := listGroups(ctx, api)
	if err != nil {
		return nil, err
	}
	var out []GroupInfo
	for _, g := range groups {
		if g.PolicyID == id {
			out = append(out, g)
		}
	}
	return out, nil
}

// GroupInfo is a sensor group summary.
type GroupInfo struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	PolicyID int64    `json:"policy_id,omitempty"`
	Policy   string   `json:"policy,omitempty"`
	Sensors  []string `json:"sensors"`
	uids     []string
}

func listGroups(ctx context.Context, api API) ([]GroupInfo, error) {
	var list []map[string]any
	if err := api.GetJSON(ctx, pathGroupList, nil, &list); err != nil {
		return nil, fmt.Errorf("listing sensor groups: %w", err)
	}
	var out []GroupInfo
	for _, g := range list {
		gi := GroupInfo{ID: idOf(g["id"]), Name: str(g["name"]), PolicyID: idOf(g["policy.id"]), Policy: str(g["policy.name"]), Sensors: []string{}}
		for _, s := range listOf(g["sensors"]) {
			m := obj(s)
			name := str(m["name"])
			if name == "" {
				name = str(m["uid"])
			}
			gi.Sensors = append(gi.Sensors, name)
			gi.uids = append(gi.uids, str(m["uid"]))
		}
		out = append(out, gi)
	}
	return out, nil
}

// named lists objects (id, name) a link can point at.
func named(ctx context.Context, api API, field, collectionType string) ([]Ref, error) {
	var refs []Ref
	switch {
	case field == "suricataPolicyID":
		var list []map[string]any
		if err := api.GetJSON(ctx, pathSuricatas, nil, &list); err != nil {
			return nil, fmt.Errorf("listing Suricata policies: %w", err)
		}
		for _, x := range list {
			refs = append(refs, Ref{idOf(x["id"]), str(x["name"])})
		}
	case field == "yaraRulesetID":
		var out struct {
			YaraRulesets struct {
				Rulesets []map[string]any `json:"rulesets"`
			} `json:"yaraRulesets"`
		}
		if err := gql(ctx, api, `query { yaraRulesets { rulesets { id name } } }`, nil, &out); err != nil {
			return nil, fmt.Errorf("listing YARA rulesets: %w", err)
		}
		for _, x := range out.YaraRulesets.Rulesets {
			refs = append(refs, Ref{idOf(x["id"]), str(x["name"])})
		}
	case field == "bundle.id":
		var list []map[string]any
		if err := api.GetJSON(ctx, pathBundle, nil, &list); err != nil {
			return nil, fmt.Errorf("listing bundles: %w", err)
		}
		for _, x := range list {
			refs = append(refs, Ref{idOf(x["id"]), str(x["name"])})
		}
	default:
		cs, err := collections(ctx, api)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if str(c["type"]) == collectionType {
				refs = append(refs, Ref{idOf(c["id"]), str(c["name"])})
			}
		}
	}
	return refs, nil
}

func collections(ctx context.Context, api API) ([]map[string]any, error) {
	var out struct {
		FileCollections struct {
			Collections []map[string]any `json:"collections"`
		} `json:"fileCollections"`
	}
	q := `query { fileCollections(input: {pagination: {limit: 10000}}) { collections { id name type sources { id alias name enabled connector { name } file { id name } } } } }`
	if err := gql(ctx, api, q, nil, &out); err != nil {
		return nil, fmt.Errorf("listing collections: %w", err)
	}
	return out.FileCollections.Collections, nil
}

// pick finds an object by id or exact name among refs.
func pick(refs []Ref, ref, what string) (Ref, error) {
	ref = strings.TrimSpace(ref)
	id, _ := strconv.ParseInt(ref, 10, 64)
	var names []string
	for _, r := range refs {
		if (id > 0 && r.ID == id) || r.Name == ref {
			return r, nil
		}
		names = append(names, r.Name)
	}
	if len(names) == 0 {
		return Ref{}, fmt.Errorf("no %s %q (there are none)", what, ref)
	}
	sort.Strings(names)
	return Ref{}, fmt.Errorf("no %s %q; there are: %s", what, ref, strings.Join(names, ", "))
}
