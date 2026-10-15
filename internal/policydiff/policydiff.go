// Package policydiff compares two sensor policies, on the same or on
// different Fleet Managers: settings, packages, linked objects (by name,
// since ids differ between Fleet Managers) and the content of the linked
// Suricata policy, YARA ruleset, collections and bundle. It only reads.
package policydiff

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/redact"
)

// API is the part of *fleet.Client that policydiff uses.
type API interface {
	GetJSON(ctx context.Context, path string, query url.Values, out any) error
	GraphQL(ctx context.Context, query string, variables map[string]any) (*fleet.Response, error)
}

// Side is one policy to compare.
type Side struct {
	API    API
	Fleet  string
	Policy string
}

// Diff is one difference.
type Diff struct {
	Item string `json:"item"`
	A    string `json:"a"`
	B    string `json:"b"`
}

// Section is the differences of one part.
type Section struct {
	Name      string `json:"name"`
	Same      bool   `json:"same"`
	Diffs     []Diff `json:"differences,omitempty"`
	Note      string `json:"note,omitempty"`
	Truncated int    `json:"more_differences,omitempty"`
}

// Result is the comparison.
type Result struct {
	A        string    `json:"a"`
	B        string    `json:"b"`
	Same     bool      `json:"identical"`
	Sections []Section `json:"sections"`
}

// MaxDiffs caps the differences listed per section.
const MaxDiffs = 60

type loaded struct {
	label    string
	pol      map[string]any
	props    map[string]any
	suricata map[string]any
	mods     []map[string]any
	colls    map[string]map[string]any // field -> collection
	yara     map[string]any
	bundle   map[string]any
	names    map[string]string // link field -> name
}

// Compare loads both policies and compares them.
func Compare(ctx context.Context, a, b Side) (*Result, error) {
	la, err := load(ctx, a)
	if err != nil {
		return nil, err
	}
	lb, err := load(ctx, b)
	if err != nil {
		return nil, err
	}
	r := &Result{A: la.label, B: lb.label, Same: true}
	add := func(name string, diffs []Diff, note string) {
		sort.Slice(diffs, func(i, j int) bool { return diffs[i].Item < diffs[j].Item })
		s := Section{Name: name, Same: len(diffs) == 0, Note: note}
		if len(diffs) > MaxDiffs {
			s.Truncated = len(diffs) - MaxDiffs
			diffs = diffs[:MaxDiffs]
		}
		s.Diffs = diffs
		if !s.Same {
			r.Same = false
		}
		r.Sections = append(r.Sections, s)
	}
	add("settings", settings(la, lb), "values not set in a policy are compared at their default; secrets only as set or not set")
	add("bundle packages", bundlePackages(la, lb), "enabled state, version and git revision of custom bundle packages")
	add("links", linkNames(la, lb), "linked objects compared by name")
	add("Suricata policy", suricataDiff(la, lb), "")
	add("YARA ruleset", sourcesDiff(la.yara, lb.yara, "name"), "YARA sources by name and file")
	for _, f := range collectionFields {
		add(collectionWhat[f], sourcesDiff(la.colls[f], lb.colls[f], "alias"), "sources by alias, file name and file")
	}
	return r, nil
}

var (
	linkFields       = []string{"suricataPolicyID", "yaraRulesetID", "intelCollectionID", "inputCollectionID", "resourceCollectionID", "caBundleCollectionID", "bundle.id"}
	collectionFields = []string{"intelCollectionID", "inputCollectionID", "resourceCollectionID", "caBundleCollectionID"}
	collectionWhat   = map[string]string{"intelCollectionID": "intel collection", "inputCollectionID": "input collection",
		"resourceCollectionID": "asset classification collection", "caBundleCollectionID": "CA bundle collection"}
)

func load(ctx context.Context, s Side) (*loaded, error) {
	var list []map[string]any
	if err := s.API.GetJSON(ctx, "/fleet/v1/sensor/policy/list", nil, &list); err != nil {
		return nil, fmt.Errorf("%s: listing policies: %w", s.Fleet, err)
	}
	ref := strings.TrimSpace(s.Policy)
	want, _ := strconv.ParseInt(ref, 10, 64)
	var id int64
	for _, p := range list {
		if (want > 0 && idOf(p["id"]) == want) || str(p["name"]) == ref {
			id = idOf(p["id"])
		}
	}
	if id == 0 {
		return nil, fmt.Errorf("%s: no sensor policy %q", s.Fleet, ref)
	}
	l := &loaded{names: map[string]string{}, colls: map[string]map[string]any{}}
	if err := s.API.GetJSON(ctx, fmt.Sprintf("/fleet/v1/sensor/policy/%d", id), nil, &l.pol); err != nil {
		return nil, fmt.Errorf("%s: reading policy %d: %w", s.Fleet, id, err)
	}
	l.label = fmt.Sprintf("%s: %q (%d)", s.Fleet, str(l.pol["name"]), id)
	l.props = obj(obj(l.pol["configuration.metadata"])["properties"])

	if sid := idOf(l.pol["suricataPolicyID"]); sid > 0 {
		if err := s.API.GetJSON(ctx, fmt.Sprintf("/fleet/v1/suricata/%d", sid), nil, &l.suricata); err != nil {
			return nil, fmt.Errorf("%s: reading Suricata policy %d: %w", s.Fleet, sid, err)
		}
		l.names["suricataPolicyID"] = str(l.suricata["name"])
		var mods []map[string]any
		if err := s.API.GetJSON(ctx, fmt.Sprintf("/fleet/v1/suricata/%d/modifiers", sid), nil, &mods); err == nil {
			l.mods = mods
		}
	}
	if bid := idOf(l.pol["bundle.id"]); bid > 0 {
		if err := s.API.GetJSON(ctx, fmt.Sprintf("/fleet/v1/sensor/bundle/%d", bid), nil, &l.bundle); err == nil {
			l.names["bundle.id"] = str(l.bundle["name"])
		}
	}
	if yid := idOf(l.pol["yaraRulesetID"]); yid > 0 {
		var out struct {
			YaraRuleset map[string]any `json:"yaraRuleset"`
		}
		q := `query($id: ID!) { yaraRuleset(id: $id) { id name sources { name namespace enabled file { name hash } } } }`
		if err := gql(ctx, s.API, q, map[string]any{"id": fmt.Sprint(yid)}, &out); err == nil {
			l.yara = out.YaraRuleset
			l.names["yaraRulesetID"] = str(l.yara["name"])
		}
	}
	for _, f := range collectionFields {
		cid := idOf(l.pol[f])
		if cid == 0 {
			continue
		}
		var out struct {
			FileCollection map[string]any `json:"fileCollection"`
		}
		q := `query($id: ID!) { fileCollection(id: $id) { id name sources { alias name enabled connector { name } file { name hash } } } }`
		if err := gql(ctx, s.API, q, map[string]any{"id": fmt.Sprint(cid)}, &out); err == nil {
			l.colls[f] = out.FileCollection
			l.names[f] = str(out.FileCollection["name"])
		}
	}
	return l, nil
}

func isSecret(prop map[string]any) bool {
	return strings.EqualFold(str(prop["cl:type"]), "password") || prop["writeOnly"] == true
}

// effective is a setting's value: set in the policy, or the default.
func effective(l *loaded, key string) (string, bool) {
	prop := obj(l.props[key])
	v, set := obj(l.pol["configuration"])[key]
	if isSecret(prop) {
		if set {
			return "(secret set)", true
		}
		return "(secret not set)", false
	}
	if set {
		return show(v), true
	}
	if prop == nil {
		return "(unknown setting)", false
	}
	return "default " + show(defaultValue(prop)), false
}

func defaultValue(prop map[string]any) any {
	d := str(prop["cl:default"])
	if str(prop["cl:type"]) == "Boolean" {
		return d == "1" || d == "true"
	}
	return d
}

func settings(a, b *loaded) []Diff {
	keys := map[string]bool{}
	for k := range obj(a.pol["configuration"]) {
		keys[k] = true
	}
	for k := range obj(b.pol["configuration"]) {
		keys[k] = true
	}
	var out []Diff
	for k := range keys {
		va, _ := effective(a, k)
		vb, _ := effective(b, k)
		if strings.TrimPrefix(va, "default ") != strings.TrimPrefix(vb, "default ") {
			out = append(out, Diff{Item: k, A: va, B: vb})
		}
	}
	return out
}

func bundlePackages(a, b *loaded) []Diff {
	pkgs := func(l *loaded) map[string]string {
		m := map[string]string{}
		info := obj(obj(l.bundle["info"])["packages"])
		en := obj(l.pol["packages.enabled"])
		for k, v := range info {
			p := obj(v)
			state := "disabled"
			if en[k] == true {
				state = "enabled"
			}
			rev := str(p["revision"])
			if len(rev) > 8 {
				rev = rev[:8]
			}
			m[k] = fmt.Sprintf("%s %s %s", state, str(p["version"]), rev)
		}
		for k, v := range en {
			if _, ok := info[k]; !ok && v == true {
				m[k] = "enabled, not in the bundle"
			}
		}
		return m
	}
	return mapDiff(pkgs(a), pkgs(b), "(not in the bundle)")
}

func linkNames(a, b *loaded) []Diff {
	var out []Diff
	for _, f := range linkFields {
		na, nb := a.names[f], b.names[f]
		if idOf(a.pol[f]) > 0 && na == "" {
			na = fmt.Sprintf("id %d", idOf(a.pol[f]))
		}
		if idOf(b.pol[f]) > 0 && nb == "" {
			nb = fmt.Sprintf("id %d", idOf(b.pol[f]))
		}
		if na != nb {
			out = append(out, Diff{Item: f, A: orNone(na), B: orNone(nb)})
		}
	}
	return out
}

func suricataDiff(a, b *loaded) []Diff {
	if a.suricata == nil || b.suricata == nil {
		return nil // the links section shows a missing Suricata policy
	}
	var out []Diff
	for _, k := range []string{"rulesAutomation", "useModifierFiles", "homeNet"} {
		if !sameJSON(a.suricata[k], b.suricata[k]) {
			out = append(out, Diff{Item: k, A: show(a.suricata[k]), B: show(b.suricata[k])})
		}
	}
	for _, d := range mapDiff(flatten(obj(a.suricata["config"])), flatten(obj(b.suricata["config"])), "(unset)") {
		d.Item = "config " + d.Item
		out = append(out, d)
	}
	for _, d := range mapDiff(flatten(obj(a.suricata["settings"])), flatten(obj(b.suricata["settings"])), "(unset)") {
		d.Item = "setting " + d.Item
		out = append(out, d)
	}
	src := func(l *loaded) map[string]string {
		m := map[string]string{}
		for _, s := range listOf(l.suricata["sources"]) {
			x := obj(s)
			what := redact.String(str(x["url"]))
			if str(x["entityType"]) == "file" {
				what = "file " + str(x["filename"])
			}
			m[str(x["name"])] = fmt.Sprintf("%s, enabled %v", what, x["enabled"] == true)
		}
		return m
	}
	for _, d := range mapDiff(src(a), src(b), "(no such source)") {
		d.Item = "rule source " + d.Item
		out = append(out, d)
	}
	mf := func(l *loaded) map[string]string {
		m := map[string]string{}
		for _, x := range listOf(l.suricata["modifierFiles"]) {
			f := obj(x)
			m[str(f["name"])] = fmt.Sprintf("enabled %v, %s", f["enabled"] == true, map[bool]string{true: "has a file", false: "empty"}[idOf(f["fileId"]) > 0])
		}
		return m
	}
	for _, d := range mapDiff(mf(a), mf(b), "(none)") {
		d.Item = "configuration file " + d.Item
		out = append(out, d)
	}
	mods := func(l *loaded) map[string]string {
		m := map[string]string{}
		for _, x := range l.mods {
			match, change := obj(x["match"]), obj(x["change"])
			key := fmt.Sprintf("%s:%s %s", str(match["key"]), str(match["value"]), str(change["key"]))
			m[key] = strings.TrimSpace(str(x["action"]) + " " + str(change["value"]))
		}
		return m
	}
	for _, d := range mapDiff(mods(a), mods(b), "(no modifier)") {
		d.Item = "rule modifier " + d.Item
		out = append(out, d)
	}
	if hashA, hashB := fileHash(a.suricata), fileHash(b.suricata); hashA != hashB {
		out = append(out, Diff{Item: "generated ruleset", A: fmt.Sprintf("%v bytes", hashA), B: fmt.Sprintf("%v bytes", hashB)})
	}
	return out
}

// fileHash identifies the generated ruleset by its size (Fleet Manager
// does not report a hash for it).
func fileHash(sp map[string]any) any {
	return obj(obj(sp["fileInfo"])["suricata-file-id"])["size-bytes"]
}

// sourcesDiff compares the sources of a YARA ruleset or collection.
func sourcesDiff(a, b map[string]any, key string) []Diff {
	if a == nil || b == nil {
		return nil
	}
	m := func(c map[string]any) map[string]string {
		out := map[string]string{}
		for _, s := range listOf(c["sources"]) {
			x := obj(s)
			f := obj(x["file"])
			h := str(f["hash"])
			if len(h) > 12 {
				h = h[:12]
			}
			v := fmt.Sprintf("%s, enabled %v, sha256 %s", str(f["name"]), x["enabled"] == true, orNone(h))
			if c := obj(x["connector"]); c != nil {
				v += ", connector " + str(c["name"])
			}
			out[str(x[key])+" / "+str(x["name"])] = v
		}
		return out
	}
	return mapDiff(m(a), m(b), "(no such source)")
}

func mapDiff(a, b map[string]string, missing string) []Diff {
	var out []Diff
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			vb = missing
		}
		if va != vb {
			out = append(out, Diff{Item: k, A: va, B: vb})
		}
	}
	for k, vb := range b {
		if _, ok := a[k]; !ok {
			out = append(out, Diff{Item: k, A: missing, B: vb})
		}
	}
	return out
}

func flatten(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = show(v)
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// --- helpers ---

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
		return err
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("GraphQL: %s", env.Errors[0].Message)
	}
	return json.Unmarshal(env.Data, out)
}

func idOf(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
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
