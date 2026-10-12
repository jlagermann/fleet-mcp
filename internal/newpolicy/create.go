package newpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/metrics"
	"github.com/jlagermann/fleet-mcp/internal/migrate"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// Secrets supplies setting secrets the user stored at a hidden prompt.
type Secrets interface {
	GetSetting(name string) (string, error)
}

// Plan is a policy ready to create, or the reasons it is not.
type Plan struct {
	Spec  Spec   `json:"spec"`
	Built *Built `json:"policy"`
	// Linked shows the resolved Suricata policy, YARA ruleset,
	// collections and bundle.
	Linked         map[string]string `json:"linked,omitempty"`
	BundlePackages []string          `json:"bundle_packages,omitempty"`
	// Enrichments follows each linked collection to its sources and the
	// packages that read them.
	Enrichments []EnrichmentCheck `json:"enrichments,omitempty"`
	// Questions are for the user before creating: input files whose reader
	// is not in the policy or not known to fleet-mcp. They do not block.
	Questions       []string          `json:"questions_for_user,omitempty"`
	MissingSecrets  []string          `json:"missing_secrets,omitempty"`
	ConfigErrors    map[string]string `json:"config_errors,omitempty"`
	Blockers        []string          `json:"blockers,omitempty"`
	links           map[string]any
	packagesEnabled map[string]bool
	usedSecrets     []string
}

// Ready reports whether the policy can be created.
func (p *Plan) Ready() bool { return len(p.Blockers) == 0 }

// UsedSecrets are the secret-store names the policy took values from.
func (p *Plan) UsedSecrets() []string { return p.usedSecrets }

// Prepare builds the policy for the target and checks everything that can
// be checked without creating it.
func Prepare(ctx context.Context, api migrate.API, sec Secrets, s Spec) (*Plan, error) {
	defer metrics.Step(ctx, "build and check the new policy")()
	var meta map[string]any
	if err := api.GetJSON(ctx, "/fleet/v1/sensor/policy/metadata", nil, &meta); err != nil {
		return nil, err
	}
	props, _ := obj(meta["configuration.metadata"])["properties"].(map[string]any)
	exporters := obj(meta["exporter.metadata"])
	b := Build(s, props, exporters)
	p := &Plan{Spec: s, Built: b, Linked: map[string]string{}, links: map[string]any{}}
	p.Blockers = append(p.Blockers, b.Errors...)

	var policies any
	if err := api.GetJSON(ctx, "/fleet/v1/sensor/policy/list", nil, &policies); err != nil {
		return nil, err
	}
	var anyPolicy int64
	for _, el := range listOf(policies) {
		m := obj(el)
		if anyPolicy == 0 {
			anyPolicy = idOf(m["id"])
		}
		if str(m["name"]) == s.Name {
			p.Blockers = append(p.Blockers, fmt.Sprintf("a sensor policy named %q already exists on the target", s.Name))
		}
	}
	if err := p.resolveLinks(ctx, api); err != nil {
		return nil, err
	}

	// Secrets go into the configuration; their values are never shown.
	for _, store := range sortedKeys(b.SecretSettings()) {
		v, err := sec.GetSetting(store)
		if err != nil {
			p.MissingSecrets = append(p.MissingSecrets, store)
			continue
		}
		b.Configuration[b.SecretSettings()[store]] = v
		p.usedSecrets = append(p.usedSecrets, store)
	}
	if len(p.MissingSecrets) > 0 {
		p.Blockers = append(p.Blockers, fmt.Sprintf("store these secrets at a hidden prompt first, one command each: %s",
			strings.Join(setSettingCommands(p.MissingSecrets), "; ")))
	}

	if p.Ready() && anyPolicy > 0 {
		body, _ := json.Marshal(map[string]any{"config": b.Configuration})
		resp, err := api.Do(ctx, http.MethodPost, fmt.Sprintf("/fleet/v1/sensor/policy/%d/validation", anyPolicy), nil, body, "application/json")
		if err != nil {
			return nil, fmt.Errorf("validating the settings: %w", err)
		}
		var out struct {
			Errors map[string]string `json:"errors"`
		}
		if json.Unmarshal(resp.Body, &out) == nil && len(out.Errors) > 0 {
			p.ConfigErrors = out.Errors
			for _, k := range sortedKeys(out.Errors) {
				p.Blockers = append(p.Blockers, fmt.Sprintf("setting %s: %s", k, out.Errors[k]))
			}
		}
	}
	sort.Strings(p.Blockers)
	return p, nil
}

func setSettingCommands(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = secrets.Command("secret", "set-setting", n)
	}
	return out
}

// resolveLinks finds the Suricata policy, YARA ruleset, collections and
// bundle on the target by name or ID.
func (p *Plan) resolveLinks(ctx context.Context, api migrate.API) error {
	s := p.Spec
	if s.Suricata != "" {
		var list any
		if err := api.GetJSON(ctx, "/fleet/v1/suricata/policies", nil, &list); err != nil {
			return err
		}
		p.link("Suricata policy", s.Suricata, "suricataPolicyID", namedIDs(listOf(list)))
	}
	if s.Yara != "" {
		var out struct {
			YaraRulesets struct {
				Rulesets []map[string]any `json:"rulesets"`
			} `json:"yaraRulesets"`
		}
		if err := gql(ctx, api, `query { yaraRulesets(input: {pagination: {limit: 10000}}) { rulesets { id name } } }`, &out); err != nil {
			return err
		}
		p.link("YARA ruleset", s.Yara, "yaraRulesetID", namedIDs(anyList(out.YaraRulesets.Rulesets)))
	}
	// Collections are checked once the bundle packages are known.
	type linked struct {
		kind string
		coll map[string]any
	}
	var colls []linked
	if s.InputCollection != "" || s.IntelCollection != "" || s.AssetClassification != "" {
		var out struct {
			FileCollections struct {
				Collections []map[string]any `json:"collections"`
			} `json:"fileCollections"`
		}
		if err := gql(ctx, api, `query { fileCollections(input: {pagination: {limit: 10000}}) { collections { id name type sources { alias name enabled fileId isProcessing processingError metadata connector { name } } } } }`, &out); err != nil {
			return err
		}
		byType := map[string][]any{}
		for _, c := range out.FileCollections.Collections {
			byType[str(c["type"])] = append(byType[str(c["type"])], c)
		}
		for _, l := range []struct{ kind, ref, what, field, typ string }{
			{"input", s.InputCollection, "input collection", "inputCollectionID", "INPUT"},
			{"intel", s.IntelCollection, "intel collection", "intelCollectionID", "INTEL"},
			{"asset classification", s.AssetClassification, "asset classification collection", "resourceCollectionID", "RESOURCE"},
		} {
			if l.ref == "" {
				continue
			}
			if id := p.link(l.what, l.ref, l.field, namedIDs(byType[l.typ])); id > 0 {
				for _, c := range byType[l.typ] {
					if idOf(obj(c)["id"]) == id {
						colls = append(colls, linked{l.kind, obj(c)})
					}
				}
			}
		}
	}
	defer func() {
		var input map[string]any
		for _, c := range colls {
			p.checkEnrichment(c.kind, c.coll)
			if c.kind == "input" {
				input = c.coll
			}
		}
		p.checkPackageInputs(input)
	}()
	if s.Bundle != "" {
		var list any
		if err := api.GetJSON(ctx, "/fleet/v1/sensor/bundle", nil, &list); err != nil {
			return err
		}
		bundles := listOf(list)
		id := p.link("bundle", s.Bundle, "bundle.id", namedIDs(bundles))
		if id > 0 {
			var have []string
			for _, el := range bundles {
				if idOf(obj(el)["id"]) == id {
					have = sortedKeys(obj(obj(obj(el)["info"])["packages"]))
				}
			}
			p.packagesEnabled = map[string]bool{}
			for _, want := range s.BundlePackages {
				found := ""
				for _, h := range have {
					if h == want || strings.HasSuffix(h, ":"+want) {
						found = h
					}
				}
				if found == "" {
					p.Blockers = append(p.Blockers, fmt.Sprintf("bundle %s has no package %q; it has: %s", s.Bundle, want, strings.Join(have, ", ")))
					continue
				}
				p.packagesEnabled[found] = true
				p.BundlePackages = append(p.BundlePackages, found)
			}
			if len(s.BundlePackages) == 0 {
				p.Built.Warnings = append(p.Built.Warnings, fmt.Sprintf("bundle %s is linked but none of its packages is enabled; it has: %s", s.Bundle, strings.Join(have, ", ")))
			}
		}
	} else if len(s.BundlePackages) > 0 {
		p.Blockers = append(p.Blockers, "bundle_packages needs bundle")
	}
	return nil
}

type named struct {
	ID   int64
	Name string
}

func namedIDs(list []any) []named {
	var out []named
	for _, el := range list {
		m := obj(el)
		out = append(out, named{ID: idOf(m["id"]), Name: str(m["name"])})
	}
	return out
}

func anyList(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

// link resolves ref (an ID or exact name) among items and records the
// policy field to set. It returns the ID, or 0 with a blocker.
func (p *Plan) link(what, ref, field string, items []named) int64 {
	want, numErr := strconv.ParseInt(ref, 10, 64)
	var hits []named
	var names []string
	for _, it := range items {
		names = append(names, it.Name)
		if (numErr == nil && it.ID == want) || it.Name == ref {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 1:
		p.links[field] = hits[0].ID
		p.Linked[what] = fmt.Sprintf("%s (id %d)", hits[0].Name, hits[0].ID)
		return hits[0].ID
	case 0:
		sort.Strings(names)
		p.Blockers = append(p.Blockers, fmt.Sprintf("no %s %q on the target; it has: %s", what, ref, strings.Join(names, ", ")))
	default:
		p.Blockers = append(p.Blockers, fmt.Sprintf("%d %ss are named %q; use the ID", len(hits), what, ref))
	}
	return 0
}

// Create makes the policy and links its resources. If linking fails the
// new policy is deleted again. It returns the policy ID and any differences
// found when reading the policy back.
func Create(ctx context.Context, api migrate.API, p *Plan) (int64, []string, error) {
	if !p.Ready() {
		return 0, nil, errors.New("the plan has blockers; preview again")
	}
	done := metrics.Step(ctx, "create the sensor policy")
	body, _ := json.Marshal(map[string]any{"name": p.Spec.Name, "description": p.Spec.Description, "configuration": p.Built.Configuration})
	resp, err := api.Do(ctx, http.MethodPost, "/fleet/v1/sensor/policy", nil, body, "application/json")
	done()
	if err != nil {
		return 0, nil, err
	}
	var created struct {
		ID any `json:"id"`
	}
	if err := json.Unmarshal(resp.Body, &created); err != nil || idOf(created.ID) == 0 {
		return 0, nil, errors.New("no policy ID in Fleet Manager's response")
	}
	id := idOf(created.ID)
	if len(p.links) > 0 || len(p.packagesEnabled) > 0 {
		done := metrics.Step(ctx, "link the Suricata policy, YARA ruleset, collections and bundle")
		update := map[string]any{"id": id}
		for k, v := range p.links {
			update[k] = v
		}
		if len(p.packagesEnabled) > 0 {
			update["packages.enabled"] = p.packagesEnabled
		}
		body, _ := json.Marshal(update)
		_, err := api.Do(ctx, http.MethodPut, fmt.Sprintf("/fleet/v1/sensor/policy/%d", id), nil, body, "application/json")
		done()
		if err != nil {
			_, delErr := api.Do(context.WithoutCancel(ctx), http.MethodDelete, fmt.Sprintf("/fleet/v1/sensor/policy/%d", id), nil, nil, "")
			if delErr != nil {
				return id, nil, fmt.Errorf("linking failed (%v) and deleting the new policy %d failed too: %w", err, id, delErr)
			}
			return 0, nil, fmt.Errorf("linking failed, so the new policy was deleted again: %w", err)
		}
	}
	return id, verify(ctx, api, id, p), nil
}

func verify(ctx context.Context, api migrate.API, id int64, p *Plan) []string {
	defer metrics.Step(ctx, "read the policy back and verify it")()
	var pol map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("/fleet/v1/sensor/policy/%d", id), nil, &pol); err != nil {
		return []string{"could not read the new policy back: " + err.Error()}
	}
	got := obj(pol["configuration"])
	secret := map[string]bool{}
	for _, setting := range p.Built.SecretSettings() {
		secret[setting] = true
	}
	var d []string
	for _, k := range sortedKeys(p.Built.Configuration) {
		g, ok := got[k]
		want := p.Built.Configuration[k]
		switch {
		case secret[k]:
			if g != true && str(g) == "" {
				d = append(d, "secret "+k+" is not set")
			}
		case !ok && (want == false || want == ""):
			// Fleet Manager does not store a value equal to the default.
		case !ok:
			d = append(d, "setting "+k+" is missing")
		case !sameJSON(g, want):
			d = append(d, "setting "+k+" differs")
		}
	}
	for field, want := range p.links {
		if idOf(pol[field]) != idOf(want) {
			d = append(d, field+" is not linked")
		}
	}
	return d
}

// --- small helpers ---

func gql(ctx context.Context, api migrate.API, query string, out any) error {
	resp, err := api.GraphQL(ctx, query, nil)
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
		return errors.New("GraphQL: " + env.Errors[0].Message)
	}
	return json.Unmarshal(env.Data, out)
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func idOf(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	}
	return 0
}

func listOf(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		l, _ := t["list"].([]any)
		return l
	}
	return nil
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y) || fmt.Sprint(a) == fmt.Sprint(b)
}
