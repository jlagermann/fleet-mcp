package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// ImportsFile records, inside a package directory, where the package was
// imported and which parts were left for later. It is not covered by the
// manifest digest.
const ImportsFile = "imports.json"

// ImportRecord is one import of a package.
type ImportRecord struct {
	Fleet      string    `json:"fleet"`
	PolicyID   int64     `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	ImportedAt time.Time `json:"imported_at"`
	// Deferred are parts left out that a completion can still add.
	Deferred    []string   `json:"deferred,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ReadImports returns a package's import records (none if never imported).
func ReadImports(dir string) ([]ImportRecord, error) {
	b, err := os.ReadFile(filepath.Join(dir, ImportsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []ImportRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("%s: %w", ImportsFile, err)
	}
	return recs, nil
}

func writeImports(dir string, recs []ImportRecord) error {
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ImportsFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ImportsFile))
}

// pendingImport finds the latest import into fleet that deferred part.
func pendingImport(recs []ImportRecord, fleet, part string) int {
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Fleet == fleet && slices.Contains(recs[i].Deferred, part) {
			return i
		}
	}
	return -1
}

// missingExporterTypes lists exporter types the package uses that the
// target does not offer.
func missingExporterTypes(m *Manifest, target map[string]any) []string {
	var missing []string
	for _, t := range m.Features.Exporters {
		if _, ok := target[t]; !ok {
			missing = append(missing, t)
		}
	}
	return missing
}

// exporterNames lists "name (type)" for every exporter in a configuration.
func exporterNames(cfg map[string]any) []string {
	var names []string
	for k, v := range cfg {
		if inst, field, ok := exporterKey(k); ok && field == "name" {
			names = append(names, fmt.Sprintf("%s (%s)", str(v), str(cfg["bro.exporters."+inst+".type"])))
		}
	}
	sort.Strings(names)
	return names
}

// splitList splits Fleet Manager's comma-separated lists.
func splitList(v any) []string {
	var out []string
	for _, s := range strings.Split(str(v), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// planCompletion plans adding the exporters an earlier import deferred to
// the policy that import created.
func (p *Plan) planCompletion(ctx context.Context, api API, dir string, m *Manifest, meta map[string]any) error {
	recs, err := ReadImports(dir)
	if err != nil {
		return err
	}
	i := pendingImport(recs, p.Fleet, "exporters")
	if i < 0 {
		return fmt.Errorf("no earlier import of this package into %s left exporters to add; nothing to complete", p.Fleet)
	}
	rec := recs[i]
	p.PolicyName, p.completeInto = rec.PolicyName, rec.PolicyID

	// Only the exporters' own follow-ups (their tokens) still apply.
	var fu []Omission
	for _, o := range m.Omitted {
		if o.Part == "exporters" {
			fu = append(fu, o)
		}
	}
	p.FollowUp = fu
	p.Exporters = m.Features.Exporters

	var pol map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, rec.PolicyID), nil, &pol); err != nil {
		p.block("sensor policy %d (%s), created by the earlier import, cannot be read: %v", rec.PolicyID, rec.PolicyName, err)
		return nil
	}
	if missing := missingExporterTypes(m, obj(meta["exporter.metadata"])); len(missing) > 0 {
		p.block("%s still offers no %s exporter type; attach a sensor to it first", p.Fleet, strings.Join(missing, ", "))
		return nil
	}

	current := obj(pol["configuration"])
	have := splitList(current["bro.exporters.instances"])
	instances := append([]string(nil), have...)
	disabled := splitList(current["bro.exporters.disabled"])
	pkgDisabled := splitList(m.Policy.Configuration["bro.exporters.disabled"])
	cfg := map[string]any{}
	for _, inst := range splitList(m.Policy.Configuration["bro.exporters.instances"]) {
		name := fmt.Sprintf("%s (%s)", str(m.Policy.Configuration["bro.exporters."+inst+".name"]), str(m.Policy.Configuration["bro.exporters."+inst+".type"]))
		if slices.Contains(have, inst) {
			p.Reuses = append(p.Reuses, PlannedObject{Kind: "exporter", Name: name, Detail: "already on the policy"})
			continue
		}
		prefix := "bro.exporters." + inst + "."
		for k, v := range m.Policy.Configuration {
			if strings.HasPrefix(k, prefix) {
				cfg[k] = v
			}
		}
		instances = append(instances, inst)
		if slices.Contains(pkgDisabled, inst) {
			disabled = append(disabled, inst)
		}
		p.create("exporter", name, "added to sensor policy "+rec.PolicyName)
	}
	if len(cfg) > 0 {
		cfg["bro.exporters.instances"] = strings.Join(instances, ", ")
		cfg["bro.exporters.disabled"] = strings.Join(disabled, ", ")
	} else {
		p.warn("every exporter in the package is already on sensor policy %s; completing only records that", rec.PolicyName)
	}
	p.configuration = cfg
	return nil
}

// applyCompletion adds the planned exporter settings to the existing
// policy. Fleet Manager merges the configuration of an update, so other
// settings are untouched.
func (a *applier) applyCompletion(ctx context.Context) error {
	id := a.plan.completeInto
	a.res.PolicyID = id
	if len(a.plan.configuration) > 0 {
		body := map[string]any{"id": id, "configuration": a.plan.configuration}
		if _, err := a.api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathPolicy, id), nil, jsonBody(body), "application/json"); err != nil {
			return fmt.Errorf("adding exporters to sensor policy %d: %w", id, err)
		}
	}
	for _, c := range a.plan.Creates {
		a.created(c.Kind, id, c.Name)
	}
	return nil
}

// recordImport notes a finished import, or a finished completion, in the
// package directory.
func recordImport(dir string, p *Plan, res *Result) error {
	recs, err := ReadImports(dir)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if p.completeInto > 0 {
		if i := pendingImport(recs, p.Fleet, "exporters"); i >= 0 {
			recs[i].Deferred = slices.DeleteFunc(recs[i].Deferred, func(s string) bool { return s == "exporters" })
			recs[i].CompletedAt = &now
		}
	} else {
		recs = append(recs, ImportRecord{Fleet: p.Fleet, PolicyID: res.PolicyID, PolicyName: p.PolicyName, ImportedAt: now, Deferred: p.deferred})
	}
	return writeImports(dir, recs)
}

// verifyConfiguration reads the completed policy back and compares the
// settings that were sent. An empty value Fleet Manager did not store is
// not a difference.
func (a *applier) verifyConfiguration(ctx context.Context) {
	var p map[string]any
	if err := a.api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, a.res.PolicyID), nil, &p); err != nil {
		a.res.Verification = append(a.res.Verification, "could not read the policy back: "+err.Error())
		return
	}
	got := obj(p["configuration"])
	for _, k := range sortedKeys(a.plan.configuration) {
		want := a.plan.configuration[k]
		g, ok := got[k]
		switch {
		case !ok && want == "":
		case !ok:
			a.res.Verification = append(a.res.Verification, "setting "+k+" is missing")
		case !sameJSON(g, want):
			a.res.Verification = append(a.res.Verification, "setting "+k+" differs")
		}
	}
}
