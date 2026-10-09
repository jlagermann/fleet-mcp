package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// Created is an object an import made on the target.
type Created struct {
	Kind string `json:"kind"`
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Result is the outcome of Apply.
type Result struct {
	PolicyID int64     `json:"policy_id,omitempty"`
	Created  []Created `json:"created"`
	// Uploaded counts file-manager uploads; Fleet Manager has no API to
	// delete them, so a rollback leaves them behind unreferenced.
	Uploaded       int        `json:"uploaded_files"`
	Verification   []string   `json:"verification,omitempty"`
	RolledBack     bool       `json:"rolled_back,omitempty"`
	RollbackErrors []string   `json:"rollback_errors,omitempty"`
	FollowUp       []Omission `json:"follow_up,omitempty"`
}

type applier struct {
	api  API
	dir  string
	m    *Manifest
	plan *Plan
	opts ImportOptions
	res  *Result
	// uploaded maps a package file path to its file-manager ID per store.
	uploaded map[string]int64
}

// Apply imports a package as planned. On failure it deletes what it
// created, in reverse order, and reports that in the result.
func Apply(ctx context.Context, api API, dir string, m *Manifest, plan *Plan, opts ImportOptions) (*Result, error) {
	if !plan.Ready() {
		return nil, errors.New("the plan has blockers; resolve them and preview again")
	}
	if err := VerifyFiles(dir, m); err != nil {
		return nil, fmt.Errorf("package files: %w", err)
	}
	a := &applier{api: api, dir: dir, m: m, plan: plan, opts: opts, res: &Result{Created: []Created{}, FollowUp: plan.FollowUp}, uploaded: map[string]int64{}}
	if err := a.run(ctx); err != nil {
		a.rollback(ctx)
		return a.res, err
	}
	a.verify(ctx)
	return a.res, nil
}

func (a *applier) created(kind string, id int64, name string) {
	a.res.Created = append(a.res.Created, Created{Kind: kind, ID: id, Name: name})
}

func (a *applier) run(ctx context.Context) error {
	links := map[string]any{}
	if b := a.m.Bundle; b != nil && !a.opts.excluded("bundle") {
		id, err := a.bundle(ctx, b)
		if err != nil {
			return fmt.Errorf("bundle: %w", err)
		}
		links["bundle.id"] = id
	}
	if s := a.m.Suricata; s != nil && !a.opts.excluded("suricata") {
		id, err := a.suricata(ctx, s)
		if err != nil {
			return fmt.Errorf("suricata policy: %w", err)
		}
		links["suricataPolicyID"] = id
	}
	if y := a.m.Yara; y != nil && !a.opts.excluded("yara") {
		id, err := a.yara(ctx, y)
		if err != nil {
			return fmt.Errorf("YARA ruleset: %w", err)
		}
		links["yaraRulesetID"] = id
	}
	for _, r := range collectionRoles {
		c := a.m.Collections[r.Role]
		if c == nil || a.opts.excluded(r.Role) {
			continue
		}
		id, err := a.collection(ctx, c)
		if err != nil {
			return fmt.Errorf("%s collection: %w", r.Role, err)
		}
		links[r.Field] = id
	}
	return a.policy(ctx, links)
}

func (a *applier) readFile(f *FileRef) ([]byte, error) {
	return os.ReadFile(filepath.Join(a.dir, filepath.FromSlash(f.Path)))
}

// upload stores a package file in a file-manager store, once per store.
func (a *applier) upload(ctx context.Context, store string, f *FileRef) (int64, error) {
	key := store + "|" + f.Path
	if id, ok := a.uploaded[key]; ok {
		return id, nil
	}
	content, err := a.readFile(f)
	if err != nil {
		return 0, err
	}
	resp, err := a.api.DoMultipart(ctx, http.MethodPost, pathStores+store, map[string]string{"name": f.Name},
		fleet.FilePart{Field: "content", FileName: f.Name, Content: content})
	if err != nil {
		return 0, fmt.Errorf("uploading %s: %w", f.Name, err)
	}
	id, err := responseID(resp)
	if err != nil {
		return 0, fmt.Errorf("uploading %s: %w", f.Name, err)
	}
	a.uploaded[key] = id
	a.res.Uploaded++
	return id, nil
}

func responseID(resp *fleet.Response) (int64, error) {
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return 0, fmt.Errorf("response is not JSON: %w", err)
	}
	id := idOf(out["id"])
	if id <= 0 {
		return 0, errors.New("response has no id")
	}
	return id, nil
}

func (a *applier) bundle(ctx context.Context, b *Bundle) (int64, error) {
	content, err := a.readFile(&b.File)
	if err != nil {
		return 0, err
	}
	name := a.opts.name(b.Name)
	resp, err := a.api.DoMultipart(ctx, http.MethodPut, pathBundle, map[string]string{"name": name, "description": b.Description},
		fleet.FilePart{Field: "file", FileName: name, Content: content})
	if err != nil {
		return 0, err
	}
	id, err := responseID(resp)
	if err != nil {
		return 0, err
	}
	a.created("bundle", id, name)
	return id, nil
}

func (a *applier) suricata(ctx context.Context, s *Suricata) (int64, error) {
	// Upload the files first so a failed upload leaves no policy behind.
	var sources []map[string]any
	for _, src := range s.Sources {
		m := map[string]any{"name": src.Name, "entityType": src.EntityType, "enabled": src.Enabled}
		if src.Notes != "" {
			m["notes"] = src.Notes
		}
		switch {
		case src.File != nil:
			id, err := a.upload(ctx, "suricata", src.File)
			if err != nil {
				return 0, err
			}
			m["fileId"] = id
		default:
			m["url"] = src.URL
		}
		sources = append(sources, m)
	}
	update := map[string]any{
		"sources": sources, "rulesAutomation": s.RulesAutomation, "useModifierFiles": s.UseModifierFiles,
		"homeNet": s.HomeNet,
	}
	if sources == nil {
		update["sources"] = []any{}
	}
	if len(s.Settings) > 0 {
		update["settings"] = s.Settings
	}
	if len(s.Config) > 0 {
		update["config"] = s.Config
	}
	for _, sf := range suricataFiles {
		if f := s.Files[sf.Key]; f != nil {
			id, err := a.upload(ctx, sf.Store, f)
			if err != nil {
				return 0, err
			}
			update[sf.Field] = id
		}
	}
	if len(s.ModifierFiles) > 0 {
		var mods []map[string]any
		for _, mf := range s.ModifierFiles {
			m := map[string]any{"name": mf.Name, "enabled": mf.Enabled}
			if mf.File != nil {
				id, err := a.upload(ctx, "suricata-configuration-files", mf.File)
				if err != nil {
					return 0, err
				}
				m["fileId"] = id
			} else {
				m["url"] = mf.URL
			}
			mods = append(mods, m)
		}
		update["modifierFiles"] = mods
	}

	name := a.opts.name(s.Name)
	resp, err := a.api.Do(ctx, http.MethodPost, pathSuricata, nil, jsonBody(map[string]any{"name": name, "description": s.Description}), "application/json")
	if err != nil {
		return 0, err
	}
	id, err := responseID(resp)
	if err != nil {
		return 0, err
	}
	a.created("suricata policy", id, name)
	if _, err := a.api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathSuricata, id), nil, jsonBody(update), "application/json"); err != nil {
		return 0, err
	}
	return id, nil
}

const (
	createYaraSource  = `mutation($input: NewYaraSource!) { createYaraSource(input: $input) { id } }`
	createYaraRuleset = `mutation($input: NewYaraRuleset!) { createYaraRuleset(input: $input) { id } }`
	associateYara     = `mutation($input: YaraRulesetToSourcesInput!) { associateYaraRulesetToSources(input: $input) { message } }`
	createFileSource  = `mutation($input: NewFileSource!) { createFileSource(input: $input) { id } }`
	createCollection  = `mutation($input: NewFileCollection!) { createFileCollection(input: $input) { id } }`
	associateSources  = `mutation($input: FileCollectionToSourcesInput!) { associateFileCollectionToSources(input: $input) { message } }`
)

// uploadGraphQL runs a create mutation that uploads one package file and
// returns the new object's ID from data.<field>.id.
func (a *applier) uploadGraphQL(ctx context.Context, query, field string, input map[string]any, f *FileRef) (int64, error) {
	content, err := a.readFile(f)
	if err != nil {
		return 0, err
	}
	input["file"] = nil
	resp, err := a.api.GraphQLUpload(ctx, query, map[string]any{"input": input}, "variables.input.file", f.Name, content)
	var out map[string]struct {
		ID any `json:"id"`
	}
	if err := decodeGraphQL(resp, err, &out); err != nil {
		return 0, err
	}
	id := idOf(out[field].ID)
	if id <= 0 {
		return 0, fmt.Errorf("%s returned no id", field)
	}
	a.res.Uploaded++
	return id, nil
}

func (a *applier) mutateID(ctx context.Context, query, field string, input map[string]any) (int64, error) {
	var out map[string]struct {
		ID any `json:"id"`
	}
	if err := gql(ctx, a.api, query, map[string]any{"input": input}, &out); err != nil {
		return 0, err
	}
	id := idOf(out[field].ID)
	if id <= 0 {
		return 0, fmt.Errorf("%s returned no id", field)
	}
	return id, nil
}

func (a *applier) yara(ctx context.Context, y *Yara) (int64, error) {
	var ids []int64
	for _, src := range y.Sources {
		name := a.opts.name(src.Name)
		input := map[string]any{"name": name, "description": src.Description, "enabled": src.Enabled, "namespace": src.Namespace}
		if src.Interval != nil {
			input["interval"] = *src.Interval
		}
		id, err := a.uploadGraphQL(ctx, createYaraSource, "createYaraSource", input, src.File)
		if err != nil {
			return 0, fmt.Errorf("source %s: %w", src.Name, err)
		}
		a.created("YARA source", id, name)
		ids = append(ids, id)
	}
	name := a.opts.name(y.Name)
	id, err := a.mutateID(ctx, createYaraRuleset, "createYaraRuleset", map[string]any{"name": name, "description": y.Description})
	if err != nil {
		return 0, err
	}
	a.created("YARA ruleset", id, name)
	if len(ids) > 0 {
		if err := gql(ctx, a.api, associateYara, map[string]any{"input": map[string]any{"rulesetID": id, "sourceIDs": ids}}, nil); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (a *applier) collection(ctx context.Context, c *Collection) (int64, error) {
	var ids []int64
	for _, src := range c.Sources {
		if id, ok := a.plan.reuse[c.Type+"|"+src.Alias+"|"+src.Name]; ok {
			ids = append(ids, id)
			continue
		}
		alias := a.opts.name(src.Alias)
		input := map[string]any{"alias": alias, "name": src.Name, "description": src.Description, "enabled": src.Enabled, "type": src.Type}
		if src.Interval != nil {
			input["interval"] = *src.Interval
		}
		id, err := a.uploadGraphQL(ctx, createFileSource, "createFileSource", input, src.File)
		if err != nil {
			return 0, fmt.Errorf("source %s/%s: %w", src.Alias, src.Name, err)
		}
		a.created("file source", id, alias+"/"+src.Name)
		ids = append(ids, id)
	}
	name := a.opts.name(c.Name)
	id, err := a.mutateID(ctx, createCollection, "createFileCollection", map[string]any{"name": name, "description": c.Description, "type": c.Type})
	if err != nil {
		return 0, err
	}
	a.created("collection", id, name)
	if len(ids) > 0 {
		if err := gql(ctx, a.api, associateSources, map[string]any{"input": map[string]any{"collectionID": id, "sourceIDs": ids}}, nil); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (a *applier) policy(ctx context.Context, links map[string]any) error {
	pol := a.m.Policy
	resp, err := a.api.Do(ctx, http.MethodPost, pathPolicy, nil, jsonBody(map[string]any{
		"name": a.plan.PolicyName, "description": pol.Description, "configuration": a.plan.configuration,
	}), "application/json")
	if err != nil {
		return fmt.Errorf("sensor policy: %w", err)
	}
	id, err := responseID(resp)
	if err != nil {
		return fmt.Errorf("sensor policy: %w", err)
	}
	a.created("sensor policy", id, a.plan.PolicyName)
	a.res.PolicyID = id
	// Links and packages are only applied by an update, not at create.
	update := map[string]any{"id": id}
	for k, v := range links {
		update[k] = v
	}
	if len(pol.PackagesEnabled) > 0 && !a.opts.excluded("bundle") {
		update["packages.enabled"] = pol.PackagesEnabled
	}
	if pol.EnableSuricataVLAN {
		update["enableSuricataVLAN"] = true
	}
	if len(pol.FilterConfiguration) > 0 {
		update["filter-configuration"] = pol.FilterConfiguration
	}
	if len(update) == 1 {
		return nil
	}
	if _, err := a.api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathPolicy, id), nil, jsonBody(update), "application/json"); err != nil {
		return fmt.Errorf("linking resources to sensor policy %d: %w", id, err)
	}
	return nil
}

const (
	deleteFileCollections = `mutation($ids: [ID!]!) { deleteFileCollections(ids: $ids) { message } }`
	deleteFileSources     = `mutation($ids: [ID!]!) { deleteFileSources(ids: $ids) { message } }`
	deleteYaraRulesets    = `mutation($ids: [ID!]!) { deleteYaraRulesets(ids: $ids) { message } }`
	deleteYaraSources     = `mutation($ids: [ID!]!) { deleteYaraSources(ids: $ids) { message } }`
)

// rollback deletes created objects, newest first.
func (a *applier) rollback(ctx context.Context) {
	if len(a.res.Created) == 0 {
		return
	}
	// Don't let a cancelled request context stop the clean-up.
	ctx = context.WithoutCancel(ctx)
	var errs []string
	for i := len(a.res.Created) - 1; i >= 0; i-- {
		c := a.res.Created[i]
		var err error
		ids := map[string]any{"ids": []string{strconv.FormatInt(c.ID, 10)}}
		switch c.Kind {
		case "sensor policy":
			_, err = a.api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathPolicy, c.ID), nil, nil, "")
		case "suricata policy":
			_, err = a.api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathSuricata, c.ID), nil, nil, "")
		case "bundle":
			_, err = a.api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathBundle, c.ID), nil, nil, "")
		case "collection":
			err = gql(ctx, a.api, deleteFileCollections, ids, nil)
		case "file source":
			err = gql(ctx, a.api, deleteFileSources, ids, nil)
		case "YARA ruleset":
			err = gql(ctx, a.api, deleteYaraRulesets, ids, nil)
		case "YARA source":
			err = gql(ctx, a.api, deleteYaraSources, ids, nil)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %d (%s): %v", c.Kind, c.ID, c.Name, err))
		}
	}
	a.res.RolledBack = len(errs) == 0
	a.res.RollbackErrors = errs
}

// verify reads the new policy back and reports differences from the
// package.
func (a *applier) verify(ctx context.Context) {
	var p map[string]any
	if err := a.api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, a.res.PolicyID), nil, &p); err != nil {
		a.res.Verification = append(a.res.Verification, "could not read the new policy back: "+err.Error())
		return
	}
	got := obj(p["configuration"])
	var diffs []string
	for _, k := range sortedKeys(a.plan.configuration) {
		want := a.plan.configuration[k]
		if g, ok := got[k]; !ok {
			diffs = append(diffs, "setting "+k+" is missing")
		} else if !sameJSON(g, want) {
			diffs = append(diffs, "setting "+k+" differs")
		}
	}
	for _, c := range a.res.Created {
		field := map[string]string{"bundle": "bundle.id", "suricata policy": "suricataPolicyID", "YARA ruleset": "yaraRulesetID"}[c.Kind]
		if field != "" && idOf(p[field]) != c.ID {
			diffs = append(diffs, fmt.Sprintf("%s is not linked (%s = %v)", c.Kind, field, p[field]))
		}
	}
	for _, r := range collectionRoles {
		if a.m.Collections[r.Role] != nil && !a.opts.excluded(r.Role) && idOf(p[r.Field]) == 0 {
			diffs = append(diffs, r.Role+" collection is not linked")
		}
	}
	if pe := a.m.Policy.PackagesEnabled; len(pe) > 0 && !a.opts.excluded("bundle") {
		gotPE := obj(p["packages.enabled"])
		for _, k := range sortedKeys(pe) {
			if truthy(gotPE[k]) != pe[k] {
				diffs = append(diffs, "package "+k+" enabled state differs")
			}
		}
	}
	sort.Strings(diffs)
	a.res.Verification = diffs
}

func sameJSON(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	var av, bv any
	_ = json.Unmarshal(ab, &av)
	_ = json.Unmarshal(bb, &bv)
	return reflect.DeepEqual(av, bv)
}
