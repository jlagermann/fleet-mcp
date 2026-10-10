package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Conflict resolutions, set per decision ID in ImportOptions.Resolve.
const (
	// UseExisting links the object already on the target, unchanged.
	UseExisting = "use_existing"
	// Rename creates the migrated object under a new name: "rename" adds
	// " (from <source fleet>)", "rename:<name>" uses that name.
	Rename = "rename"
	// UpdateExisting (sensor policy only) applies the migrated settings and
	// links to the existing policy. Its other settings stay.
	UpdateExisting = "update_existing"
)

// conflictID names the decision for an object that exists on the target.
func conflictID(kind, name string) string { return "conflict:" + kind + ":" + name }

// existingObj is an object on the target with a given kind and name.
type existingObj struct {
	ID int64
	// Hash is the file hash of a file source or YARA source.
	Hash string
}

// targetNames holds what already exists on the target, by kind and name.
type targetNames struct {
	objs map[string]map[string]existingObj
	// sources maps "TYPE|alias|name" to a file source.
	sources map[string]existingObj
}

func (t *targetNames) get(kind, name string) (existingObj, bool) {
	o, ok := t.objs[kind][name]
	return o, ok
}

const namesQuery = `query {
  yaraRulesets(input: {pagination: {limit: 10000}}) { rulesets { id name } }
  yaraSources(input: {pagination: {limit: 10000}}) { sources { id name file { hash } } }
  fileCollections(input: {pagination: {limit: 10000}}) { collections { id name } }
  fileSources(input: {pagination: {limit: 10000}}) { sources { id alias name type file { hash } } }
}`

func loadNames(ctx context.Context, api API) (*targetNames, error) {
	t := &targetNames{objs: map[string]map[string]existingObj{}, sources: map[string]existingObj{}}
	add := func(kind, name string, o existingObj) {
		if t.objs[kind] == nil {
			t.objs[kind] = map[string]existingObj{}
		}
		t.objs[kind][name] = o
	}
	for kind, path := range map[string]string{"sensor policy": pathPolicyList, "suricata policy": pathSuricataList, "bundle": pathBundle} {
		var list any
		if err := api.GetJSON(ctx, path, nil, &list); err != nil {
			return nil, err
		}
		for _, el := range listOf(list) {
			add(kind, str(obj(el)["name"]), existingObj{ID: idOf(obj(el)["id"])})
		}
	}
	type fileHash struct {
		Hash string `json:"hash"`
	}
	var out struct {
		YaraRulesets struct {
			Rulesets []struct {
				ID   any    `json:"id"`
				Name string `json:"name"`
			} `json:"rulesets"`
		} `json:"yaraRulesets"`
		YaraSources struct {
			Sources []struct {
				ID   any       `json:"id"`
				Name string    `json:"name"`
				File *fileHash `json:"file"`
			} `json:"sources"`
		} `json:"yaraSources"`
		FileCollections struct {
			Collections []struct {
				ID   any    `json:"id"`
				Name string `json:"name"`
			} `json:"collections"`
		} `json:"fileCollections"`
		FileSources struct {
			Sources []struct {
				ID    any       `json:"id"`
				Alias string    `json:"alias"`
				Name  string    `json:"name"`
				Type  string    `json:"type"`
				File  *fileHash `json:"file"`
			} `json:"sources"`
		} `json:"fileSources"`
	}
	if err := gql(ctx, api, namesQuery, nil, &out); err != nil {
		return nil, err
	}
	hash := func(f *fileHash) string {
		if f == nil {
			return ""
		}
		return f.Hash
	}
	for _, r := range out.YaraRulesets.Rulesets {
		add("YARA ruleset", r.Name, existingObj{ID: idOf(r.ID)})
	}
	for _, s := range out.YaraSources.Sources {
		add("YARA source", s.Name, existingObj{ID: idOf(s.ID), Hash: hash(s.File)})
	}
	for _, c := range out.FileCollections.Collections {
		add("collection", c.Name, existingObj{ID: idOf(c.ID)})
	}
	for _, s := range out.FileSources.Sources {
		t.sources[s.Type+"|"+s.Alias+"|"+s.Name] = existingObj{ID: idOf(s.ID), Hash: hash(s.File)}
	}
	return t, nil
}

// resolution is what to do with one object of the package.
type resolution struct {
	// Existing is the target object to link instead of creating one.
	Existing int64
	// Name is the name to create the object under.
	Name string
}

// resolve decides what happens to an object named name (already with any
// name_suffix) of the given kind. differ compares the package's object
// with the existing one and returns the differences; it is called only
// when the name is taken.
func (p *Plan) resolve(kind, name string, existing *targetNames, opts ImportOptions, differ func(id int64) ([]string, error)) (resolution, error) {
	o, taken := existing.get(kind, name)
	if !taken {
		return resolution{Name: name}, nil
	}
	diffs, err := differ(o.ID)
	if err != nil {
		return resolution{}, fmt.Errorf("comparing with the existing %s %q: %w", kind, name, err)
	}
	return p.resolveTaken(kind, name, o.ID, diffs, existing, opts), nil
}

// resolveTaken applies the user's answer for a name that is taken.
func (p *Plan) resolveTaken(kind, name string, id int64, diffs []string, existing *targetNames, opts ImportOptions) resolution {
	if len(diffs) == 0 {
		p.Reuses = append(p.Reuses, PlannedObject{Kind: kind, Name: name, ID: id, Detail: "identical one already on the target; reused"})
		return resolution{Existing: id}
	}
	did := conflictID(kind, name)
	answer := opts.Resolve[did]
	switch {
	case answer == UseExisting:
		p.Reuses = append(p.Reuses, PlannedObject{Kind: kind, Name: name, ID: id, Detail: "existing one kept unchanged and linked, as chosen (it differs from the package)"})
		return resolution{Existing: id}
	case answer == Rename || strings.HasPrefix(answer, Rename+":"):
		newName := strings.TrimPrefix(strings.TrimPrefix(answer, Rename), ":")
		if newName == "" {
			newName = fmt.Sprintf("%s (from %s)", name, p.SourceFleet)
		}
		if _, taken := existing.get(kind, newName); taken {
			p.block("the new name %q for the %s is taken too; choose another with resolve {%q: \"rename:<name>\"}", newName, kind, did)
		}
		return resolution{Name: newName}
	case answer != "":
		p.block("%q is not an answer for %s; use %s or %s", answer, did, UseExisting, Rename)
	}
	p.Decisions = append(p.Decisions, Decision{
		ID: did,
		Question: fmt.Sprintf("A %s named %q already exists on %s and differs from the one being migrated: %s. Keep and use the existing one, or create the migrated one under a new name?",
			kind, name, p.Fleet, summarize(diffs)),
		Resolve: map[string]string{
			UseExisting: fmt.Sprintf(`preview again with resolve {%q: %q}: the existing %s is linked unchanged`, did, UseExisting, kind),
			Rename:      fmt.Sprintf(`preview again with resolve {%q: %q} (creates %q) or %q`, did, Rename, fmt.Sprintf("%s (from %s)", name, p.SourceFleet), Rename+":<name>"),
		},
	})
	return resolution{Name: name}
}

func summarize(diffs []string) string {
	const show = 5
	if len(diffs) <= show {
		return strings.Join(diffs, "; ")
	}
	return strings.Join(diffs[:show], "; ") + fmt.Sprintf("; and %d more", len(diffs)-show)
}

// fileHashOf returns the hash Fleet Manager records for a stored file
// (a SHA-256 of its content, as in the package manifest).
func fileHashOf(ctx context.Context, api API, id int64) string {
	if id <= 0 {
		return ""
	}
	var info struct {
		Hash string `json:"hash"`
	}
	if err := api.GetJSON(ctx, pathFiles+strconv.FormatInt(id, 10)+"/info", nil, &info); err != nil {
		return ""
	}
	return info.Hash
}

func diffBundle(ctx context.Context, api API, id int64, b *Bundle) ([]string, error) {
	resp, err := api.Do(ctx, http.MethodGet, fmt.Sprintf("%s/%d/file", pathBundle, id), nil, nil, "")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(resp.Body)
	if hex.EncodeToString(sum[:]) != b.File.SHA256 {
		return []string{"the bundle file differs"}, nil
	}
	return nil, nil
}

func diffSuricata(ctx context.Context, api API, id int64, s *Suricata, settings map[string]any) ([]string, error) {
	var sp, defs map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathSuricata, id), nil, &sp); err != nil {
		return nil, err
	}
	_ = api.GetJSON(ctx, pathSuricataDefs, nil, &defs)
	defaults := obj(defs["settings"])
	var d []string
	if str(sp["homeNet"]) != s.HomeNet {
		d = append(d, "HOME_NET differs")
	}
	if truthy(sp["rulesAutomation"]) != s.RulesAutomation {
		d = append(d, "rules automation differs")
	}
	if truthy(sp["useModifierFiles"]) != s.UseModifierFiles {
		d = append(d, "use of modifier files differs")
	}
	got := obj(sp["settings"])
	for _, k := range sortedKeys(settings) {
		g, ok := got[k]
		if !ok && sameJSON(defaults[k], settings[k]) {
			continue
		}
		if !ok || !sameJSON(g, settings[k]) {
			d = append(d, "setting "+k+" differs")
		}
	}
	for _, k := range sortedKeys(got) {
		if _, ok := settings[k]; !ok && !sameJSON(got[k], defaults[k]) {
			d = append(d, "the existing policy also sets "+k)
		}
	}
	// Sources by name: type and URL or file content.
	want := map[string]string{}
	for _, src := range s.Sources {
		v := src.EntityType + " " + src.URL
		if src.File != nil {
			v = src.EntityType + " " + src.File.SHA256
		}
		want[src.Name] = v
	}
	have := map[string]string{}
	for _, el := range listOf(sp["sources"]) {
		src := obj(el)
		v := str(src["entityType"]) + " " + str(src["url"])
		if str(src["entityType"]) == "file" {
			v = "file " + fileHashOf(ctx, api, idOf(src["fileId"]))
		}
		have[str(src["name"])] = v
	}
	d = append(d, diffSets("rule source", want, have)...)
	for _, sf := range suricataFiles {
		w := ""
		if f := s.Files[sf.Key]; f != nil {
			w = f.SHA256
		}
		h := ""
		if fid := idOf(sp[sf.Field]); fid > 0 {
			h = fileHashOf(ctx, api, fid)
		}
		if w != h {
			d = append(d, sf.Key+" file differs")
		}
	}
	wantMods := map[string]string{}
	for _, mf := range s.ModifierFiles {
		if mf.File != nil {
			wantMods[mf.Name] = mf.File.SHA256
		} else if mf.URL != "" {
			wantMods[mf.Name] = mf.URL
		}
	}
	haveMods := map[string]string{}
	for _, el := range listOf(sp["modifierFiles"]) {
		mf := obj(el)
		switch {
		case idOf(mf["fileId"]) > 0:
			haveMods[str(mf["name"])] = fileHashOf(ctx, api, idOf(mf["fileId"]))
		case strings.HasPrefix(str(mf["url"]), "http"):
			haveMods[str(mf["name"])] = str(mf["url"])
		}
	}
	d = append(d, diffSets("modifier file", wantMods, haveMods)...)
	var mods []RuleModifier
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d/modifiers", pathSuricata, id), nil, &mods); err == nil {
		key := func(r RuleModifier) string {
			return r.Action + " " + r.Match.Key + "=" + r.Match.Value + " " + r.Change.Key + "=" + r.Change.Value
		}
		wantR, haveR := map[string]string{}, map[string]string{}
		for _, r := range s.RuleModifiers {
			wantR[key(r)] = "x"
		}
		for _, r := range mods {
			haveR[key(r)] = "x"
		}
		d = append(d, diffSets("rule modifier", wantR, haveR)...)
	}
	return d, nil
}

// diffSets compares name→value maps of what is wanted and what exists.
func diffSets(what string, want, have map[string]string) []string {
	var d []string
	for _, k := range sortedKeys(want) {
		h, ok := have[k]
		switch {
		case !ok:
			d = append(d, fmt.Sprintf("%s %s is missing on the target", what, k))
		case h != want[k]:
			d = append(d, fmt.Sprintf("%s %s differs", what, k))
		}
	}
	for _, k := range sortedKeys(have) {
		if _, ok := want[k]; !ok {
			d = append(d, fmt.Sprintf("the target also has %s %s", what, k))
		}
	}
	return d
}

func diffYara(ctx context.Context, api API, id int64, y *Yara) ([]string, error) {
	var out struct {
		YaraRuleset *struct {
			Sources []struct {
				Name string `json:"name"`
				File *struct {
					Hash string `json:"hash"`
				} `json:"file"`
			} `json:"sources"`
		} `json:"yaraRuleset"`
	}
	if err := gql(ctx, api, `query($id: ID!) { yaraRuleset(id: $id) { sources { name file { hash } } } }`, map[string]any{"id": strconv.FormatInt(id, 10)}, &out); err != nil {
		return nil, err
	}
	want, have := map[string]string{}, map[string]string{}
	for _, s := range y.Sources {
		if s.File != nil {
			want[s.Name] = s.File.SHA256
		}
	}
	if out.YaraRuleset != nil {
		for _, s := range out.YaraRuleset.Sources {
			if s.File != nil {
				have[s.Name] = s.File.Hash
			} else {
				have[s.Name] = ""
			}
		}
	}
	return diffSets("YARA source", want, have), nil
}

func diffCollection(ctx context.Context, api API, id int64, c *Collection) ([]string, error) {
	var out struct {
		FileCollection *struct {
			Type    string `json:"type"`
			Sources []struct {
				Alias string `json:"alias"`
				Name  string `json:"name"`
				File  *struct {
					Hash string `json:"hash"`
				} `json:"file"`
			} `json:"sources"`
		} `json:"fileCollection"`
	}
	if err := gql(ctx, api, `query($id: ID!) { fileCollection(id: $id) { type sources { alias name file { hash } } } }`, map[string]any{"id": strconv.FormatInt(id, 10)}, &out); err != nil {
		return nil, err
	}
	var d []string
	want, have := map[string]string{}, map[string]string{}
	for _, s := range c.Sources {
		want[s.Alias+"/"+s.Name] = s.File.SHA256
	}
	if fc := out.FileCollection; fc != nil {
		if fc.Type != c.Type {
			d = append(d, "collection type is "+fc.Type+", not "+c.Type)
		}
		for _, s := range fc.Sources {
			h := ""
			if s.File != nil {
				h = s.File.Hash
			}
			have[s.Alias+"/"+s.Name] = h
		}
	}
	return append(d, diffSets("source", want, have)...), nil
}

// ignore lists settings that are not compared (secrets of the package
// whose values are not supplied yet).
func diffPolicy(ctx context.Context, api API, id int64, cfg map[string]any, secret, ignore map[string]bool, pkgs map[string]bool) ([]string, error) {
	var pol map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, id), nil, &pol); err != nil {
		return nil, err
	}
	got := obj(pol["configuration"])
	var d []string
	for _, k := range sortedKeys(cfg) {
		g, ok := got[k]
		switch {
		case secret[k]:
			if !secretSet(g) {
				d = append(d, "secret "+k+" is not set on the target")
			}
		case !ok:
			d = append(d, "setting "+k+" is not set on the target")
		case !sameJSON(g, cfg[k]):
			d = append(d, "setting "+k+" differs")
		}
	}
	// Exporters left out of this import are not a difference.
	sendsExporters := false
	for k := range cfg {
		sendsExporters = sendsExporters || strings.HasPrefix(k, "bro.exporters.")
	}
	for _, k := range sortedKeys(got) {
		if ignore[k] || (!sendsExporters && strings.HasPrefix(k, "bro.exporters.")) {
			continue
		}
		if _, ok := cfg[k]; !ok {
			d = append(d, "the existing policy also sets "+k)
		}
	}
	gotPE := obj(pol["packages.enabled"])
	var pk []string
	for _, k := range sortedKeys(pkgs) {
		if truthy(gotPE[k]) != pkgs[k] {
			pk = append(pk, k)
		}
	}
	if len(pk) > 0 {
		sort.Strings(pk)
		d = append(d, "enabled packages differ: "+strings.Join(pk, ", "))
	}
	return d, nil
}

// nameOf is the name an object is created under: the user's new name for
// a conflict, otherwise def.
func (p *Plan) nameOf(key, def string) string {
	if r, ok := p.res[key]; ok && r.Name != "" {
		return r.Name
	}
	return def
}
