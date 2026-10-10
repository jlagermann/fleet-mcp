package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Parts can be left out of an import with ImportOptions.Exclude.
var Parts = []string{"bundle", "suricata", "yara", "exporters", "input", "intel", "resource", "ca_bundles"}

// ImportOptions shape an import.
type ImportOptions struct {
	// Name is the new sensor policy's name; empty keeps the exported name.
	Name string `json:"name,omitempty"`
	// NameSuffix is appended to the name of every object created, to
	// avoid clashing with existing objects on the target.
	NameSuffix string `json:"name_suffix,omitempty"`
	// AllowUnlicensed imports features no target sensor is licensed for.
	AllowUnlicensed bool `json:"allow_unlicensed,omitempty"`
	// Exclude leaves parts (see Parts) out of the import.
	Exclude []string `json:"exclude,omitempty"`
}

func (o ImportOptions) excluded(part string) bool { return slices.Contains(o.Exclude, part) }

func (o ImportOptions) name(n string) string { return n + o.NameSuffix }

// Plan is what an import would do, computed without changing anything.
type Plan struct {
	Fleet         string            `json:"fleet"`
	PolicyName    string            `json:"policy_name"`
	SourceFleet   string            `json:"source_fleet"`
	SourceVersion string            `json:"source_version"`
	TargetVersion string            `json:"target_version"`
	Creates       []PlannedObject   `json:"creates"`
	Reuses        []PlannedObject   `json:"reuses,omitempty"`
	UploadFiles   int               `json:"upload_files"`
	UploadBytes   int64             `json:"upload_bytes"`
	Licenses      []LicenseCheck    `json:"licenses,omitempty"`
	Exporters     []string          `json:"exporters,omitempty"`
	ConfigErrors  map[string]string `json:"config_errors,omitempty"`
	Blockers      []string          `json:"blockers,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
	FollowUp      []Omission        `json:"follow_up,omitempty"`

	// reuse maps "TYPE|alias|name" to an existing identical file source.
	reuse map[string]int64
	// configuration is the policy configuration that will be sent.
	configuration map[string]any
}

// PlannedObject is one object an import creates or reuses.
type PlannedObject struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	ID     int64  `json:"id,omitempty"`
}

// LicenseCheck reports how many target sensors hold a feature's license.
type LicenseCheck struct {
	Feature  string `json:"feature"`
	Licensed int    `json:"licensed_sensors"`
	Sensors  int    `json:"sensors"`
	Status   string `json:"status"` // licensed, partial, unlicensed, unverified
}

// Ready reports whether the plan can be applied.
func (p *Plan) Ready() bool { return len(p.Blockers) == 0 }

func (p *Plan) block(format string, a ...any) {
	p.Blockers = append(p.Blockers, fmt.Sprintf(format, a...))
}
func (p *Plan) warn(format string, a ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, a...))
}
func (p *Plan) create(kind, name, detail string) {
	p.Creates = append(p.Creates, PlannedObject{Kind: kind, Name: name, Detail: detail})
}

// BuildPlan checks a package against the target Fleet Manager: version,
// licenses, exporter types, settings the target does not know, and name
// clashes. It changes nothing on the target (the configuration check uses
// Fleet Manager's validation endpoint, which does not save).
func BuildPlan(ctx context.Context, api API, fleetName string, m *Manifest, opts ImportOptions) (*Plan, error) {
	for _, x := range opts.Exclude {
		if !slices.Contains(Parts, x) {
			return nil, fmt.Errorf("unknown part %q to exclude (parts: %s)", x, strings.Join(Parts, ", "))
		}
	}
	p := &Plan{Fleet: fleetName, PolicyName: opts.name(m.Policy.Name), SourceFleet: m.Source.Fleet,
		SourceVersion: m.Source.Version, FollowUp: append([]Omission(nil), m.Omitted...), reuse: map[string]int64{}}
	if opts.Name != "" {
		p.PolicyName = opts.name(opts.Name)
	}

	// Versions must match on major.minor.
	tv, err := serverVersion(ctx, api)
	if err != nil {
		return nil, err
	}
	p.TargetVersion = tv
	smm, serr := majorMinor(m.Source.Version)
	tmm, terr := majorMinor(tv)
	switch {
	case serr != nil || terr != nil:
		p.block("cannot compare versions %q and %q", m.Source.Version, tv)
	case smm != tmm:
		p.block("version mismatch: the package is from Fleet Manager %s and the target runs %s; major.minor must match", m.Source.Version, tv)
	}

	var meta map[string]any
	if err := api.GetJSON(ctx, pathPolicyMetadata, nil, &meta); err != nil {
		return nil, err
	}
	p.configuration = p.planConfiguration(m, opts, meta)
	if err := p.checkLicenses(ctx, api, m, opts); err != nil {
		return nil, err
	}
	if err := p.validateConfiguration(ctx, api); err != nil {
		return nil, err
	}
	if err := p.planObjects(ctx, api, m, opts); err != nil {
		return nil, err
	}
	sort.Strings(p.Blockers)
	return p, nil
}

// planConfiguration decides which settings are sent and checks them
// against the target's settings schema and exporter types.
func (p *Plan) planConfiguration(m *Manifest, opts ImportOptions, meta map[string]any) map[string]any {
	props := obj(obj(meta["configuration.metadata"])["properties"])
	targetExporters := obj(meta["exporter.metadata"])
	cfg := map[string]any{}
	dropExporters := opts.excluded("exporters")
	// sendExporters is false when exporters are excluded or blocked; a
	// blocked plan then reports one blocker instead of one per setting.
	sendExporters := !dropExporters
	if !dropExporters {
		var missing []string
		for _, t := range m.Features.Exporters {
			if _, ok := targetExporters[t]; !ok {
				missing = append(missing, t)
			}
		}
		p.Exporters = m.Features.Exporters
		if len(missing) > 0 {
			p.block("the target Fleet Manager offers no %s exporter (it lists exporter types once a sensor has registered); exclude \"exporters\" or register a sensor first",
				strings.Join(missing, ", "))
			sendExporters = false
		}
	}
	var unknown []string
	for k, v := range m.Policy.Configuration {
		if strings.HasPrefix(k, "bro.exporters.") {
			if sendExporters {
				cfg[k] = v
			}
			continue
		}
		if len(props) > 0 && props[k] == nil {
			unknown = append(unknown, k)
			continue
		}
		cfg[k] = v
	}
	if dropExporters {
		var names []string
		for k, v := range m.Policy.Configuration {
			if inst, field, ok := exporterKey(k); ok && field == "name" {
				names = append(names, fmt.Sprintf("%s (%s)", str(v), inst))
			}
		}
		sort.Strings(names)
		for _, n := range names {
			p.FollowUp = append(p.FollowUp, Omission{Part: "exporters", Item: n, Reason: "excluded from this import",
				Action: "recreate exporter " + n + " on the target policy"})
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		p.block("the target does not know these settings: %s", strings.Join(unknown, ", "))
	}
	return cfg
}

// checkLicenses compares the licensed features the policy enables with
// the licenses of the target's sensors.
func (p *Plan) checkLicenses(ctx context.Context, api API, m *Manifest, opts ImportOptions) error {
	if len(m.Features.Licensed) == 0 {
		return nil
	}
	var catalog any
	if err := api.GetJSON(ctx, pathCatalog, nil, &catalog); err != nil {
		return err
	}
	sensors := listOf(catalog)
	for _, f := range m.Features.Licensed {
		lc := LicenseCheck{Feature: f, Sensors: len(sensors)}
		for _, s := range sensors {
			for _, l := range listOf(obj(s)["licenses"]) {
				if lm := obj(l); str(lm["name"]) == f && truthy(lm["active"]) {
					lc.Licensed++
				}
			}
		}
		switch {
		case lc.Sensors == 0:
			lc.Status = "unverified"
			p.warn("cannot verify the %s license: the target has no sensors yet; check licenses before assigning the policy to a group", f)
		case lc.Licensed == 0:
			lc.Status = "unlicensed"
			if opts.AllowUnlicensed {
				p.warn("no target sensor is licensed for %s; it is imported anyway (allow_unlicensed)", f)
			} else {
				p.block("no target sensor is licensed for %s, which the policy enables; license it or import with allow_unlicensed", f)
			}
		case lc.Licensed < lc.Sensors:
			lc.Status = "partial"
			p.warn("only %d of %d target sensors are licensed for %s", lc.Licensed, lc.Sensors, f)
		default:
			lc.Status = "licensed"
		}
		p.Licenses = append(p.Licenses, lc)
	}
	return nil
}

// validateConfiguration asks the target to validate the settings against
// any existing policy's metadata (all policies share one schema).
func (p *Plan) validateConfiguration(ctx context.Context, api API) error {
	var list any
	if err := api.GetJSON(ctx, pathPolicyList, nil, &list); err != nil {
		return err
	}
	pols := listOf(list)
	if len(pols) == 0 {
		p.warn("the target has no sensor policy to validate settings against; Fleet Manager validates them when the policy is created")
		return nil
	}
	if len(p.configuration) == 0 {
		return nil
	}
	path := fmt.Sprintf("%s/%d/validation", pathPolicy, idOf(obj(pols[0])["id"]))
	resp, err := api.Do(ctx, http.MethodPost, path, nil, jsonBody(map[string]any{"config": p.configuration}), "application/json")
	if err != nil {
		return fmt.Errorf("validating settings: %w", err)
	}
	var out struct {
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return fmt.Errorf("validating settings: %w", err)
	}
	if len(out.Errors) > 0 {
		p.ConfigErrors = out.Errors
		for _, k := range sortedKeys(out.Errors) {
			p.block("setting %s: %s", k, out.Errors[k])
		}
	}
	return nil
}

// planObjects lists what will be created and finds name clashes.
func (p *Plan) planObjects(ctx context.Context, api API, m *Manifest, opts ImportOptions) error {
	existing, err := loadNames(ctx, api)
	if err != nil {
		return err
	}
	clash := func(kind, name string) {
		if existing.names[kind][name] {
			p.block("a %s named %q already exists on the target; use name_suffix or a different name", kind, name)
		}
	}
	files := map[string]int64{}
	addFile := func(f *FileRef) {
		if f != nil {
			files[f.Path] = f.Size
		}
	}

	if m.Bundle != nil && !opts.excluded("bundle") {
		n := opts.name(m.Bundle.Name)
		clash("bundle", n)
		p.create("bundle", n, fmt.Sprintf("%d bytes", m.Bundle.File.Size))
		addFile(&m.Bundle.File)
	}
	if s := m.Suricata; s != nil && !opts.excluded("suricata") {
		n := opts.name(s.Name)
		clash("suricata policy", n)
		p.create("suricata policy", n, fmt.Sprintf("%d sources, %d modifier files, %d config files", len(s.Sources), len(s.ModifierFiles), len(s.Files)))
		for i := range s.Sources {
			addFile(s.Sources[i].File)
		}
		for _, k := range sortedKeys(s.Files) {
			addFile(s.Files[k])
		}
		for i := range s.ModifierFiles {
			addFile(s.ModifierFiles[i].File)
		}
	} else if s != nil {
		p.FollowUp = append(p.FollowUp, Omission{Part: "suricata", Item: s.Name, Reason: "excluded from this import", Action: "link a Suricata policy on the target"})
	}
	if y := m.Yara; y != nil && !opts.excluded("yara") {
		n := opts.name(y.Name)
		clash("YARA ruleset", n)
		for _, src := range y.Sources {
			clash("YARA source", opts.name(src.Name))
			p.create("YARA source", opts.name(src.Name), src.Namespace)
			addFile(src.File)
		}
		p.create("YARA ruleset", n, fmt.Sprintf("%d sources", len(y.Sources)))
	} else if y != nil {
		p.FollowUp = append(p.FollowUp, Omission{Part: "yara", Item: y.Name, Reason: "excluded from this import", Action: "link a YARA ruleset on the target"})
	}
	for _, r := range collectionRoles {
		c := m.Collections[r.Role]
		if c == nil {
			continue
		}
		if opts.excluded(r.Role) {
			p.FollowUp = append(p.FollowUp, Omission{Part: r.Role, Item: c.Name, Reason: "excluded from this import", Action: "link a " + r.Role + " collection on the target"})
			continue
		}
		n := opts.name(c.Name)
		clash("collection", n)
		for _, src := range c.Sources {
			key := c.Type + "|" + src.Alias + "|" + src.Name
			if id, ok := existing.sources[key+"|"+src.File.SHA256]; ok && opts.NameSuffix == "" {
				p.reuse[key] = id
				p.Reuses = append(p.Reuses, PlannedObject{Kind: "file source", Name: src.Alias + "/" + src.Name, ID: id, Detail: "identical file already on the target"})
				continue
			}
			alias := opts.name(src.Alias)
			if existing.sourceNames[c.Type+"|"+alias+"|"+src.Name] {
				p.block("a %s file source %s/%s already exists on the target with different content; use name_suffix", c.Type, alias, src.Name)
			}
			detail := fmt.Sprintf("%s, %d bytes", src.Type, src.File.Size)
			if src.Snapshot {
				detail += ", snapshot of connector " + src.Connector.Name
				p.FollowUp = append(p.FollowUp, Omission{Part: r.Role, Item: src.Alias + "/" + src.Name,
					Reason: "imported as a static snapshot of connector " + src.Connector.Name,
					Action: "create a " + src.Connector.AppConnectorID + " connector on the target to keep it updated"})
			}
			p.create("file source", alias+"/"+src.Name, detail)
			addFile(src.File)
		}
		p.create("collection", n, fmt.Sprintf("%s, %d sources", c.Type, len(c.Sources)))
	}
	clash("sensor policy", p.PolicyName)
	p.create("sensor policy", p.PolicyName, fmt.Sprintf("%d settings, %d packages enabled", len(p.configuration), countTrue(m.Policy.PackagesEnabled)))
	p.UploadFiles = len(files)
	for _, n := range files {
		p.UploadBytes += n
	}
	return nil
}

func countTrue(m map[string]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}

// names on the target, by kind.
type names map[string]map[string]bool

type targetNames struct {
	names
	// sources maps "TYPE|alias|name|sha256" to a file source ID.
	sources map[string]int64
	// sourceNames holds "TYPE|alias|name".
	sourceNames map[string]bool
}

const namesQuery = `query {
  yaraRulesets(input: {pagination: {limit: 10000}}) { rulesets { name } }
  yaraSources(input: {pagination: {limit: 10000}}) { sources { name } }
  fileCollections(input: {pagination: {limit: 10000}}) { collections { name } }
  fileSources(input: {pagination: {limit: 10000}}) { sources { id alias name type file { hash } } }
}`

func loadNames(ctx context.Context, api API) (*targetNames, error) {
	t := &targetNames{names: names{}, sources: map[string]int64{}, sourceNames: map[string]bool{}}
	add := func(kind, name string) {
		if t.names[kind] == nil {
			t.names[kind] = map[string]bool{}
		}
		t.names[kind][name] = true
	}
	for kind, path := range map[string]string{"sensor policy": pathPolicyList, "suricata policy": pathSuricataList, "bundle": pathBundle} {
		var list any
		if err := api.GetJSON(ctx, path, nil, &list); err != nil {
			return nil, err
		}
		for _, el := range listOf(list) {
			add(kind, str(obj(el)["name"]))
		}
	}
	var out struct {
		YaraRulesets struct {
			Rulesets []struct{ Name string } `json:"rulesets"`
		} `json:"yaraRulesets"`
		YaraSources struct {
			Sources []struct{ Name string } `json:"sources"`
		} `json:"yaraSources"`
		FileCollections struct {
			Collections []struct{ Name string } `json:"collections"`
		} `json:"fileCollections"`
		FileSources struct {
			Sources []struct {
				ID    any    `json:"id"`
				Alias string `json:"alias"`
				Name  string `json:"name"`
				Type  string `json:"type"`
				File  *struct {
					Hash string `json:"hash"`
				} `json:"file"`
			} `json:"sources"`
		} `json:"fileSources"`
	}
	if err := gql(ctx, api, namesQuery, nil, &out); err != nil {
		return nil, err
	}
	for _, r := range out.YaraRulesets.Rulesets {
		add("YARA ruleset", r.Name)
	}
	for _, s := range out.YaraSources.Sources {
		add("YARA source", s.Name)
	}
	for _, c := range out.FileCollections.Collections {
		add("collection", c.Name)
	}
	for _, s := range out.FileSources.Sources {
		key := s.Type + "|" + s.Alias + "|" + s.Name
		t.sourceNames[key] = true
		if s.File != nil && s.File.Hash != "" {
			t.sources[key+"|"+s.File.Hash] = idOf(s.ID)
		}
	}
	return t, nil
}
