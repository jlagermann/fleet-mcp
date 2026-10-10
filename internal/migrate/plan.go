package migrate

import (
	"context"
	"encoding/json"
	"errors"
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
	// Exclude leaves parts (see Parts) out of the import.
	Exclude []string `json:"exclude,omitempty"`
	// Complete adds parts an earlier import of the same package into the
	// same Fleet Manager left out (today: exporters) to the policy that
	// import created. Name, NameSuffix and Exclude do not apply.
	Complete bool `json:"complete,omitempty"`
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
	// Decisions are questions for the user; the plan is not ready until
	// each is answered by changing the options (see Decision.Resolve).
	Decisions []Decision `json:"decisions,omitempty"`
	Blockers  []string   `json:"blockers,omitempty"`
	Warnings  []string   `json:"warnings,omitempty"`
	FollowUp  []Omission `json:"follow_up,omitempty"`

	// reuse maps "TYPE|alias|name" to an existing identical file source.
	reuse map[string]int64
	// configuration is the policy configuration that will be sent.
	configuration map[string]any
	// suricataSettings are the Suricata settings that will be sent.
	suricataSettings map[string]any
	// completeInto is the existing policy a completion updates.
	completeInto int64
	// deferred are the parts this import leaves for a later completion.
	deferred []string
}

// Decision is a question the user must answer before the import runs.
type Decision struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	// Resolve says how each answer changes the request.
	Resolve map[string]string `json:"resolve"`
}

// PlannedObject is one object an import creates or reuses.
type PlannedObject struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	ID     int64  `json:"id,omitempty"`
}

// LicenseCheck reports how many target sensors hold a feature's license.
// It is informational: it never blocks or warns.
type LicenseCheck struct {
	Feature  string `json:"feature"`
	Licensed int    `json:"licensed_sensors"`
	Sensors  int    `json:"sensors"`
	Status   string `json:"status"` // licensed, partial, unlicensed, no sensors
}

// Ready reports whether the plan can be applied.
func (p *Plan) Ready() bool { return len(p.Blockers) == 0 && len(p.Decisions) == 0 }

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
// dir is the package directory; a completion (opts.Complete) reads the
// earlier import from it.
func BuildPlan(ctx context.Context, api API, fleetName, dir string, m *Manifest, opts ImportOptions) (*Plan, error) {
	if opts.Complete && (opts.Name != "" || opts.NameSuffix != "" || len(opts.Exclude) > 0) {
		return nil, errors.New("complete adds to the policy an earlier import created; name, name_suffix and exclude do not apply")
	}
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
	if opts.Complete {
		if err := p.planCompletion(ctx, api, dir, m, meta); err != nil {
			return nil, err
		}
		if p.Ready() && len(p.configuration) > 0 {
			if err := p.validateConfiguration(ctx, api); err != nil {
				return nil, err
			}
		}
		sort.Strings(p.Blockers)
		return p, nil
	}
	p.configuration = p.planConfiguration(m, opts, meta)
	if m.Suricata != nil && !opts.excluded("suricata") {
		if err := p.planSuricataSettings(ctx, api, m.Suricata); err != nil {
			return nil, err
		}
	}
	if err := p.checkLicenses(ctx, api, m); err != nil {
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
	if !dropExporters && len(m.Features.Exporters) > 0 {
		p.Exporters = m.Features.Exporters
		if missing := missingExporterTypes(m, targetExporters); len(missing) > 0 {
			names := exporterNames(m.Policy.Configuration)
			p.Decisions = append(p.Decisions, Decision{
				ID: "exporters",
				Question: fmt.Sprintf("The %d exporters (%s) cannot be migrated yet: %s offers no %s exporter type until a sensor is attached to it. Continue with everything else and add the exporters later?",
					len(names), strings.Join(names, ", "), p.Fleet, strings.Join(missing, ", ")),
				Resolve: map[string]string{
					"yes": `import with exclude ["exporters"]; after a sensor is attached, import the same package again with complete: true to add the exporters to the policy`,
					"no":  "attach a sensor to the target Fleet Manager first, then preview again",
				},
			})
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
	if dropExporters && len(m.Features.Exporters) > 0 {
		// Left for a completion run; their tokens stay on the follow-up
		// list because they are entered after the completion.
		p.deferred = append(p.deferred, "exporters")
		for _, n := range exporterNames(m.Policy.Configuration) {
			p.FollowUp = append(p.FollowUp, Omission{Part: "exporters", Item: n, Reason: "left out of this import",
				Action: "after a sensor is attached to " + p.Fleet + ", import this package again with complete: true to add it"})
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		p.block("the target does not know these settings: %s", strings.Join(unknown, ", "))
	}
	return cfg
}

// checkLicenses reports, for information only, how many target sensors
// hold the licenses for the features the policy enables. Importing a
// policy never depends on sensors; licenses matter when a policy is
// assigned to a group with sensors in it.
func (p *Plan) checkLicenses(ctx context.Context, api API, m *Manifest) error {
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
			lc.Status = "no sensors"
		case lc.Licensed == 0:
			lc.Status = "unlicensed"
		case lc.Licensed < lc.Sensors:
			lc.Status = "partial"
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
		p.create("suricata policy", n, fmt.Sprintf("%d sources, %d modifier files, %d rule modifiers, %d config files", len(s.Sources), len(s.ModifierFiles), len(s.RuleModifiers), len(s.Files)))
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

// planSuricataSettings drops Suricata settings the target's Suricata
// schema does not know (Fleet Manager would silently discard them) and
// reports them.
func (p *Plan) planSuricataSettings(ctx context.Context, api API, s *Suricata) error {
	var meta map[string]any
	if err := api.GetJSON(ctx, pathSuricataMeta, nil, &meta); err != nil {
		return err
	}
	props := obj(meta["properties"])
	p.suricataSettings = map[string]any{}
	var unknown []string
	for k, v := range s.Settings {
		if len(props) > 0 && !schemaHas(props, k) {
			unknown = append(unknown, k)
			continue
		}
		p.suricataSettings[k] = v
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		p.FollowUp = append(p.FollowUp, Omission{Part: "suricata", Item: k,
			Reason: "the target's Suricata settings schema does not have this setting (left over from an older version?)",
			Action: "check whether a current setting replaces " + k})
	}
	if len(unknown) > 0 {
		p.warn("%d Suricata settings are unknown to the target and are not copied: %s", len(unknown), strings.Join(unknown, ", "))
	}
	return nil
}

// schemaHas reports whether a settings schema defines key, directly or
// through a "prefix.*" pattern.
func schemaHas(props map[string]any, key string) bool {
	if _, ok := props[key]; ok {
		return true
	}
	for k := range props {
		if prefix, ok := strings.CutSuffix(k, ".*"); ok && strings.HasPrefix(key, prefix+".") {
			return true
		}
	}
	return false
}
