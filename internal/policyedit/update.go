package policyedit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// UpdateRequest changes an existing sensor policy.
type UpdateRequest struct {
	Policy      string `json:"policy" jsonschema:"sensor policy id or exact name"`
	Name        string `json:"name,omitempty" jsonschema:"new name for the policy"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
	// Settings are configuration keys and their new values; null resets a
	// setting to its default.
	Settings map[string]any `json:"settings,omitempty" jsonschema:"configuration settings to change, key -> new value (JSON: true/false, numbers, strings; lists as a JSON array or a comma-separated string); null resets the setting to its default. Keys are the sensor configuration names, e.g. bro.site.local_nets"`
	// SecretSettings are keys whose values the user stored with
	// "fleet-mcp secret set-setting <key>"; they never pass through chat.
	SecretSettings  []string `json:"secret_settings,omitempty" jsonschema:"password-type settings (proxy password, exporter tokens, ...) whose values the user stored at a hidden prompt with: fleet-mcp secret set-setting <key>"`
	EnablePackages  []string `json:"enable_packages,omitempty" jsonschema:"packages to enable: Corelight packages by name (e.g. corelight:ja4 or its display name) or custom bundle packages by key or name"`
	DisablePackages []string `json:"disable_packages,omitempty" jsonschema:"packages to disable, named as in enable_packages"`
	SuricataPolicy  string   `json:"suricata_policy,omitempty" jsonschema:"Suricata policy to link (id or name), or none to unlink"`
	YaraRuleset     string   `json:"yara_ruleset,omitempty" jsonschema:"YARA ruleset to link (id or name), or none"`
	IntelCollection string   `json:"intel_collection,omitempty" jsonschema:"intel collection to link (id or name), or none"`
	InputCollection string   `json:"input_collection,omitempty" jsonschema:"input collection to link (id or name), or none"`
	// ResourceCollection is the asset classification collection.
	ResourceCollection string `json:"resource_collection,omitempty" jsonschema:"asset classification (resource) collection to link (id or name), or none"`
	CABundleCollection string `json:"ca_bundle_collection,omitempty" jsonschema:"CA bundle collection to link (id or name), or none"`
	Bundle             string `json:"bundle,omitempty" jsonschema:"package bundle to use (id or name), or none"`
}

func (r UpdateRequest) link(field string) string {
	return map[string]string{"suricataPolicyID": r.SuricataPolicy, "yaraRulesetID": r.YaraRuleset, "intelCollectionID": r.IntelCollection,
		"inputCollectionID": r.InputCollection, "resourceCollectionID": r.ResourceCollection, "caBundleCollectionID": r.CABundleCollection,
		"bundle.id": r.Bundle}[field]
}

// Change is one change in the preview.
type Change struct {
	Kind string `json:"kind"`
	Key  string `json:"item"`
	From string `json:"from"`
	To   string `json:"to"`
	Note string `json:"note,omitempty"`
}

// UpdatePlan is what an update will do; the exported fields are the
// preview.
type UpdatePlan struct {
	Policy     Ref         `json:"policy"`
	Groups     []GroupInfo `json:"groups_using_it"`
	Changes    []Change    `json:"changes"`
	Unchanged  []string    `json:"already_so,omitempty"`
	Validation string      `json:"validation,omitempty"`
	Enrichment []string    `json:"enrichment,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	Blockers   []string    `json:"blockers,omitempty"`

	body     map[string]any // the PUT body
	before   map[string]any
	expected map[string]any // configuration key -> value (nil: absent)
	pkgs     map[string]any // packages.enabled after, if changed
	linkTo   map[string]any // link field -> id or nil
	state    string
}

// Ready reports whether there is something to change and nothing blocks.
func (p *UpdatePlan) Ready() bool { return len(p.Blockers) == 0 && len(p.Changes) > 0 }

// State is what the plan was built from, for the confirm token.
func (p *UpdatePlan) State() string { return p.state }

// SecretKeys lists the secret settings the plan uses.
func (r UpdateRequest) SecretKeys() []string { return r.SecretSettings }

func (p *UpdatePlan) block(f string, a ...any) { p.Blockers = append(p.Blockers, fmt.Sprintf(f, a...)) }
func (p *UpdatePlan) warn(f string, a ...any)  { p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...)) }
func (p *UpdatePlan) note(f string, a ...any)  { p.Notes = append(p.Notes, fmt.Sprintf(f, a...)) }

// PrepareUpdate builds the plan. secrets holds the values of
// req.SecretSettings, read from fleet-mcp's secret store by the caller.
// It reads Fleet Manager and asks it to validate; it changes nothing.
func PrepareUpdate(ctx context.Context, api API, req UpdateRequest, secrets map[string]string) (*UpdatePlan, error) {
	ref, pol, err := resolvePolicy(ctx, api, req.Policy)
	if err != nil {
		return nil, err
	}
	p := &UpdatePlan{Policy: ref, body: map[string]any{"id": ref.ID}, before: pol, expected: map[string]any{}, linkTo: map[string]any{}}
	if p.Groups, err = groupsUsing(ctx, api, ref.ID); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(map[string]any{"c": pol["configuration"], "p": pol["packages.enabled"], "u": pol["record.updated-at"]})
	p.state = string(b)

	if req.Name != "" && req.Name != ref.Name {
		p.body["name"] = req.Name
		p.Changes = append(p.Changes, Change{Kind: "name", Key: "name", From: show(ref.Name), To: show(req.Name)})
	}
	if req.Description != "" && req.Description != str(pol["description"]) {
		p.body["description"] = req.Description
		p.Changes = append(p.Changes, Change{Kind: "description", Key: "description", From: show(pol["description"]), To: show(req.Description)})
	}

	props := obj(obj(pol["configuration.metadata"])["properties"])
	cfg := obj(pol["configuration"])
	changes := map[string]any{} // configuration key -> new value (nil = reset)
	setSetting := func(key string, val any, kind, note string, secret bool) {
		prop := obj(props[key])
		cur, set := cfg[key]
		from := show(cur)
		if !set {
			from = "default " + show(prop["cl:default"])
		}
		if val == nil {
			if !set {
				p.Unchanged = append(p.Unchanged, key+" is already at its default")
				return
			}
			changes[key] = nil
			p.expected[key] = nil
			p.Changes = append(p.Changes, Change{Kind: kind, Key: key, From: from, To: "default " + show(prop["cl:default"]), Note: note})
			return
		}
		if (set && sameJSON(cur, val)) || (!set && !secret && sameDefault(val, prop["cl:default"])) {
			p.Unchanged = append(p.Unchanged, fmt.Sprintf("%s is already %s", key, show(val)))
			return
		}
		changes[key] = val
		p.expected[key] = val
		to := show(val)
		if secret {
			to = "(secret from fleet-mcp's store)"
			p.expected[key] = secretMarker
		}
		if lic := str(prop["cl:internalController"]); strings.HasPrefix(lic, "system.license.") && val == true {
			note = strings.TrimSpace(note + " needs the " + strings.TrimSuffix(strings.TrimPrefix(lic, "system.license."), ".active") + " license on the sensors")
		}
		p.Changes = append(p.Changes, Change{Kind: kind, Key: key, From: from, To: to, Note: note})
	}

	for _, key := range sortedKeys(req.Settings) {
		prop := obj(props[key])
		if prop == nil {
			p.block("unknown setting %q (not in this Fleet Manager's sensor configuration)", key)
			continue
		}
		if isSecretProp(prop) {
			p.block("%q is a secret: the user stores it at a hidden prompt (fleet-mcp secret set-setting %s) and it goes in secret_settings, never in the chat", key, key)
			continue
		}
		val, err := coerce(prop, req.Settings[key])
		if err != nil {
			p.block("%s: %v", key, err)
			continue
		}
		setSetting(key, val, "setting", "", false)
	}
	for _, key := range req.SecretSettings {
		prop := obj(props[key])
		if prop == nil {
			p.block("unknown setting %q", key)
			continue
		}
		v, ok := secrets[key]
		if !ok || v == "" {
			p.block("no value stored for secret setting %q: the user runs fleet-mcp secret set-setting %s", key, key)
			continue
		}
		setSetting(key, v, "secret setting", "", true)
	}

	p.planPackages(ctx, api, req, pol, props, cfg, setSetting)
	if err := p.planLinks(ctx, api, req, pol); err != nil {
		return nil, err
	}

	if len(changes) > 0 {
		p.body["configuration"] = changes
		p.validate(ctx, api, changes, req.SecretSettings)
	}
	if p.pkgs != nil {
		p.body["packages.enabled"] = p.pkgs
	}
	for f, v := range p.linkTo {
		p.body[f] = v
	}
	if err := p.checkEnrichment(ctx, api, pol); err != nil {
		return nil, err
	}
	if len(p.Groups) == 0 {
		p.note("no sensor group uses this policy, so no sensor is affected yet")
	} else {
		n := 0
		for _, g := range p.Groups {
			n += len(g.Sensors)
		}
		p.note("%d sensor(s) in %d group(s) get the change: Fleet Manager sends the updated policy to them", n, len(p.Groups))
	}
	return p, nil
}

const secretMarker = "\x00secret"

func isSecretProp(prop map[string]any) bool {
	t := strings.ToLower(str(prop["cl:type"]))
	return t == "password" || prop["writeOnly"] == true
}

// coerce converts a value to the setting's type and checks network lists.
func coerce(prop map[string]any, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	typ := str(prop["cl:type"])
	if arr, ok := v.([]any); ok && (prop["cl:multiValuedCSV"] == true || strings.HasSuffix(typ, "List")) {
		var parts []string
		for _, x := range arr {
			parts = append(parts, strings.TrimSpace(fmt.Sprint(x)))
		}
		v = strings.Join(parts, ",")
	}
	switch typ {
	case "Boolean":
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			if b, err := strconv.ParseBool(strings.TrimSpace(x)); err == nil {
				return b, nil
			}
		}
		return nil, fmt.Errorf("expects true or false, got %s", show(v))
	case "Integer", "Int", "Number":
		switch x := v.(type) {
		case float64:
			return x, nil
		case string:
			if n, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
				return n, nil
			}
		}
		return nil, fmt.Errorf("expects a number, got %s", show(v))
	case "NetworkList", "Network", "CIDR":
		s := fmt.Sprint(v)
		for _, item := range strings.Split(s, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(item); err != nil && net.ParseIP(item) == nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR block", item)
			}
		}
		return s, nil
	}
	return v, nil
}

// validate asks Fleet Manager to check the new values (secrets are left
// out: they are checked when applied).
func (p *UpdatePlan) validate(ctx context.Context, api API, changes map[string]any, secretKeys []string) {
	skip := map[string]bool{}
	for _, k := range secretKeys {
		skip[k] = true
	}
	check := map[string]any{}
	for k, v := range changes {
		if v != nil && !skip[k] {
			check[k] = v
		}
	}
	if len(check) == 0 {
		return
	}
	resp, err := api.Do(ctx, http.MethodPost, fmt.Sprintf("%s/%d/validation", pathPolicy, p.Policy.ID), nil, jsonBody(map[string]any{"config": check}), "application/json")
	if err != nil {
		p.warn("Fleet Manager could not validate the settings: %v", err)
		return
	}
	var out struct {
		Errors map[string]string `json:"errors"`
	}
	_ = json.Unmarshal(resp.Body, &out)
	for _, k := range sortedKeys(out.Errors) {
		p.block("%s: %s", k, out.Errors[k])
	}
	p.Validation = fmt.Sprintf("Fleet Manager checked %d setting(s): %d problem(s)", len(check), len(out.Errors))
}

// planPackages resolves enable/disable requests: Corelight packages are
// settings (bro.pkgs.corelight.<name>.loaded), custom bundle packages are
// keys of packages.enabled.
func (p *UpdatePlan) planPackages(ctx context.Context, api API, req UpdateRequest, pol, props, cfg map[string]any,
	setSetting func(key string, val any, kind, note string, secret bool)) {
	if len(req.EnablePackages)+len(req.DisablePackages) == 0 {
		return
	}
	bundleKeys := map[string]bool{}
	cur := obj(pol["packages.enabled"])
	for k := range cur {
		bundleKeys[k] = true
	}
	if bid := idOf(pol["bundle.id"]); bid > 0 {
		var b map[string]any
		if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathBundle, bid), nil, &b); err == nil {
			for k := range obj(obj(b["info"])["packages"]) {
				bundleKeys[k] = true
			}
		}
	}
	newMap := map[string]any{}
	for k, v := range cur {
		newMap[k] = v
	}
	changed := false
	apply := func(names []string, on bool) {
		for _, name := range names {
			if key, ok := corelightPackage(name, pol, props); ok {
				setSetting(key, on, "package", "Corelight package "+name, false)
				continue
			}
			key, err := bundlePackage(name, bundleKeys)
			if err != nil {
				p.block("%v", err)
				continue
			}
			if newMap[key] == on {
				p.Unchanged = append(p.Unchanged, fmt.Sprintf("package %s is already %s", key, onOff(on)))
				continue
			}
			from := onOff(newMap[key] == true)
			newMap[key] = on
			changed = true
			p.Changes = append(p.Changes, Change{Kind: "package", Key: key, From: from, To: onOff(on), Note: "custom bundle package"})
		}
	}
	apply(req.EnablePackages, true)
	apply(req.DisablePackages, false)
	if changed {
		p.pkgs = newMap
	}
}

func onOff(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// corelightPackage maps a Corelight package (corelight:<name> or its
// display name) to its setting.
func corelightPackage(name string, pol, props map[string]any) (string, bool) {
	n := strings.TrimSpace(name)
	for _, m := range listOf(pol["packages.metadata"]) {
		pm := obj(m)
		full := str(pm["name"]) // corelight:<name>
		if !strings.HasPrefix(full, "corelight:") {
			continue
		}
		if strings.EqualFold(full, n) || strings.EqualFold(str(pm["package_name"]), n) || strings.EqualFold(strings.TrimPrefix(full, "corelight:"), n) {
			key := "bro.pkgs.corelight." + strings.ReplaceAll(strings.TrimPrefix(full, "corelight:"), "-", "_") + ".loaded"
			if props[key] != nil {
				return key, true
			}
		}
	}
	return "", false
}

// bundlePackage finds a custom bundle package key by exact key, or by the
// last part of its path or URL.
func bundlePackage(name string, keys map[string]bool) (string, error) {
	n := strings.TrimSpace(name)
	if keys[n] {
		return n, nil
	}
	var hits []string
	for k := range keys {
		parts := strings.Split(k, ":")
		if strings.EqualFold(parts[len(parts)-1], n) {
			hits = append(hits, k)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("no package %q: not a Corelight package and not in the policy's bundle (keys: %s)", n, strings.Join(sortedKeys(keys), ", "))
	}
	return "", fmt.Errorf("package %q is ambiguous: %s", n, strings.Join(hits, ", "))
}

func (p *UpdatePlan) planLinks(ctx context.Context, api API, req UpdateRequest, pol map[string]any) error {
	for _, l := range links {
		want := strings.TrimSpace(req.link(l.Field))
		if want == "" {
			continue
		}
		cur := idOf(pol[l.Field])
		if strings.EqualFold(want, "none") {
			if cur == 0 {
				p.Unchanged = append(p.Unchanged, "no "+l.What+" is linked")
				continue
			}
			p.linkTo[l.Field] = nil
			p.Changes = append(p.Changes, Change{Kind: "link", Key: l.Field, From: fmt.Sprintf("%s %d", l.What, cur), To: "none"})
			continue
		}
		refs, err := named(ctx, api, l.Field, l.CollectionType)
		if err != nil {
			return err
		}
		r, err := pick(refs, want, l.What)
		if err != nil {
			p.block("%v", err)
			continue
		}
		if r.ID == cur {
			p.Unchanged = append(p.Unchanged, fmt.Sprintf("%s %s is already linked", l.What, r))
			continue
		}
		from := "none"
		if cur > 0 {
			from = fmt.Sprintf("%s %d", l.What, cur)
			for _, x := range refs {
				if x.ID == cur {
					from = fmt.Sprintf("%s %s", l.What, x)
				}
			}
		}
		p.linkTo[l.Field] = r.ID
		note := ""
		if l.Field == "bundle.id" {
			note = "packages of the new bundle that are not in packages.enabled arrive disabled"
		}
		p.Changes = append(p.Changes, Change{Kind: "link", Key: l.Field, From: from, To: fmt.Sprintf("%s %s", l.What, r), Note: note})
	}
	return nil
}

// checkEnrichment reports what the policy's intel, input and resource
// collections will contain after the change, and which input files no
// loaded package reads.
func (p *UpdatePlan) checkEnrichment(ctx context.Context, api API, pol map[string]any) error {
	relevant := false
	for _, c := range p.Changes {
		if c.Kind == "package" || (c.Kind == "link" && strings.HasSuffix(c.Key, "CollectionID")) {
			relevant = true
		}
	}
	if !relevant {
		return nil
	}
	cs, err := collections(ctx, api)
	if err != nil {
		return err
	}
	byID := map[int64]map[string]any{}
	for _, c := range cs {
		byID[idOf(c["id"])] = c
	}
	var inputFiles []string
	for _, l := range links {
		if l.CollectionType == "" || l.CollectionType == "CA_BUNDLES" {
			continue
		}
		id := idOf(pol[l.Field])
		if v, ok := p.linkTo[l.Field]; ok {
			id = idOf(v)
		}
		if id == 0 {
			continue
		}
		c := byID[id]
		if c == nil {
			continue
		}
		srcs := listOf(c["sources"])
		if len(srcs) == 0 {
			p.Enrichment = append(p.Enrichment, fmt.Sprintf("%s %q has no sources: it delivers nothing", l.What, str(c["name"])))
			continue
		}
		for _, s := range srcs {
			m := obj(s)
			label := fmt.Sprintf("%s %q source %q (%s)", l.What, str(c["name"]), str(m["alias"]), str(m["name"]))
			switch {
			case m["enabled"] != true:
				p.Enrichment = append(p.Enrichment, label+": disabled, sensors do not get it")
			case obj(m["file"]) == nil && obj(m["connector"]) == nil:
				p.Enrichment = append(p.Enrichment, label+": has no file yet")
			case obj(m["connector"]) != nil:
				p.Enrichment = append(p.Enrichment, label+": fed by connector "+str(obj(m["connector"])["name"]))
			default:
				p.Enrichment = append(p.Enrichment, label+": ok")
			}
			if l.CollectionType == "INPUT" && m["enabled"] == true {
				inputFiles = append(inputFiles, str(m["name"]))
			}
		}
	}
	if len(inputFiles) == 0 {
		return nil
	}
	var cat struct {
		List []map[string]any `json:"list"`
	}
	if err := api.GetJSON(ctx, pathCatalog, nil, &cat); err != nil {
		return nil
	}
	readers := map[string]map[string]bool{}
	connected := 0
	for _, s := range cat.List {
		if s["fleet.connected"] != true {
			continue
		}
		connected++
		for _, in := range listOf(s["bro.inputs"]) {
			m := obj(in)
			if readers[str(m["name"])] == nil {
				readers[str(m["name"])] = map[string]bool{}
			}
			readers[str(m["name"])][str(m["package"])] = true
		}
	}
	if connected == 0 {
		p.Enrichment = append(p.Enrichment, "no sensor is connected, so which package reads each input file cannot be checked")
		return nil
	}
	for _, f := range inputFiles {
		if r := readers[f]; len(r) > 0 {
			p.Enrichment = append(p.Enrichment, fmt.Sprintf("input file %s is read by %s on the connected sensors", f, strings.Join(sortedKeys(r), ", ")))
		} else {
			p.Enrichment = append(p.Enrichment, fmt.Sprintf("no connected sensor has a loaded package that reads input file %s: it does nothing until one is enabled", f))
		}
	}
	return nil
}

// UpdateResult is what an update did.
type UpdateResult struct {
	Done         []string `json:"done"`
	Verification []string `json:"verification,omitempty"`
}

// ApplyUpdate sends the change in one PUT and reads the policy back.
func ApplyUpdate(ctx context.Context, api API, p *UpdatePlan) (*UpdateResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to change or blocked: %v", p.Blockers)
	}
	res := &UpdateResult{}
	resp, err := api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathPolicy, p.Policy.ID), nil, jsonBody(p.body), "application/json")
	if err != nil {
		return res, fmt.Errorf("updating sensor policy %s: %w", p.Policy, err)
	}
	var d struct {
		Delta     map[string]any `json:"configuration.delta"`
		Deletions []string       `json:"configuration.deletions"`
	}
	_ = json.Unmarshal(resp.Body, &d)
	res.Done = append(res.Done, fmt.Sprintf("updated sensor policy %s: %d setting(s) changed, %d reset to default", p.Policy, len(d.Delta), len(d.Deletions)))

	var after map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, p.Policy.ID), nil, &after); err != nil {
		res.Verification = append(res.Verification, fmt.Sprintf("could not read the policy back: %v", err))
		return res, nil
	}
	cfg := obj(after["configuration"])
	for k, want := range p.expected {
		got, set := cfg[k]
		switch {
		case want == nil:
			if set {
				res.Verification = append(res.Verification, fmt.Sprintf("%s is still set to %s", k, show(got)))
			}
		case want == secretMarker:
			if !set {
				res.Verification = append(res.Verification, k+" is not set")
			}
		case !set:
			// Fleet Manager does not store a value equal to the default.
			if def := obj(obj(obj(after["configuration.metadata"])["properties"])[k])["cl:default"]; !sameDefault(want, def) {
				res.Verification = append(res.Verification, fmt.Sprintf("%s is not set (wanted %s)", k, show(want)))
			}
		case !sameJSON(got, want):
			res.Verification = append(res.Verification, fmt.Sprintf("%s is %s, wanted %s", k, show(got), show(want)))
		}
	}
	before := obj(p.before["configuration"])
	for k, v := range before {
		if _, changed := p.expected[k]; !changed && !sameJSON(v, cfg[k]) {
			res.Verification = append(res.Verification, fmt.Sprintf("%s changed too: %s -> %s", k, show(v), show(cfg[k])))
		}
	}
	for k := range cfg {
		if _, was := before[k]; !was {
			if _, changed := p.expected[k]; !changed {
				res.Verification = append(res.Verification, fmt.Sprintf("%s appeared: %s", k, show(cfg[k])))
			}
		}
	}
	if p.pkgs != nil && !sameJSON(obj(after["packages.enabled"]), p.pkgs) {
		res.Verification = append(res.Verification, "packages.enabled is not as planned")
	}
	for f, v := range p.linkTo {
		if idOf(after[f]) != idOf(v) {
			res.Verification = append(res.Verification, fmt.Sprintf("%s is %v, wanted %v", f, after[f], v))
		}
	}
	for _, f := range []string{"name", "description"} {
		if v, ok := p.body[f]; ok && str(after[f]) != v {
			res.Verification = append(res.Verification, fmt.Sprintf("%s is %q, wanted %q", f, str(after[f]), v))
		}
	}
	return res, nil
}

// sameDefault compares a value with a metadata default ("0"/"1" for
// booleans, strings otherwise).
func sameDefault(v, def any) bool {
	d := str(def)
	switch x := v.(type) {
	case bool:
		return (x && d == "1") || (!x && (d == "0" || d == ""))
	case float64:
		n, err := strconv.ParseFloat(d, 64)
		return err == nil && n == x
	case string:
		return x == d
	}
	return false
}
