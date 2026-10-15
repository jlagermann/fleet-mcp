package content

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// Fleet Manager endpoints.
const (
	pathPolicyList   = "/fleet/v1/sensor/policy/list"
	pathPolicy       = "/fleet/v1/sensor/policy"
	pathBundle       = "/fleet/v1/sensor/bundle"
	pathSuricata     = "/fleet/v1/suricata"
	pathSuricataList = "/fleet/v1/suricata/policies"
	pathValidate     = "/fleet/v1/suricata/validate/rules"
	pathCatalog      = "/fleet/v1/sensor/catalog"
	pathFiles        = "/fleet/v1/filemgr/files/"
	pathStores       = "/fleet/v1/filemgr/stores/"
)

const (
	qFileSources = `query($input: FileSourceQuery) { fileSources(input: $input) { sources { id alias name description enabled connector { name } file { id name hash sizeBytes } } } }`
	qCollections = `query($input: FileCollectionQuery) { fileCollections(input: $input) { collections { id name type sources { id } } } }`
	qYaraSources = `query { yaraSources { sources { id name namespace description enabled file { id name hash sizeBytes } } } }`
	qYaraSets    = `query { yaraRulesets { rulesets { id name sources { id } } } }`
	mValidYara   = `mutation($input: FileValidationYara!) { validateYaraFile(input: $input) { isValid } }`
)

// Prepare builds the plan for a push. It reads Fleet Manager and the local
// file and changes nothing (Fleet Manager's validation endpoints are the
// only calls that are not GETs or queries).
func Prepare(ctx context.Context, api API, req Request) (*Plan, error) {
	req.Kind = Kind(strings.ToLower(strings.TrimSpace(string(req.Kind))))
	b, fi, err := readLocal(req.File)
	if err != nil {
		return nil, err
	}
	p := &Plan{Kind: req.Kind, File: fi, req: req, content: b, fileNm: filepath.Base(fi.Path)}
	if req.Description == "" {
		p.req.Description = DefaultDescription
	}
	if len(b) == 0 {
		p.block("the file is empty")
	}
	switch req.Kind {
	case Intel, Input:
		err = p.planFileSource(ctx, api)
	case Yara:
		err = p.planYara(ctx, api)
	case SuricataRules:
		err = p.planSuricataRules(ctx, api)
	case SuricataYAML, SuricataThreshold, SuricataClassification, SuricataReference:
		err = p.planSuricataConfig(ctx, api)
	case SuricataDisable, SuricataEnable, SuricataModify:
		err = p.planSuricataModifier(ctx, api)
	case Bundle:
		err = p.planBundle(ctx, api)
	default:
		return nil, fmt.Errorf("kind must be one of %s", strings.Join(Kinds(), ", "))
	}
	if err != nil {
		return nil, err
	}
	p.sameFile = p.Unchanged
	if p.Unchanged {
		p.Steps = nil
		p.note("Fleet Manager already has this exact file (same SHA-256); nothing to push.")
		if p.link.needed && !p.link.alreadyIn {
			p.Unchanged = false
			p.planLinkSteps()
		}
	}
	return p, nil
}

// download fetches a file-manager file.
func download(ctx context.Context, api API, fileID int64) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := api.Download(ctx, fmt.Sprintf("%s%d/content", pathFiles, fileID), &buf, MaxFileBytes); err != nil {
		return nil, fmt.Errorf("downloading file %d: %w", fileID, err)
	}
	return buf.Bytes(), nil
}

// resolvePolicy finds a sensor policy by id or exact name and returns it.
func resolvePolicy(ctx context.Context, api API, ref string) (*PolicyRef, map[string]any, error) {
	var list []map[string]any
	if err := api.GetJSON(ctx, pathPolicyList, nil, &list); err != nil {
		return nil, nil, fmt.Errorf("listing sensor policies: %w", err)
	}
	ref = strings.TrimSpace(ref)
	id, _ := strconv.ParseInt(ref, 10, 64)
	var names []string
	for _, pol := range list {
		names = append(names, str(pol["name"]))
		if (id > 0 && idOf(pol["id"]) == id) || str(pol["name"]) == ref {
			pid := idOf(pol["id"])
			var full map[string]any
			if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, pid), nil, &full); err != nil {
				return nil, nil, fmt.Errorf("reading sensor policy %d: %w", pid, err)
			}
			return &PolicyRef{ID: pid, Name: str(pol["name"])}, full, nil
		}
	}
	return nil, nil, fmt.Errorf("no sensor policy %q; policies: %s", ref, strings.Join(names, ", "))
}

// policiesUsing lists the sensor policies whose field is one of ids.
func policiesUsing(ctx context.Context, api API, field string, ids map[int64]bool) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var list []map[string]any
	if err := api.GetJSON(ctx, pathPolicyList, nil, &list); err != nil {
		return nil, err
	}
	var out []string
	for _, pol := range list {
		var full map[string]any
		if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, idOf(pol["id"])), nil, &full); err != nil {
			return nil, err
		}
		if ids[idOf(full[field])] {
			out = append(out, fmt.Sprintf("%s (%d)", str(pol["name"]), idOf(pol["id"])))
		}
	}
	return out, nil
}

// --- intel and input file sources ---

func (p *Plan) planFileSource(ctx context.Context, api API) error {
	typ, field, what := "INTEL", "intelCollectionID", "intel"
	if p.Kind == Input {
		typ, field, what = "INPUT", "inputCollectionID", "input"
	}
	fileName := p.req.Name
	if p.Kind == Intel {
		fileName = "bro_intel.dat" // Fleet Manager's name for every intel source
		if p.req.Name != "" {
			p.note("name is ignored for intel: Fleet Manager names every intel file bro_intel.dat on the sensors.")
		}
	} else if fileName == "" {
		fileName = p.fileNm
	}
	alias := p.req.Source
	if alias == "" {
		alias = DefaultSource
		if p.Kind == Input {
			alias = fileName
		}
	}
	p.Target = Target{Object: what + " file source", Name: alias}

	var out struct {
		FileSources struct {
			Sources []map[string]any `json:"sources"`
		} `json:"fileSources"`
	}
	if err := gql(ctx, api, qFileSources, map[string]any{"input": map[string]any{"type": typ, "pagination": map[string]any{"limit": 10000}}}, &out); err != nil {
		return fmt.Errorf("listing %s file sources: %w", what, err)
	}
	var cur map[string]any
	for _, s := range out.FileSources.Sources {
		if str(s["alias"]) == alias {
			cur = s
			break
		}
	}

	var old []byte
	if cur != nil {
		p.Target.Exists, p.Target.ID = true, idOf(cur["id"])
		p.Target.ManagedBy = managedBy(alias, str(cur["description"]))
		if c := obj(cur["connector"]); c != nil {
			p.block("file source %q is fed by the connector %q; Fleet Manager refetches it, so push to another alias", alias, str(c["name"]))
		}
		if p.Kind == Input && str(cur["name"]) != fileName {
			p.warn("the source's file name on the sensors changes from %s to %s; a package reading %s no longer finds it", str(cur["name"]), fileName, str(cur["name"]))
		}
		if cur["enabled"] != true {
			p.warn("file source %q is disabled; the update keeps it disabled, so sensors do not get it", alias)
		}
		if f := obj(cur["file"]); f != nil {
			p.Target.CurrentSHA256, p.Target.CurrentSize = str(f["hash"]), idOf(f["sizeBytes"])
			if p.Target.CurrentSHA256 == p.File.SHA256 && str(cur["name"]) == fileName {
				p.Unchanged = true
			} else {
				var err error
				if old, err = download(ctx, api, idOf(f["id"])); err != nil {
					return err
				}
			}
		}
		p.step("update %s file source %q (id %d) in place with the new file", what, alias, p.Target.ID)
	} else {
		p.step("create %s file source %q (file %s on the sensors)", what, alias, fileName)
	}
	p.state = append(p.state, fileName)
	if p.Target.ManagedBy != "" && p.Target.ManagedBy != "fleet-mcp" {
		p.note("%q is managed by %s; if it still runs, its next push overwrites this one.", alias, p.Target.ManagedBy)
	}

	if p.Kind == Intel {
		p.Diff = diffRecords(old, p.content, old != nil, 2, "indicators")
		if p.Diff["fields_header"] != nil {
			p.block("the intel file has no #fields header; Zeek's intel framework cannot read it")
		}
	} else {
		p.Diff = diffRecords(old, p.content, old != nil, 0, "records")
		if p.Diff["fields_header"] != nil {
			p.warn("the input file has no #fields header; Zeek's input framework needs one")
		}
	}

	// Collections holding the source, and the policies using them.
	var colls struct {
		FileCollections struct {
			Collections []map[string]any `json:"collections"`
		} `json:"fileCollections"`
	}
	if err := gql(ctx, api, qCollections, map[string]any{"input": map[string]any{"pagination": map[string]any{"limit": 10000}}}, &colls); err != nil {
		return fmt.Errorf("listing collections: %w", err)
	}
	in := map[int64]bool{}
	byName := map[string]int64{}
	for _, c := range colls.FileCollections.Collections {
		if str(c["type"]) != typ {
			continue
		}
		byName[str(c["name"])] = idOf(c["id"])
		for _, s := range listOf(c["sources"]) {
			if p.Target.Exists && idOf(obj(s)["id"]) == p.Target.ID {
				in[idOf(c["id"])] = true
			}
		}
	}
	used, err := policiesUsing(ctx, api, field, in)
	if err != nil {
		return err
	}
	p.UsedBy = used

	if p.req.Policy != "" {
		if err := p.planLink(ctx, api, field, in, byName); err != nil {
			return err
		}
	} else if len(used) == 0 {
		p.warn("no sensor policy uses a collection with this source, so no sensor gets it; pass policy to link it")
	}
	if p.Kind == Input {
		if err := p.checkReaders(ctx, api, fileName); err != nil {
			return err
		}
	}
	return nil
}

// planLink plans adding the source to the policy's collection or ruleset,
// or creating one named after the policy and linking it.
func (p *Plan) planLink(ctx context.Context, api API, field string, in map[int64]bool, byName map[string]int64) error {
	ref, body, err := resolvePolicy(ctx, api, p.req.Policy)
	if err != nil {
		return err
	}
	p.Policy, p.policyBody = ref, body
	p.link = linkPlan{needed: true, policyField: field}
	if id := idOf(body[field]); id > 0 {
		p.link.collectionID = id
		p.link.alreadyIn = in[id]
		p.state = append(p.state, fmt.Sprintf("%s=%d", field, id))
	} else {
		name := ref.Name
		if id, ok := byName[name]; ok {
			p.link.collectionID = id // an unlinked one named after the policy
			p.link.alreadyIn = in[id]
		} else {
			p.link.createName = name
		}
		p.state = append(p.state, field+"=none")
	}
	p.planLinkSteps()
	return nil
}

func (p *Plan) planLinkSteps() {
	l := p.link
	what := map[string]string{"intelCollectionID": "intel collection", "inputCollectionID": "input collection", "yaraRulesetID": "YARA ruleset"}[l.policyField]
	switch {
	case l.alreadyIn && idOf(p.policyBody[l.policyField]) == l.collectionID:
		p.note("the source is already in %s %d of sensor policy %q", what, l.collectionID, p.Policy.Name)
	case l.createName != "":
		p.step("create %s %q with the source", what, l.createName)
		p.step("link it to sensor policy %q (%d); Fleet Manager then sends it to the policy's sensors", p.Policy.Name, p.Policy.ID)
	default:
		if !l.alreadyIn {
			p.step("add the source to %s %d", what, l.collectionID)
		}
		if idOf(p.policyBody[l.policyField]) != l.collectionID {
			p.step("link %s %d to sensor policy %q (%d)", what, l.collectionID, p.Policy.Name, p.Policy.ID)
		}
	}
}

// checkReaders reports which package the connected sensors say reads the
// input file (bro.inputs lists files a loaded package looks for).
func (p *Plan) checkReaders(ctx context.Context, api API, file string) error {
	var cat struct {
		List []map[string]any `json:"list"`
	}
	if err := api.GetJSON(ctx, pathCatalog, nil, &cat); err != nil {
		return fmt.Errorf("reading the sensor catalog: %w", err)
	}
	readers := map[string]bool{}
	connected := 0
	for _, s := range cat.List {
		if s["fleet.connected"] != true {
			continue
		}
		connected++
		for _, in := range listOf(s["bro.inputs"]) {
			if m := obj(in); str(m["name"]) == file && str(m["package"]) != "" {
				readers[str(m["package"])] = true
			}
		}
	}
	switch {
	case len(readers) > 0:
		p.note("connected sensors report %s is read by: %s", file, strings.Join(sortedKeys(readers), ", "))
	case connected == 0:
		p.warn("no sensor is connected, so fleet-mcp cannot check which package reads %s", file)
	default:
		p.warn("no connected sensor has a loaded package that reads %s; it does nothing until such a package is enabled (check the file name)", file)
	}
	return nil
}

// --- YARA ---

func (p *Plan) planYara(ctx context.Context, api API) error {
	name := p.req.Source
	if name == "" {
		name = DefaultSource
	}
	p.Target = Target{Object: "YARA source", Name: name}
	var out struct {
		YaraSources struct {
			Sources []map[string]any `json:"sources"`
		} `json:"yaraSources"`
	}
	if err := gql(ctx, api, qYaraSources, nil, &out); err != nil {
		return fmt.Errorf("listing YARA sources: %w", err)
	}
	var old []byte
	for _, s := range out.YaraSources.Sources {
		if str(s["name"]) != name {
			continue
		}
		p.Target.Exists, p.Target.ID = true, idOf(s["id"])
		p.Target.ManagedBy = managedBy(name, str(s["description"]))
		if f := obj(s["file"]); f != nil {
			p.Target.CurrentSHA256, p.Target.CurrentSize = str(f["hash"]), idOf(f["sizeBytes"])
			if p.Target.CurrentSHA256 != "" && p.Target.CurrentSHA256 == p.File.SHA256 {
				p.Unchanged = true
			} else {
				var err error
				if old, err = download(ctx, api, idOf(f["id"])); err != nil {
					return err
				}
				sum := sha256Hex(old)
				p.Target.CurrentSHA256 = sum
				if sum == p.File.SHA256 {
					p.Unchanged = true
				}
			}
		}
		break
	}
	if p.Target.Exists {
		p.step("update YARA source %q (id %d) in place with the new file", name, p.Target.ID)
	} else {
		p.step("create YARA source %q (namespace %s)", name, DefaultSource)
	}
	if p.Target.ManagedBy != "" && p.Target.ManagedBy != "fleet-mcp" {
		p.note("%q is managed by %s; if it still runs, its next push overwrites this one.", name, p.Target.ManagedBy)
	}
	p.Diff = diffYara(old, p.content, old != nil)
	if p.Diff["rules"] == 0 {
		p.block("no YARA rule found in the file")
	}
	if !p.Unchanged {
		var v struct {
			ValidateYaraFile struct {
				IsValid bool `json:"isValid"`
			} `json:"validateYaraFile"`
		}
		resp, err := api.GraphQLUpload(ctx, mValidYara, map[string]any{"input": map[string]any{"file": nil}}, "variables.input.file", p.fileNm, p.content)
		if err := decodeGraphQL(resp, err, &v); err != nil {
			p.Validation = map[string]any{"valid": false, "error": err.Error()}
			p.block("Fleet Manager rejected the YARA file: %v", err)
		} else {
			p.Validation = map[string]any{"valid": v.ValidateYaraFile.IsValid, "by": "Fleet Manager validateYaraFile"}
			if !v.ValidateYaraFile.IsValid {
				p.block("Fleet Manager says the YARA file is not valid")
			}
		}
	}

	var sets struct {
		YaraRulesets struct {
			Rulesets []map[string]any `json:"rulesets"`
		} `json:"yaraRulesets"`
	}
	if err := gql(ctx, api, qYaraSets, nil, &sets); err != nil {
		return fmt.Errorf("listing YARA rulesets: %w", err)
	}
	in := map[int64]bool{}
	byName := map[string]int64{}
	for _, rs := range sets.YaraRulesets.Rulesets {
		byName[str(rs["name"])] = idOf(rs["id"])
		for _, s := range listOf(rs["sources"]) {
			if p.Target.Exists && idOf(obj(s)["id"]) == p.Target.ID {
				in[idOf(rs["id"])] = true
			}
		}
	}
	used, err := policiesUsing(ctx, api, "yaraRulesetID", in)
	if err != nil {
		return err
	}
	p.UsedBy = used
	if p.req.Policy != "" {
		return p.planLink(ctx, api, "yaraRulesetID", in, byName)
	}
	if len(used) == 0 {
		p.warn("no sensor policy uses a YARA ruleset with this source, so no sensor gets it; pass policy to link it")
	}
	return nil
}

// --- Suricata ---

// resolveSuricata finds the Suricata policy from suricata_policy, or from
// the sensor policy's link.
func (p *Plan) resolveSuricata(ctx context.Context, api API) error {
	ref := p.req.SuricataPolicy
	if ref == "" && p.req.Policy != "" {
		pol, body, err := resolvePolicy(ctx, api, p.req.Policy)
		if err != nil {
			return err
		}
		p.Policy = pol
		if idOf(body["suricataPolicyID"]) == 0 {
			return fmt.Errorf("sensor policy %q has no Suricata policy; pass suricata_policy", pol.Name)
		}
		ref = strconv.FormatInt(idOf(body["suricataPolicyID"]), 10)
	}
	if ref == "" {
		return fmt.Errorf("%s needs suricata_policy (or policy, to use its Suricata policy)", p.Kind)
	}
	var list []map[string]any
	if err := api.GetJSON(ctx, pathSuricataList, nil, &list); err != nil {
		return fmt.Errorf("listing Suricata policies: %w", err)
	}
	id, _ := strconv.ParseInt(ref, 10, 64)
	var names []string
	for _, sp := range list {
		names = append(names, str(sp["name"]))
		if (id > 0 && idOf(sp["id"]) == id) || str(sp["name"]) == ref {
			var full map[string]any
			if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathSuricata, idOf(sp["id"])), nil, &full); err != nil {
				return fmt.Errorf("reading Suricata policy: %w", err)
			}
			p.suricata = full
			used, err := policiesUsing(ctx, api, "suricataPolicyID", map[int64]bool{idOf(sp["id"]): true})
			if err != nil {
				return err
			}
			p.UsedBy = used
			if len(used) == 0 {
				p.warn("no sensor policy uses Suricata policy %q, so no sensor gets this", str(full["name"]))
			}
			return nil
		}
	}
	return fmt.Errorf("no Suricata policy %q; Suricata policies: %s", ref, strings.Join(names, ", "))
}

func (p *Plan) planSuricataRules(ctx context.Context, api API) error {
	if err := p.resolveSuricata(ctx, api); err != nil {
		return err
	}
	sp := p.suricata
	spName, spID := str(sp["name"]), idOf(sp["id"])
	var oldID int64
	if sp["rulesAutomation"] == true {
		name := p.req.Source
		if name == "" {
			name = DefaultSource
		}
		p.Target = Target{Object: fmt.Sprintf("rule source of Suricata policy %q (%d)", spName, spID), Name: name}
		for _, s := range listOf(sp["sources"]) {
			m := obj(s)
			if str(m["name"]) != name {
				continue
			}
			if str(m["entityType"]) != "file" {
				p.block("rule source %q of Suricata policy %q is a URL source; push to another source name", name, spName)
			}
			p.Target.Exists, p.Target.ID = true, idOf(m["id"])
			p.Target.ManagedBy = managedBy(name, str(m["created_by"]))
			oldID = idOf(m["fileId"])
			if m["enabled"] != true {
				p.warn("rule source %q is disabled; the update keeps it disabled", name)
			}
		}
		if p.Target.Exists {
			p.step("upload the rules file and point rule source %q of Suricata policy %q at it", name, spName)
		} else {
			p.step("upload the rules file and add it to Suricata policy %q as rule source %q", spName, name)
		}
		p.note("Suricata policy %q uses rules automation: Fleet Manager combines its enabled rule sources and applies its modifiers to build the ruleset it sends.", spName)
	} else {
		p.Target = Target{Object: fmt.Sprintf("rules file of Suricata policy %q (%d)", spName, spID), Name: "suricata.rules", Exists: true, ID: spID}
		oldID = idOf(obj(obj(sp["fileInfo"])["suricata-file-id"])["id"])
		p.step("upload the rules file and make it the rule set of Suricata policy %q (it replaces all of the policy's rules)", spName)
	}
	if p.Target.ManagedBy != "" && p.Target.ManagedBy != "fleet-mcp" {
		p.note("%q is managed by %s; if it still runs, its next push overwrites this one.", p.Target.Name, p.Target.ManagedBy)
	}
	var old []byte
	if oldID > 0 {
		var err error
		if old, err = download(ctx, api, oldID); err != nil {
			return err
		}
		p.Target.CurrentSHA256, p.Target.CurrentSize = sha256Hex(old), int64(len(old))
		if p.Target.CurrentSHA256 == p.File.SHA256 {
			p.Unchanged = true
		}
	}
	p.Diff = diffSuricata(old, p.content, old != nil)
	if p.Diff["rules"] == 0 {
		p.block("no Suricata rule with a sid found in the file")
	}
	if !p.Unchanged {
		p.validateRules(ctx, api)
	}
	p.state = append(p.state, fmt.Sprintf("suricata=%d", spID))
	return nil
}

// validateRules asks Fleet Manager to check the rules file.
func (p *Plan) validateRules(ctx context.Context, api API) {
	resp, err := api.DoMultipart(ctx, http.MethodPost, pathValidate, nil, fleet.FilePart{Field: "content", FileName: p.fileNm, Content: p.content})
	if err != nil {
		p.Validation = map[string]any{"error": err.Error()}
		p.warn("Fleet Manager could not validate the rules file: %v", err)
		return
	}
	var v map[string]any
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		p.warn("Fleet Manager's validation response was not JSON")
		return
	}
	p.Validation = map[string]any{"by": "Fleet Manager rule parser (it parses the rules; it does not run Suricata)", "rules": v["ruleCount"], "enabled": v["enabledRuleCount"], "disabled": v["disabledRuleCount"], "errors": v["errorCount"]}
	if errs := listOf(v["errors"]); len(errs) > 0 {
		var s []string
		for _, e := range errs {
			s = append(s, clip(str(e)))
		}
		p.Validation["error_sample"] = sample(s, 10)
	}
	if d := obj(v["duplicateSIDs"]); len(d) > 0 {
		p.Validation["duplicate_sids"] = sample(sortedKeys(d), 10)
		p.warn("%d duplicate SID(s) in the file", len(d))
	}
	if n := idOf(v["errorCount"]); n > 0 {
		p.warn("Fleet Manager found %d rule error(s); those rules fail to load on the sensors", n)
	}
}

func (p *Plan) planSuricataConfig(ctx context.Context, api API) error {
	if err := p.resolveSuricata(ctx, api); err != nil {
		return err
	}
	cfg := suricataConfig[p.Kind]
	sp := p.suricata
	spName, spID := str(sp["name"]), idOf(sp["id"])
	p.Target = Target{Object: fmt.Sprintf("%s of Suricata policy %q (%d)", cfg.File, spName, spID), Name: cfg.File, ID: spID}
	var old []byte
	if fi := obj(obj(sp["fileInfo"])[cfg.Field]); fi != nil {
		p.Target.Exists = true
		p.Target.ManagedBy = managedBy("", str(fi["loaded-by"]))
		var err error
		if old, err = download(ctx, api, idOf(fi["id"])); err != nil {
			return err
		}
		p.Target.CurrentSHA256, p.Target.CurrentSize = sha256Hex(old), int64(len(old))
		p.Unchanged = p.Target.CurrentSHA256 == p.File.SHA256
	}
	if p.Kind == SuricataYAML && !strings.HasPrefix(strings.TrimSpace(string(p.content)), "%YAML") {
		p.block("Fleet Manager only accepts a suricata.yaml snippet that starts with the %%YAML 1.1 and --- header lines")
	}
	p.Diff = diffLines(old, p.content, old != nil)
	p.step("upload %s and set it on Suricata policy %q", cfg.File, spName)
	p.state = append(p.state, fmt.Sprintf("suricata=%d", spID))
	return nil
}

// --- bundles ---

func (p *Plan) planBundle(ctx context.Context, api API) error {
	if p.req.Policy == "" {
		return fmt.Errorf("bundle needs policy: the sensor policy whose bundle is replaced")
	}
	pol, body, err := resolvePolicy(ctx, api, p.req.Policy)
	if err != nil {
		return err
	}
	p.Policy, p.policyBody = pol, body
	pkgs, err := parseBundle(p.content)
	if err != nil {
		p.block("%v", err)
		return nil
	}
	enabled := map[string]bool{}
	for k, v := range obj(body["packages.enabled"]) {
		enabled[k] = v == true
	}
	var oldPkgs map[string]any
	if bid := idOf(body["bundle.id"]); bid > 0 {
		var b map[string]any
		if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathBundle, bid), nil, &b); err != nil {
			return fmt.Errorf("reading bundle %d: %w", bid, err)
		}
		p.Target = Target{Object: fmt.Sprintf("bundle of sensor policy %q (%d)", pol.Name, pol.ID), ID: bid, Name: str(b["name"]), Exists: true,
			ManagedBy: managedBy(str(b["name"]), str(b["description"]))}
		oldPkgs = obj(obj(b["info"])["packages"])
	} else {
		p.Target = Target{Object: fmt.Sprintf("bundle of sensor policy %q (%d)", pol.Name, pol.ID), Name: "(none)"}
	}
	diff, warnings := diffBundle(pkgs, oldPkgs, enabled)
	p.Diff = diff
	p.Warnings = append(p.Warnings, warnings...)
	if diff["added"] == nil && diff["changed"] == nil && diff["removed"] == nil && oldPkgs != nil {
		p.note("every package has the same version and revision as the current bundle; pushing it still makes the sensors redeploy the bundle")
	}
	name := bundleName(pol.Name, p.File.SHA256)
	if p.Target.Exists && p.Target.Name == name {
		p.Unchanged = true // fleet-mcp names bundles by content, so this is the same file
		return nil
	}
	p.step("upload the bundle to Fleet Manager as %q", name)
	p.step("set it as the bundle of sensor policy %q (%d), keeping its enabled packages; Fleet Manager then deploys it to the policy's sensors", pol.Name, pol.ID)
	if p.Target.Exists {
		p.note("the previous bundle %q (%d) stays on Fleet Manager", p.Target.Name, p.Target.ID)
	}
	if p.Target.ManagedBy != "" && p.Target.ManagedBy != "fleet-mcp" {
		p.note("the current bundle is managed by %s; if it still runs, its next build replaces this one.", p.Target.ManagedBy)
	}
	p.state = append(p.state, fmt.Sprintf("bundle=%d", idOf(body["bundle.id"])))
	return nil
}

// bundleName names an uploaded bundle by policy and content, so the same
// file always gets the same name.
func bundleName(policy, sha string) string {
	return fmt.Sprintf("%s-%s.bundle", policy, sha[:12])
}
