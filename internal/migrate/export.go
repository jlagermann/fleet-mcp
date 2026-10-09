package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/redact"
)

// DefaultMaxFileBytes caps one exported file.
const DefaultMaxFileBytes = 1 << 30

// ExportOptions selects what to export.
type ExportOptions struct {
	// Fleet is the source Fleet Manager's name, recorded in the manifest.
	Fleet string
	// Policy is the sensor policy's ID or name.
	Policy string
	// Dir is the package directory to create; it must not exist.
	Dir string
	// SnapshotConnectorSources exports the latest file of collection
	// sources fed by a connector as a plain uploaded source.
	SnapshotConnectorSources bool
	// MaxFileBytes caps each file; 0 means DefaultMaxFileBytes.
	MaxFileBytes int64
}

// collectionRoles maps a manifest collection role to the policy field
// that links it.
var collectionRoles = []struct{ Role, Field string }{
	{"input", "inputCollectionID"},
	{"intel", "intelCollectionID"},
	{"resource", "resourceCollectionID"},
	{"ca_bundles", "caBundleCollectionID"},
}

// suricataFiles maps a manifest key to the Suricata policy field and the
// file-manager store it is uploaded to.
var suricataFiles = []struct{ Key, Field, Store string }{
	{"yaml", "suricata-yaml-file-id", "suricata-yaml"},
	{"threshold", "suricata-threshold-file-id", "suricata-threshold"},
	{"classification", "suricata-classification-file-id", "suricata-classification"},
	{"reference", "suricata-reference-file-id", "suricata-reference"},
}

type exporter struct {
	api  API
	dir  string
	max  int64
	byID map[int64]*FileRef
	m    *Manifest
}

// Export writes a package for one sensor policy to opts.Dir.
func Export(ctx context.Context, api API, opts ExportOptions) (m *Manifest, err error) {
	if opts.Dir == "" {
		return nil, errors.New("no package directory")
	}
	if _, err := os.Stat(opts.Dir); err == nil {
		return nil, fmt.Errorf("package directory %s already exists", opts.Dir)
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	id, err := resolvePolicy(ctx, api, opts.Policy)
	if err != nil {
		return nil, err
	}
	version, err := serverVersion(ctx, api)
	if err != nil {
		return nil, err
	}
	var p map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, id), nil, &p); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(opts.Dir)
		}
	}()

	e := &exporter{api: api, dir: opts.Dir, max: opts.MaxFileBytes, byID: map[int64]*FileRef{}, m: &Manifest{
		Format: Format, ExportedAt: time.Now().UTC(),
		Source: Source{Fleet: opts.Fleet, Version: version, PolicyID: id},
	}}
	if err := e.policy(p); err != nil {
		return nil, err
	}
	if bid := idOf(p["bundle.id"]); bid > 0 {
		if err := e.bundle(ctx, bid); err != nil {
			return nil, fmt.Errorf("bundle %d: %w", bid, err)
		}
	}
	if sid := idOf(p["suricataPolicyID"]); sid > 0 {
		if err := e.suricata(ctx, sid); err != nil {
			return nil, fmt.Errorf("suricata policy %d: %w", sid, err)
		}
	}
	if yid := idOf(p["yaraRulesetID"]); yid > 0 {
		if err := e.yara(ctx, yid); err != nil {
			return nil, fmt.Errorf("YARA ruleset %d: %w", yid, err)
		}
	}
	for _, r := range collectionRoles {
		if cid := idOf(p[r.Field]); cid > 0 {
			if err := e.collection(ctx, r.Role, cid, opts.SnapshotConnectorSources); err != nil {
				return nil, fmt.Errorf("%s collection %d: %w", r.Role, cid, err)
			}
		}
	}
	b, err := json.MarshalIndent(e.m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(opts.Dir, ManifestFile), append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	return e.m, nil
}

// resolvePolicy finds a sensor policy by ID or exact name.
func resolvePolicy(ctx context.Context, api API, ref string) (int64, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, errors.New("no policy given")
	}
	var list any
	if err := api.GetJSON(ctx, pathPolicyList, nil, &list); err != nil {
		return 0, err
	}
	want, numErr := strconv.ParseInt(ref, 10, 64)
	var byName []int64
	for _, el := range listOf(list) {
		p := obj(el)
		pid := idOf(p["id"])
		if numErr == nil && pid == want {
			return pid, nil
		}
		if str(p["name"]) == ref {
			byName = append(byName, pid)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return 0, fmt.Errorf("no sensor policy %q", ref)
	}
	return 0, fmt.Errorf("%d sensor policies are named %q; use the ID", len(byName), ref)
}

func (e *exporter) omit(part, item, reason, action string) {
	e.m.Omitted = append(e.m.Omitted, Omission{Part: part, Item: item, Reason: reason, Action: action})
}

func (e *exporter) policy(p map[string]any) error {
	cfg := obj(p["configuration"])
	clean, omitted, feats := CleanConfiguration(cfg, obj(p["configuration.metadata"]), obj(p["exporter.metadata"]))
	e.m.Omitted = append(e.m.Omitted, omitted...)
	e.m.Features = feats
	pol := Policy{
		Name: str(p["name"]), Description: str(p["description"]), Configuration: clean,
		EnableSuricataVLAN: truthy(p["enableSuricataVLAN"]),
	}
	if fc := obj(p["filter-configuration"]); len(fc) > 0 {
		pol.FilterConfiguration = fc
	}
	if pe := obj(p["packages.enabled"]); len(pe) > 0 {
		pol.PackagesEnabled = map[string]bool{}
		for k, v := range pe {
			pol.PackagesEnabled[k] = truthy(v)
		}
	}
	e.m.Policy = pol
	return nil
}

// CleanConfiguration removes secrets and file references from a policy
// configuration and reports the licensed features and exporter types it
// uses. cfgMeta is the policy's configuration.metadata (a JSON schema)
// and expMeta its exporter.metadata.
func CleanConfiguration(cfg, cfgMeta, expMeta map[string]any) (map[string]any, []Omission, Features) {
	props := obj(cfgMeta["properties"])
	noLog := noLogFields(expMeta)
	clean := map[string]any{}
	var omitted []Omission
	exporterTypes := map[string]bool{}

	for _, k := range sortedKeys(cfg) {
		v := cfg[k]
		if inst, field, ok := exporterKey(k); ok {
			typ := str(cfg["bro.exporters."+inst+".type"])
			name := str(cfg["bro.exporters."+inst+".name"])
			if name == "" {
				name = inst
			}
			if field == "type" && typ != "" {
				exporterTypes[typ] = true
			}
			if noLog[typ][field] || (redact.SensitiveKey(field) && !isNumber(v)) {
				// Secrets are never copied; report the ones that were set.
				if !harmlessValue(v) {
					omitted = append(omitted, Omission{Part: "exporters", Item: name + " (" + typ + ") " + field,
						Reason: "secret; Fleet Manager never returns it",
						Action: "enter " + field + " for exporter " + name + " on the target policy"})
				}
				continue
			}
			clean[k] = v
			continue
		}
		pm := obj(props[k])
		switch {
		case str(pm["cl:type"]) == "Password" || truthy(pm["writeOnly"]):
			if !harmlessValue(v) {
				omitted = append(omitted, Omission{Part: "policy", Item: k, Reason: "write-only secret setting",
					Action: "set " + k + " on the target policy"})
			}
			continue
		case str(pm["cl:type"]) == "File" && v != nil:
			omitted = append(omitted, Omission{Part: "policy", Item: k, Reason: "refers to a file on the source Fleet Manager",
				Action: "upload the file and select it for " + k + " on the target policy"})
			continue
		case redact.SensitiveKey(lastSegment(k)) && isNonEmptyString(v):
			omitted = append(omitted, Omission{Part: "policy", Item: k, Reason: "looks like a secret",
				Action: "set " + k + " on the target policy"})
			continue
		}
		clean[k] = v
	}

	var feats Features
	for _, k := range sortedKeys(props) {
		pm := obj(props[k])
		ctl := str(pm["cl:internalController"])
		if !strings.HasPrefix(ctl, "system.license.") || !strings.HasSuffix(ctl, ".active") {
			continue
		}
		v, set := cfg[k]
		if !set {
			v = pm["cl:default"]
		}
		if truthy(v) {
			feats.Licensed = append(feats.Licensed, strings.TrimSuffix(strings.TrimPrefix(ctl, "system.license."), ".active"))
		}
	}
	sort.Strings(feats.Licensed)
	feats.Exporters = sortedKeys(exporterTypes)
	return clean, omitted, feats
}

// exporterKey splits "bro.exporters.<instance>.<field>".
func exporterKey(k string) (inst, field string, ok bool) {
	rest, found := strings.CutPrefix(k, "bro.exporters.")
	if !found {
		return "", "", false
	}
	inst, field, ok = strings.Cut(rest, ".")
	return inst, field, ok && inst != "" && field != ""
}

func lastSegment(k string) string {
	if i := strings.LastIndexAny(k, "."); i >= 0 {
		return k[i+1:]
	}
	return k
}

func harmlessValue(v any) bool {
	switch t := v.(type) {
	case nil, float64:
		return true
	case bool:
		// A secret that is set reads back as true; that placeholder is
		// not a value that can be copied.
		return !t
	case string:
		return t == ""
	}
	return false
}

// noLogFields finds the fields marked noLog in exporter.metadata, per
// exporter type.
func noLogFields(expMeta map[string]any) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for typ, def := range expMeta {
		fields := map[string]bool{}
		var walk func(any)
		walk = func(v any) {
			switch t := v.(type) {
			case map[string]any:
				if name := str(t["fieldName"]); name != "" && truthy(t["noLog"]) {
					fields[name] = true
				}
				for _, c := range t {
					walk(c)
				}
			case []any:
				for _, c := range t {
					walk(c)
				}
			}
		}
		walk(def)
		out[typ] = fields
	}
	return out
}

// fetchFile streams one file-manager file into the package.
func (e *exporter) fetchFile(ctx context.Context, fileID int64, name, kind string) (*FileRef, error) {
	if f, ok := e.byID[fileID]; ok {
		return f, nil
	}
	f, err := e.download(ctx, fmt.Sprintf("%s%d/content", pathFiles, fileID), path.Join("files", kind, fmt.Sprintf("%d-%s", fileID, safeName(name))), name)
	if err != nil {
		return nil, err
	}
	e.byID[fileID] = f
	return f, nil
}

func (e *exporter) download(ctx context.Context, apiPath, rel, name string) (*FileRef, error) {
	full := filepath.Join(e.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return nil, err
	}
	out, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := e.api.Download(ctx, apiPath, io.MultiWriter(out, h), e.max)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &FileRef{Path: rel, Name: name, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

func (e *exporter) bundle(ctx context.Context, id int64) error {
	var b map[string]any
	if err := e.api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathBundle, id), nil, &b); err != nil {
		return err
	}
	name := str(b["name"])
	f, err := e.download(ctx, fmt.Sprintf("%s/%d/file", pathBundle, id), path.Join("files", "bundle", safeName(name)), name)
	if err != nil {
		return err
	}
	e.m.Bundle = &Bundle{Name: name, Description: str(b["description"]), File: *f}
	return nil
}

func (e *exporter) suricata(ctx context.Context, id int64) error {
	var sp map[string]any
	if err := e.api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathSuricata, id), nil, &sp); err != nil {
		return err
	}
	s := &Suricata{
		Name: str(sp["name"]), Description: str(sp["description"]), Settings: obj(sp["settings"]),
		HomeNet: str(sp["homeNet"]), RulesAutomation: truthy(sp["rulesAutomation"]),
		UseModifierFiles: truthy(sp["useModifierFiles"]), Config: obj(sp["config"]),
		Files: map[string]*FileRef{},
	}
	for _, el := range listOf(sp["sources"]) {
		src := obj(el)
		name := str(src["name"])
		typ := str(src["entityType"])
		ss := SuricataSource{Name: name, EntityType: typ, Notes: str(src["notes"]), Enabled: truthy(src["enabled"])}
		switch {
		case typ == "file" && idOf(src["fileId"]) > 0:
			fname := str(src["filename"])
			if fname == "" {
				fname = name
			}
			f, err := e.fetchFile(ctx, idOf(src["fileId"]), fname, "suricata")
			if err != nil {
				return err
			}
			ss.File = f
		case typ == "url" && str(src["url"]) != "" && redact.String(str(src["url"])) == str(src["url"]) && len(obj(src["headers"])) == 0:
			ss.URL = str(src["url"])
		case typ == "url" || len(obj(src["headers"])) > 0:
			e.omit("suricata", name, "rule source URL or headers carry a license code or credentials",
				"add the source "+name+" to the target Suricata policy with your own license code")
			continue
		default:
			e.omit("suricata", name, "rule source type "+typ+" cannot be copied",
				"recreate the source "+name+" on the target Suricata policy")
			continue
		}
		s.Sources = append(s.Sources, ss)
	}
	info := obj(sp["fileInfo"])
	for _, sf := range suricataFiles {
		fid := idOf(sp[sf.Field])
		if fid <= 0 {
			continue
		}
		name := str(obj(info[sf.Field])["name"])
		if name == "" {
			name = sf.Key
		}
		f, err := e.fetchFile(ctx, fid, name, "suricata-"+sf.Key)
		if err != nil {
			return err
		}
		s.Files[sf.Key] = f
	}
	for _, el := range listOf(sp["modifierFiles"]) {
		mf := obj(el)
		m := ModifierFile{Name: str(mf["name"]), Enabled: truthy(mf["enabled"])}
		u := str(mf["url"])
		switch fid := idOf(mf["fileId"]); {
		case fid > 0:
			f, err := e.fetchFile(ctx, fid, m.Name, "suricata-modifiers")
			if err != nil {
				return err
			}
			m.File = f
		case strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"):
			if redact.String(u) != u {
				e.omit("suricata", m.Name, "modifier file URL carries credentials", "set the URL for "+m.Name+" on the target Suricata policy")
				continue
			}
			m.URL = u
		default:
			continue // an empty placeholder; the target creates its own
		}
		s.ModifierFiles = append(s.ModifierFiles, m)
	}
	e.m.Suricata = s
	return nil
}

const yaraRulesetQuery = `query($id: ID!) { yaraRuleset(id: $id) { id name description
  sources { id name description enabled namespace interval fileID file { id name sizeBytes } } } }`

func (e *exporter) yara(ctx context.Context, id int64) error {
	var out struct {
		YaraRuleset *struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Sources     []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Enabled     *bool  `json:"enabled"`
				Namespace   string `json:"namespace"`
				Interval    *int64 `json:"interval"`
				FileID      any    `json:"fileID"`
				File        *struct {
					Name string `json:"name"`
				} `json:"file"`
			} `json:"sources"`
		} `json:"yaraRuleset"`
	}
	if err := gql(ctx, e.api, yaraRulesetQuery, map[string]any{"id": strconv.FormatInt(id, 10)}, &out); err != nil {
		return err
	}
	rs := out.YaraRuleset
	if rs == nil {
		return errors.New("not found")
	}
	y := &Yara{Name: rs.Name, Description: rs.Description}
	for _, src := range rs.Sources {
		ys := YaraSource{Name: src.Name, Description: src.Description, Namespace: src.Namespace,
			Enabled: src.Enabled == nil || *src.Enabled, Interval: src.Interval}
		fid := idOf(src.FileID)
		if fid <= 0 {
			e.omit("yara", src.Name, "source has no uploaded file", "add the rules for "+src.Name+" on the target")
			continue
		}
		name := src.Name
		if src.File != nil && src.File.Name != "" {
			name = src.File.Name
		}
		f, err := e.fetchFile(ctx, fid, name, "yara")
		if err != nil {
			return err
		}
		ys.File = f
		y.Sources = append(y.Sources, ys)
	}
	e.m.Yara = y
	return nil
}

const fileCollectionQuery = `query($id: ID!) { fileCollection(id: $id) { id name description type
  sources { id alias name description enabled type interval fileId file { id name sizeBytes }
    connectorID connector { appConnectorID name } } } }`

func (e *exporter) collection(ctx context.Context, role string, id int64, snapshot bool) error {
	var out struct {
		FileCollection *struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Type        string `json:"type"`
			Sources     []struct {
				Alias       string `json:"alias"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Enabled     *bool  `json:"enabled"`
				Type        string `json:"type"`
				Interval    *int64 `json:"interval"`
				FileID      any    `json:"fileId"`
				File        *struct {
					Name      string `json:"name"`
					SizeBytes int64  `json:"sizeBytes"`
				} `json:"file"`
				ConnectorID any `json:"connectorID"`
				Connector   *struct {
					AppConnectorID string `json:"appConnectorID"`
					Name           string `json:"name"`
				} `json:"connector"`
			} `json:"sources"`
		} `json:"fileCollection"`
	}
	if err := gql(ctx, e.api, fileCollectionQuery, map[string]any{"id": strconv.FormatInt(id, 10)}, &out); err != nil {
		return err
	}
	fc := out.FileCollection
	if fc == nil {
		return errors.New("not found")
	}
	c := &Collection{Name: fc.Name, Description: fc.Description, Type: fc.Type}
	for _, src := range fc.Sources {
		fs := FileSource{Alias: src.Alias, Name: src.Name, Description: src.Description, Type: src.Type,
			Enabled: src.Enabled == nil || *src.Enabled, Interval: src.Interval}
		item := src.Alias + "/" + src.Name
		if src.Connector != nil || idOf(src.ConnectorID) > 0 {
			conn := Connector{}
			if src.Connector != nil {
				conn = Connector{AppConnectorID: src.Connector.AppConnectorID, Name: src.Connector.Name}
			}
			fs.Connector = &conn
			if !snapshot {
				e.omit(role, item, "fed by connector "+conn.Name+" ("+conn.AppConnectorID+"); connector credentials are not exported",
					"create a "+conn.AppConnectorID+" connector and source on the target, or export again with snapshot_connector_sources")
				continue
			}
			fs.Snapshot = true
			fs.Interval = nil
		}
		fid := idOf(src.FileID)
		if fid <= 0 {
			e.omit(role, item, "source has no file yet", "add the source "+item+" on the target")
			continue
		}
		if src.File != nil && src.File.SizeBytes > e.max {
			e.omit(role, item, fmt.Sprintf("file is %d bytes, over the %d byte export limit", src.File.SizeBytes, e.max),
				"add the source "+item+" on the target")
			continue
		}
		name := src.Name
		if src.File != nil && src.File.Name != "" {
			name = src.File.Name
		}
		f, err := e.fetchFile(ctx, fid, name, role)
		if err != nil {
			return err
		}
		fs.File = f
		c.Sources = append(c.Sources, fs)
	}
	if len(c.Sources) == 0 {
		e.omit(role, c.Name, "no source of the collection could be exported", "link a "+role+" collection on the target")
		return nil
	}
	if e.m.Collections == nil {
		e.m.Collections = map[string]*Collection{}
	}
	e.m.Collections[role] = c
	return nil
}

func isNumber(v any) bool {
	_, ok := v.(float64)
	return ok || v == nil
}

func isNonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}
