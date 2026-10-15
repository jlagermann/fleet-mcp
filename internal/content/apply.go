package content

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

const (
	mCreateFileSource = `mutation($input: NewFileSource!) { createFileSource(input: $input) { id } }`
	mUpdateFileSource = `mutation($input: UpdateFileSource!) { updateFileSource(input: $input) { id } }`
	mCreateYaraSource = `mutation($input: NewYaraSource!) { createYaraSource(input: $input) { id } }`
	mUpdateYaraSource = `mutation($input: UpdateYaraSource!) { updateYaraSource(input: $input) { id } }`
	mCreateCollection = `mutation($input: NewFileCollection!) { createFileCollection(input: $input) { id } }`
	mCreateRuleset    = `mutation($input: NewYaraRuleset!) { createYaraRuleset(input: $input) { id } }`
	mAddToCollection  = `mutation($input: FileCollectionToSourcesInput!) { associateFileCollectionToSources(input: $input) { message } }`
	mAddToRuleset     = `mutation($input: YaraRulesetToSourcesInput!) { associateYaraRulesetToSources(input: $input) { message } }`
	mDeleteSources    = `mutation($ids: [ID!]!) { deleteFileSources(ids: $ids) { message } }`
	mDeleteColls      = `mutation($ids: [ID!]!) { deleteFileCollections(ids: $ids) { message } }`
	mDeleteYara       = `mutation($ids: [ID!]!) { deleteYaraSources(ids: $ids) { message } }`
	mDeleteRulesets   = `mutation($ids: [ID!]!) { deleteYaraRulesets(ids: $ids) { message } }`
	qFileSource       = `query($id: ID!) { fileSource(id: $id) { id name enabled file { id hash } } }`
	qYaraSource       = `query($id: ID!) { yaraSource(id: $id) { id file { id hash } } }`
	qYaraRuleset      = `query($id: ID!) { yaraRuleset(id: $id) { id isProcessing processingError } }`
)

// Result is what a push did.
type Result struct {
	Done         []string `json:"done"`
	RolledBack   []string `json:"rolled_back,omitempty"`
	Verification []string `json:"verification,omitempty"`
	// IDs of the objects the push wrote.
	SourceID     int64 `json:"source_id,omitempty"`
	FileID       int64 `json:"file_id,omitempty"`
	CollectionID int64 `json:"collection_id,omitempty"`
	BundleID     int64 `json:"bundle_id,omitempty"`
}

type applier struct {
	api     API
	p       *Plan
	res     *Result
	created []func(context.Context) error
	names   []string
}

func (a *applier) did(format string, args ...any) {
	a.res.Done = append(a.res.Done, fmt.Sprintf(format, args...))
}

func (a *applier) undo(name string, f func(context.Context) error) {
	a.created = append(a.created, f)
	a.names = append(a.names, name)
}

// Apply carries out a ready plan. When a step fails, objects the push
// created are deleted again; sources updated in place keep the new file.
func Apply(ctx context.Context, api API, p *Plan) (*Result, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("the plan is not ready: %v", p.Blockers)
	}
	a := &applier{api: api, p: p, res: &Result{}}
	var err error
	switch p.Kind {
	case Intel, Input:
		err = a.fileSource(ctx)
	case Yara:
		err = a.yara(ctx)
	case SuricataRules:
		err = a.suricataRules(ctx)
	case SuricataYAML, SuricataThreshold, SuricataClassification, SuricataReference:
		err = a.suricataConfig(ctx)
	case Bundle:
		err = a.bundle(ctx)
	}
	if err != nil {
		a.rollback(context.WithoutCancel(ctx))
		return a.res, err
	}
	a.verify(ctx)
	return a.res, nil
}

func (a *applier) rollback(ctx context.Context) {
	for i := len(a.created) - 1; i >= 0; i-- {
		if err := a.created[i](ctx); err != nil {
			a.res.RolledBack = append(a.res.RolledBack, fmt.Sprintf("could not delete %s: %v", a.names[i], err))
		} else {
			a.res.RolledBack = append(a.res.RolledBack, "deleted "+a.names[i])
		}
	}
}

func (a *applier) deleteGQL(query string, id int64) func(context.Context) error {
	return func(ctx context.Context) error {
		return gql(ctx, a.api, query, map[string]any{"ids": []string{fmt.Sprint(id)}}, nil)
	}
}

func (a *applier) mutateID(ctx context.Context, query, field string, input map[string]any, upload bool) (int64, error) {
	var resp *fleet.Response
	var err error
	if upload {
		input["file"] = nil
		resp, err = a.api.GraphQLUpload(ctx, query, map[string]any{"input": input}, "variables.input.file", a.p.fileNm, a.p.content)
	} else {
		resp, err = a.api.GraphQL(ctx, query, map[string]any{"input": input})
	}
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
	return id, nil
}

func (a *applier) fileSource(ctx context.Context) error {
	p := a.p
	typ, fileName := "INTEL", "bro_intel.dat"
	if p.Kind == Input {
		typ = "INPUT"
		if fileName = p.req.Name; fileName == "" {
			fileName = p.fileNm
		}
	}
	id := p.Target.ID
	if p.Target.Exists {
		if !p.sameFile {
			if _, err := a.mutateID(ctx, mUpdateFileSource, "updateFileSource",
				map[string]any{"id": fmt.Sprint(id), "alias": p.Target.Name, "name": fileName, "type": typ}, true); err != nil {
				return fmt.Errorf("updating file source %q: %w", p.Target.Name, err)
			}
			a.did("updated %s file source %q (%d) with the new file", strings.ToLower(typ), p.Target.Name, id)
		}
	} else {
		var err error
		id, err = a.mutateID(ctx, mCreateFileSource, "createFileSource",
			map[string]any{"alias": p.Target.Name, "name": fileName, "description": p.req.Description, "enabled": true, "type": typ}, true)
		if err != nil {
			return fmt.Errorf("creating file source %q: %w", p.Target.Name, err)
		}
		a.undo(fmt.Sprintf("file source %q (%d)", p.Target.Name, id), a.deleteGQL(mDeleteSources, id))
		a.did("created %s file source %q (%d)", strings.ToLower(typ), p.Target.Name, id)
	}
	a.res.SourceID = id
	return a.link(ctx, id, typ)
}

func (a *applier) yara(ctx context.Context) error {
	p := a.p
	id := p.Target.ID
	if p.Target.Exists {
		if !p.sameFile {
			if _, err := a.mutateID(ctx, mUpdateYaraSource, "updateYaraSource", map[string]any{"id": fmt.Sprint(id), "name": p.Target.Name}, true); err != nil {
				return fmt.Errorf("updating YARA source %q: %w", p.Target.Name, err)
			}
			a.did("updated YARA source %q (%d) with the new file", p.Target.Name, id)
		}
	} else {
		var err error
		id, err = a.mutateID(ctx, mCreateYaraSource, "createYaraSource",
			map[string]any{"name": p.Target.Name, "description": p.req.Description, "enabled": true, "namespace": DefaultSource}, true)
		if err != nil {
			return fmt.Errorf("creating YARA source %q: %w", p.Target.Name, err)
		}
		a.undo(fmt.Sprintf("YARA source %q (%d)", p.Target.Name, id), a.deleteGQL(mDeleteYara, id))
		a.did("created YARA source %q (%d)", p.Target.Name, id)
	}
	a.res.SourceID = id
	return a.link(ctx, id, "YARA")
}

// link adds the source to the policy's collection or ruleset, creating and
// linking one if the policy has none.
func (a *applier) link(ctx context.Context, sourceID int64, typ string) error {
	l := a.p.link
	if !l.needed {
		return nil
	}
	yara := typ == "YARA"
	cid := l.collectionID
	if l.createName != "" {
		var err error
		if yara {
			cid, err = a.mutateID(ctx, mCreateRuleset, "createYaraRuleset", map[string]any{"name": l.createName, "description": a.p.req.Description}, false)
		} else {
			cid, err = a.mutateID(ctx, mCreateCollection, "createFileCollection", map[string]any{"name": l.createName, "description": a.p.req.Description, "type": typ}, false)
		}
		if err != nil {
			return fmt.Errorf("creating collection %q: %w", l.createName, err)
		}
		del := mDeleteColls
		if yara {
			del = mDeleteRulesets
		}
		a.undo(fmt.Sprintf("collection %q (%d)", l.createName, cid), a.deleteGQL(del, cid))
		a.did("created %s %q (%d)", what(l.policyField), l.createName, cid)
	}
	if !l.alreadyIn {
		var err error
		if yara {
			err = gql(ctx, a.api, mAddToRuleset, map[string]any{"input": map[string]any{"rulesetID": cid, "sourceIDs": []int64{sourceID}}}, nil)
		} else {
			err = gql(ctx, a.api, mAddToCollection, map[string]any{"input": map[string]any{"collectionID": cid, "sourceIDs": []int64{sourceID}}}, nil)
		}
		if err != nil {
			return fmt.Errorf("adding the source to %s %d: %w", what(l.policyField), cid, err)
		}
		a.did("added the source to %s %d", what(l.policyField), cid)
	}
	a.res.CollectionID = cid
	if idOf(a.p.policyBody[l.policyField]) != cid {
		if err := a.putPolicy(ctx, map[string]any{l.policyField: cid}); err != nil {
			return err
		}
		a.did("linked %s %d to sensor policy %q (%d)", what(l.policyField), cid, a.p.Policy.Name, a.p.Policy.ID)
	}
	return nil
}

func what(field string) string {
	return map[string]string{"intelCollectionID": "intel collection", "inputCollectionID": "input collection", "yaraRulesetID": "YARA ruleset"}[field]
}

// putPolicy changes fields of the sensor policy. Fleet-client sends the
// name, description and enabled packages with a change, so this does too.
func (a *applier) putPolicy(ctx context.Context, change map[string]any) error {
	body := map[string]any{"id": a.p.Policy.ID}
	for _, k := range []string{"name", "description", "packages.enabled"} {
		if v, ok := a.p.policyBody[k]; ok {
			body[k] = v
		}
	}
	for k, v := range change {
		body[k] = v
	}
	if _, err := a.api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathPolicy, a.p.Policy.ID), nil, jsonBody(body), "application/json"); err != nil {
		return fmt.Errorf("changing sensor policy %q: %w", a.p.Policy.Name, err)
	}
	return nil
}

// upload stores the file in a file-manager store under name.
func (a *applier) upload(ctx context.Context, store, name string) (int64, error) {
	resp, err := a.api.DoMultipart(ctx, http.MethodPost, pathStores+store, map[string]string{"name": name},
		fleet.FilePart{Field: "content", FileName: name, Content: a.p.content})
	if err != nil {
		return 0, fmt.Errorf("uploading %s: %w", name, err)
	}
	id, err := responseID(resp)
	if err != nil {
		return 0, fmt.Errorf("uploading %s: %w", name, err)
	}
	a.res.FileID = id
	a.did("uploaded %s to Fleet Manager (file %d)", name, id)
	return id, nil
}

func (a *applier) putSuricata(ctx context.Context, body map[string]any) error {
	id := idOf(a.p.suricata["id"])
	if _, err := a.api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathSuricata, id), nil, jsonBody(body), "application/json"); err != nil {
		return fmt.Errorf("changing Suricata policy %q: %w", str(a.p.suricata["name"]), err)
	}
	return nil
}

func (a *applier) suricataRules(ctx context.Context) error {
	fid, err := a.upload(ctx, "suricata", "suricata.rules")
	if err != nil {
		return err
	}
	sp := a.p.suricata
	if sp["rulesAutomation"] != true {
		if err := a.putSuricata(ctx, map[string]any{"suricata-file-id": fid}); err != nil {
			return err
		}
		a.did("set it as the rule set of Suricata policy %q", str(sp["name"]))
		return nil
	}
	var sources []any
	found := false
	for _, s := range listOf(sp["sources"]) {
		m := map[string]any{}
		for k, v := range obj(s) {
			m[k] = v
		}
		if str(m["name"]) == a.p.Target.Name {
			m["fileId"], m["filename"] = fid, "suricata.rules"
			found = true
		}
		sources = append(sources, m)
	}
	if !found {
		sources = append(sources, map[string]any{"name": a.p.Target.Name, "entityType": "file", "enabled": true, "fileId": fid, "filename": "suricata.rules"})
	}
	if err := a.putSuricata(ctx, map[string]any{"sources": sources}); err != nil {
		return err
	}
	if found {
		a.did("pointed rule source %q of Suricata policy %q at the new file", a.p.Target.Name, str(sp["name"]))
	} else {
		a.did("added rule source %q to Suricata policy %q", a.p.Target.Name, str(sp["name"]))
	}
	return nil
}

func (a *applier) suricataConfig(ctx context.Context) error {
	cfg := suricataConfig[a.p.Kind]
	fid, err := a.upload(ctx, cfg.Store, cfg.File)
	if err != nil {
		return err
	}
	if err := a.putSuricata(ctx, map[string]any{cfg.Field: fid}); err != nil {
		return err
	}
	a.did("set %s on Suricata policy %q", cfg.File, str(a.p.suricata["name"]))
	return nil
}

func (a *applier) bundle(ctx context.Context) error {
	name := bundleName(a.p.Policy.Name, a.p.File.SHA256)
	resp, err := a.api.DoMultipart(ctx, http.MethodPut, pathBundle, map[string]string{"name": name, "description": a.p.req.Description},
		fleet.FilePart{Field: "file", FileName: name, Content: a.p.content})
	if err != nil {
		return fmt.Errorf("uploading the bundle: %w", err)
	}
	bid, err := responseID(resp)
	if err != nil {
		return fmt.Errorf("uploading the bundle: %w", err)
	}
	a.res.BundleID = bid
	a.did("uploaded bundle %q (%d)", name, bid)
	if bid != idOf(a.p.policyBody["bundle.id"]) {
		a.undo(fmt.Sprintf("bundle %q (%d)", name, bid), func(ctx context.Context) error {
			_, err := a.api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathBundle, bid), nil, nil, "")
			return err
		})
	}
	if err := a.putPolicy(ctx, map[string]any{"bundle.id": bid}); err != nil {
		return err
	}
	a.did("set bundle %d on sensor policy %q (%d)", bid, a.p.Policy.Name, a.p.Policy.ID)
	return nil
}

// verify reads back what the push changed.
func (a *applier) verify(ctx context.Context) {
	p := a.p
	bad := func(format string, args ...any) {
		a.res.Verification = append(a.res.Verification, fmt.Sprintf(format, args...))
	}
	switch p.Kind {
	case Intel, Input:
		var out struct {
			FileSource map[string]any `json:"fileSource"`
		}
		if err := gql(ctx, a.api, qFileSource, map[string]any{"id": fmt.Sprint(a.res.SourceID)}, &out); err != nil {
			bad("could not read the source back: %v", err)
		} else if h := str(obj(out.FileSource["file"])["hash"]); h != p.File.SHA256 {
			bad("the source's file hash is %q, not the pushed file's %s", h, p.File.SHA256)
		}
	case Yara:
		var out struct {
			YaraSource map[string]any `json:"yaraSource"`
		}
		if err := gql(ctx, a.api, qYaraSource, map[string]any{"id": fmt.Sprint(a.res.SourceID)}, &out); err != nil {
			bad("could not read the YARA source back: %v", err)
		} else if h := str(obj(out.YaraSource["file"])["hash"]); h != "" && h != p.File.SHA256 {
			bad("the YARA source's file hash is %q, not the pushed file's %s", h, p.File.SHA256)
		}
		if a.res.CollectionID > 0 {
			var rs struct {
				YaraRuleset map[string]any `json:"yaraRuleset"`
			}
			if err := gql(ctx, a.api, qYaraRuleset, map[string]any{"id": fmt.Sprint(a.res.CollectionID)}, &rs); err == nil {
				if e := str(rs.YaraRuleset["processingError"]); e != "" {
					bad("YARA ruleset %d reports a processing error: %s", a.res.CollectionID, e)
				}
			}
		}
	case SuricataRules, SuricataYAML, SuricataThreshold, SuricataClassification, SuricataReference:
		var sp map[string]any
		if err := a.api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathSuricata, idOf(p.suricata["id"])), nil, &sp); err != nil {
			bad("could not read the Suricata policy back: %v", err)
			break
		}
		var got int64
		switch {
		case p.Kind == SuricataRules && p.suricata["rulesAutomation"] == true:
			for _, s := range listOf(sp["sources"]) {
				if str(obj(s)["name"]) == p.Target.Name {
					got = idOf(obj(s)["fileId"])
				}
			}
		case p.Kind == SuricataRules:
			got = idOf(obj(obj(sp["fileInfo"])["suricata-file-id"])["id"])
		default:
			got = idOf(obj(obj(sp["fileInfo"])[suricataConfig[p.Kind].Field])["id"])
		}
		if got != a.res.FileID {
			bad("the Suricata policy points at file %d, not the uploaded file %d", got, a.res.FileID)
		}
	}
	if p.Policy != nil && p.policyBody != nil && (p.Kind == Bundle || p.link.needed) {
		a.verifyPolicy(ctx, bad)
	}
}

// verifyPolicy checks that the sensor policy has the change and that
// nothing else in it changed.
func (a *applier) verifyPolicy(ctx context.Context, bad func(string, ...any)) {
	p := a.p
	var after map[string]any
	if err := a.api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, p.Policy.ID), nil, &after); err != nil {
		bad("could not read sensor policy %d back: %v", p.Policy.ID, err)
		return
	}
	// Fields a change is expected to touch: record times, the expanded
	// object of a link (intelCollectionID -> intelCollection), and the
	// package metadata of a new bundle.
	changed := map[string]bool{"record.updated-at": true, "record.updated-by": true}
	if p.link.needed {
		changed[strings.TrimSuffix(p.link.policyField, "ID")] = true
	}
	if p.Kind == Bundle {
		for _, k := range []string{"bundle.id", "packages.metadata", "packages.current", "bundles.available"} {
			changed[k] = true
		}
		if idOf(after["bundle.id"]) != a.res.BundleID {
			bad("sensor policy %d has bundle %d, not %d", p.Policy.ID, idOf(after["bundle.id"]), a.res.BundleID)
		}
	}
	if p.link.needed {
		changed[p.link.policyField] = true
		if idOf(after[p.link.policyField]) != a.res.CollectionID {
			bad("sensor policy %d has %s %d, not %d", p.Policy.ID, p.link.policyField, idOf(after[p.link.policyField]), a.res.CollectionID)
		}
	}
	var diffs []string
	for k, v := range p.policyBody {
		if !changed[k] && !sameJSON(v, after[k]) {
			diffs = append(diffs, k)
		}
	}
	for k := range after {
		if _, ok := p.policyBody[k]; !ok && !changed[k] {
			diffs = append(diffs, k)
		}
	}
	if len(diffs) > 0 {
		bad("other fields of sensor policy %d changed too: %s", p.Policy.ID, strings.Join(sample(sortStrings(diffs), 20), ", "))
	}
}

func sortStrings(s []string) []string {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return sortedKeys(m)
}

func sameJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	var va, vb any
	_ = json.Unmarshal(ja, &va)
	_ = json.Unmarshal(jb, &vb)
	return reflect.DeepEqual(va, vb)
}
