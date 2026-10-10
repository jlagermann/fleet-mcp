package migrate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
)

// fakeFM is an in-memory Fleet Manager with just enough of the policy,
// Suricata, bundle, file-manager and GraphQL APIs for migrate.
type fakeFM struct {
	*fleettest.Server
	client *fleet.Client

	version   string
	exporters map[string]any // exporter.metadata
	props     map[string]any // configuration.metadata.properties
	sensors   []any

	next        int64
	policies    map[int64]map[string]any
	suricata    map[int64]map[string]any
	bundles     map[int64]map[string]any
	bundleData  map[int64][]byte
	files       map[int64]fakeFile
	yaraSources map[int64]map[string]any
	yaraRules   map[int64]map[string]any
	sources     map[int64]map[string]any
	collections map[int64]map[string]any
	connectors  map[int64]map[string]any

	// failOn makes a GraphQL operation containing this text fail.
	failOn string
	// deleted records "kind id" for every delete.
	deleted []string
}

type fakeFile struct {
	name    string
	content []byte
}

func (f fakeFile) hash() string {
	s := sha256.Sum256(f.content)
	return hex.EncodeToString(s[:])
}

func newFakeFM(t *testing.T, version string) *fakeFM {
	t.Helper()
	f := &fakeFM{
		Server: fleettest.New(t), version: version, next: 100,
		exporters: map[string]any{"hec": map[string]any{"elements": []any{
			map[string]any{"type": "field", "fieldProperties": map[string]any{"fieldName": "hec_token", "noLog": true}},
			map[string]any{"type": "field", "fieldProperties": map[string]any{"fieldName": "hec_endpoint"}},
		}}},
		props: map[string]any{
			"suricata.enable":                                       map[string]any{"cl:type": "Boolean", "cl:default": "0", "cl:internalController": "system.license.suricata.active"},
			"corelight.yara.enable":                                 map[string]any{"cl:type": "Boolean", "cl:default": "0", "cl:internalController": "system.license.yara.active"},
			"bro.analyzers.mqtt.enable":                             map[string]any{"cl:type": "Boolean"},
			"bro.export.splunk.index":                               map[string]any{"cl:type": "Text"},
			"smartpcap.object_store.provider.s3.kms_encryption_key": map[string]any{"cl:type": "Password", "writeOnly": true},
			"intel-file-id":                                         map[string]any{"cl:type": "File"},
			"bro.exporters.instances":                               map[string]any{"cl:type": "Text"},
		},
		policies: map[int64]map[string]any{}, suricata: map[int64]map[string]any{}, bundles: map[int64]map[string]any{},
		bundleData: map[int64][]byte{}, files: map[int64]fakeFile{}, yaraSources: map[int64]map[string]any{},
		yaraRules: map[int64]map[string]any{}, sources: map[int64]map[string]any{}, collections: map[int64]map[string]any{},
		connectors: map[int64]map[string]any{},
	}
	f.Handle("GET /fleet/v1/", f.rest)
	f.Handle("POST /fleet/v1/", f.rest)
	f.Handle("PUT /fleet/v1/", f.rest)
	f.Handle("DELETE /fleet/v1/", f.rest)
	f.Handle("POST /graph/query", f.graphql)
	c, err := fleet.New(fleet.Options{BaseURL: f.URL, Username: fleettest.Username, PasswordFile: f.PasswordFile, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	f.client = c
	return f
}

func (f *fakeFM) id() int64 { f.next++; return f.next }

func (f *fakeFM) addFile(name string, content []byte) int64 {
	id := f.id()
	f.files[id] = fakeFile{name: name, content: content}
	return id
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func listOfMaps(m map[int64]map[string]any) []any {
	out := []any{}
	for i := int64(0); i <= 100000 && len(out) < len(m); i++ {
		if v, ok := m[i]; ok {
			out = append(out, v)
		}
	}
	return out
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok && k == "configuration" {
			cfg, _ := dst[k].(map[string]any)
			if cfg == nil {
				cfg = map[string]any{}
			}
			for ck, cv := range sub {
				cfg[ck] = cv
			}
			dst[k] = cfg
			continue
		}
		dst[k] = v
	}
}

func (f *fakeFM) rest(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/fleet/v1")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	last := parts[len(parts)-1]
	id, _ := strconv.ParseInt(last, 10, 64)
	var body map[string]any
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch m := r.Method; {
	case m == "GET" && p == "/info":
		reply(w, 200, map[string]any{"server_version": f.version})
	case m == "GET" && p == "/sensor/policy/list":
		reply(w, 200, listOfMaps(f.policies))
	case m == "GET" && p == "/sensor/policy/metadata":
		reply(w, 200, map[string]any{"configuration.metadata": map[string]any{"properties": f.props}, "exporter.metadata": f.exporters})
	case m == "GET" && p == "/sensor/catalog":
		reply(w, 200, map[string]any{"list": f.sensors})
	case m == "POST" && p == "/sensor/policy":
		nid := f.id()
		pol := map[string]any{"id": nid, "name": body["name"], "description": body["description"], "configuration": body["configuration"]}
		f.policies[nid] = pol
		reply(w, 201, map[string]any{"id": nid})
	case m == "POST" && strings.HasSuffix(p, "/validation"):
		errs := map[string]any{}
		cfg, _ := body["config"].(map[string]any)
		for k := range cfg {
			if strings.HasPrefix(k, "bad.") {
				errs[k] = "unrecognized configuration settings"
			}
		}
		reply(w, 200, map[string]any{"errors": errs})
	case strings.HasPrefix(p, "/sensor/policy/") && id > 0:
		pol := f.policies[id]
		if pol == nil {
			reply(w, 404, map[string]any{"message": "not found"})
			return
		}
		switch m {
		case "GET":
			out := map[string]any{"configuration.metadata": map[string]any{"properties": f.props}, "exporter.metadata": f.exporters}
			for k, v := range pol {
				out[k] = v
			}
			reply(w, 200, out)
		case "PUT":
			delete(body, "id")
			merge(pol, body)
			reply(w, 200, map[string]any{})
		case "DELETE":
			delete(f.policies, id)
			f.deleted = append(f.deleted, fmt.Sprintf("sensor policy %d", id))
			reply(w, 200, map[string]any{})
		}
	case m == "GET" && p == "/sensor/bundle":
		reply(w, 200, listOfMaps(f.bundles))
	case m == "PUT" && p == "/sensor/bundle":
		_ = r.ParseMultipartForm(1 << 20)
		file, _, err := r.FormFile("file")
		if err != nil {
			reply(w, 400, map[string]any{"message": "no file"})
			return
		}
		b, _ := io.ReadAll(file)
		nid := f.id()
		f.bundles[nid] = map[string]any{"id": nid, "name": r.FormValue("name"), "description": r.FormValue("description")}
		f.bundleData[nid] = b
		reply(w, 201, map[string]any{"id": nid})
	case strings.HasPrefix(p, "/sensor/bundle/"):
		bid, _ := strconv.ParseInt(parts[2], 10, 64)
		switch {
		case m == "GET" && last == "file":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(f.bundleData[bid])
		case m == "GET":
			reply(w, 200, f.bundles[bid])
		case m == "DELETE":
			delete(f.bundles, bid)
			f.deleted = append(f.deleted, fmt.Sprintf("bundle %d", bid))
			reply(w, 200, map[string]any{})
		}
	case m == "GET" && p == "/suricata/metadata":
		reply(w, 200, map[string]any{"properties": map[string]any{
			"suricata.address_groups.dns_servers": map[string]any{"type": "string"},
			"suricata.port_groups.vxlan_ports":    map[string]any{"type": "string"},
			"suricata-tenant-rules-file-id.*":     map[string]any{"type": "integer"},
		}})
	case m == "GET" && p == "/suricata/defaults":
		reply(w, 200, map[string]any{"settings": map[string]any{"suricata.port_groups.vxlan_ports": "4789"}})
	case m == "GET" && p == "/suricata/policies":
		reply(w, 200, listOfMaps(f.suricata))
	case m == "POST" && p == "/suricata":
		nid := f.id()
		f.suricata[nid] = map[string]any{"id": nid, "name": body["name"], "description": body["description"], "sources": []any{}}
		reply(w, 200, f.suricata[nid])
	case strings.HasPrefix(p, "/suricata/") && id > 0:
		sp := f.suricata[id]
		switch m {
		case "GET":
			reply(w, 200, sp)
		case "PUT":
			for k, v := range body {
				sp[k] = v
			}
			w.WriteHeader(204)
		case "DELETE":
			delete(f.suricata, id)
			f.deleted = append(f.deleted, fmt.Sprintf("suricata policy %d", id))
			reply(w, 200, map[string]any{})
		}
	case m == "GET" && strings.HasPrefix(p, "/filemgr/files/") && last == "content":
		fid, _ := strconv.ParseInt(parts[2], 10, 64)
		ff, ok := f.files[fid]
		if !ok {
			reply(w, 404, map[string]any{"message": "no file"})
			return
		}
		_, _ = w.Write(ff.content)
	case m == "POST" && strings.HasPrefix(p, "/filemgr/stores/"):
		_ = r.ParseMultipartForm(1 << 20)
		file, _, err := r.FormFile("content")
		if err != nil {
			reply(w, 400, map[string]any{"message": "no content"})
			return
		}
		b, _ := io.ReadAll(file)
		nid := f.addFile(r.FormValue("name"), b)
		reply(w, 201, map[string]any{"id": nid, "name": r.FormValue("name"), "hash": f.files[nid].hash(), "sizeBytes": len(b)})
	default:
		reply(w, 404, map[string]any{"message": "fake: no route for " + m + " " + p})
	}
}

func (f *fakeFM) fileObj(id int64) any {
	ff, ok := f.files[id]
	if !ok {
		return nil
	}
	return map[string]any{"id": id, "name": ff.name, "hash": ff.hash(), "sizeBytes": len(ff.content)}
}

func (f *fakeFM) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	var upload []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		_ = r.ParseMultipartForm(1 << 20)
		_ = json.Unmarshal([]byte(r.FormValue("operations")), &req)
		if file, _, err := r.FormFile("1"); err == nil {
			upload, _ = io.ReadAll(file)
		}
	} else {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	q := req.Query
	input, _ := req.Variables["input"].(map[string]any)
	data := func(k string, v any) { reply(w, 200, map[string]any{"data": map[string]any{k: v}}) }
	if f.failOn != "" && strings.Contains(q, f.failOn) {
		reply(w, 200, map[string]any{"data": nil, "errors": []any{map[string]any{"message": "fake failure"}}})
		return
	}
	vid := func() int64 { n, _ := strconv.ParseInt(fmt.Sprint(req.Variables["id"]), 10, 64); return n }
	idList := func() []int64 {
		var out []int64
		for _, v := range req.Variables["ids"].([]any) {
			n, _ := strconv.ParseInt(fmt.Sprint(v), 10, 64)
			out = append(out, n)
		}
		return out
	}
	switch {
	case strings.Contains(q, "yaraRuleset(id"):
		rs := f.yaraRules[vid()]
		out := map[string]any{"name": rs["name"], "description": rs["description"], "sources": []any{}}
		for _, sid := range rs["sources"].([]int64) {
			s := f.yaraSources[sid]
			out["sources"] = append(out["sources"].([]any), map[string]any{"name": s["name"], "description": s["description"],
				"enabled": s["enabled"], "namespace": s["namespace"], "fileID": s["fileID"], "file": f.fileObj(s["fileID"].(int64))})
		}
		data("yaraRuleset", out)
	case strings.Contains(q, "fileCollection(id"):
		c := f.collections[vid()]
		out := map[string]any{"name": c["name"], "description": c["description"], "type": c["type"], "sources": []any{}}
		for _, sid := range c["sources"].([]int64) {
			s := f.sources[sid]
			src := map[string]any{"alias": s["alias"], "name": s["name"], "enabled": s["enabled"], "type": s["type"],
				"fileId": s["fileId"], "file": f.fileObj(s["fileId"].(int64)), "connectorID": s["connectorID"]}
			if cid, ok := s["connectorID"].(int64); ok {
				src["connector"] = map[string]any{"appConnectorID": f.connectors[cid]["appConnectorID"], "name": f.connectors[cid]["name"]}
			}
			out["sources"] = append(out["sources"].([]any), src)
		}
		data("fileCollection", out)
	case strings.Contains(q, "yaraRulesets(input"):
		var rs, ys, cs, ss []any
		for _, v := range listOfMaps(f.yaraRules) {
			rs = append(rs, map[string]any{"name": v.(map[string]any)["name"]})
		}
		for _, v := range listOfMaps(f.yaraSources) {
			ys = append(ys, map[string]any{"name": v.(map[string]any)["name"]})
		}
		for _, v := range listOfMaps(f.collections) {
			cs = append(cs, map[string]any{"name": v.(map[string]any)["name"]})
		}
		for _, v := range listOfMaps(f.sources) {
			s := v.(map[string]any)
			ss = append(ss, map[string]any{"id": s["id"], "alias": s["alias"], "name": s["name"], "type": s["type"], "file": f.fileObj(s["fileId"].(int64))})
		}
		reply(w, 200, map[string]any{"data": map[string]any{
			"yaraRulesets": map[string]any{"rulesets": rs}, "yaraSources": map[string]any{"sources": ys},
			"fileCollections": map[string]any{"collections": cs}, "fileSources": map[string]any{"sources": ss},
		}})
	case strings.Contains(q, "createYaraSource"):
		nid := f.id()
		input["fileID"] = f.addFile(fmt.Sprint(input["name"]), upload)
		input["id"] = nid
		f.yaraSources[nid] = input
		data("createYaraSource", map[string]any{"id": nid})
	case strings.Contains(q, "createYaraRuleset"):
		nid := f.id()
		input["id"] = nid
		input["sources"] = []int64{}
		f.yaraRules[nid] = input
		data("createYaraRuleset", map[string]any{"id": nid})
	case strings.Contains(q, "associateYaraRulesetToSources"):
		rs := f.yaraRules[int64(input["rulesetID"].(float64))]
		for _, v := range input["sourceIDs"].([]any) {
			rs["sources"] = append(rs["sources"].([]int64), int64(v.(float64)))
		}
		data("associateYaraRulesetToSources", map[string]any{"message": "ok"})
	case strings.Contains(q, "createFileSource"):
		nid := f.id()
		input["fileId"] = f.addFile(fmt.Sprint(input["name"]), upload)
		input["id"] = nid
		f.sources[nid] = input
		data("createFileSource", map[string]any{"id": nid})
	case strings.Contains(q, "createFileCollection"):
		nid := f.id()
		input["id"] = nid
		input["sources"] = []int64{}
		f.collections[nid] = input
		data("createFileCollection", map[string]any{"id": nid})
	case strings.Contains(q, "associateFileCollectionToSources"):
		c := f.collections[int64(input["collectionID"].(float64))]
		for _, v := range input["sourceIDs"].([]any) {
			c["sources"] = append(c["sources"].([]int64), int64(v.(float64)))
		}
		data("associateFileCollectionToSources", map[string]any{"message": "ok"})
	case strings.Contains(q, "deleteFileCollections"):
		for _, id := range idList() {
			delete(f.collections, id)
			f.deleted = append(f.deleted, fmt.Sprintf("collection %d", id))
		}
		data("deleteFileCollections", map[string]any{"message": "ok"})
	case strings.Contains(q, "deleteFileSources"):
		for _, id := range idList() {
			delete(f.sources, id)
			f.deleted = append(f.deleted, fmt.Sprintf("file source %d", id))
		}
		data("deleteFileSources", map[string]any{"message": "ok"})
	case strings.Contains(q, "deleteYaraRulesets"):
		for _, id := range idList() {
			delete(f.yaraRules, id)
			f.deleted = append(f.deleted, fmt.Sprintf("YARA ruleset %d", id))
		}
		data("deleteYaraRulesets", map[string]any{"message": "ok"})
	case strings.Contains(q, "deleteYaraSources"):
		for _, id := range idList() {
			delete(f.yaraSources, id)
			f.deleted = append(f.deleted, fmt.Sprintf("YARA source %d", id))
		}
		data("deleteYaraSources", map[string]any{"message": "ok"})
	default:
		reply(w, 422, map[string]any{"errors": []any{map[string]any{"message": "fake: unsupported query " + q}}})
	}
}

// seedSource builds a source Fleet Manager with one fully linked policy.
func seedSource(t *testing.T) (*fakeFM, int64) {
	f := newFakeFM(t, "29.2.2-100")
	rules := f.addFile("local.rules", []byte("alert ip any any -> any any (msg:\"x\"; sid:1;)\n"))
	yaml := f.addFile("suricata.yaml", []byte("%YAML 1.1\n"))
	disable := f.addFile("disable.conf", []byte("-2000001\n"))
	sid := f.id()
	f.suricata[sid] = map[string]any{
		"id": sid, "name": "lab-suricata", "description": "d", "homeNet": "[10.0.0.0/8]", "rulesAutomation": true,
		"useModifierFiles": true, "settings": map[string]any{"suricata.address_groups.dns_servers": "[10.0.0.53]", "suricata.profiling.enable": false},
		"config": map[string]any{"srmEnableFlowBits": false},
		"sources": []any{
			map[string]any{"name": "local", "entityType": "file", "fileId": float64(rules), "filename": "local.rules", "enabled": true},
			map[string]any{"name": "Corelight Feed", "entityType": "url", "url": "https://feed.corelight.com/corelight.rules", "enabled": false},
			map[string]any{"name": "ET Pro", "entityType": "url", "url": "https://ppp.rules.corelight.io/SECRETCODE123/suricata/etpro.rules.tar.gz", "enabled": true},
		},
		"suricata-yaml-file-id": float64(yaml),
		"fileInfo":              map[string]any{"suricata-yaml-file-id": map[string]any{"name": "suricata.yaml"}},
		"modifierFiles": []any{
			map[string]any{"name": "disable.conf", "enabled": true, "fileId": float64(disable)},
			map[string]any{"name": "enable.conf", "enabled": false, "fileId": float64(0), "url": ""},
		},
	}
	ysrc := f.id()
	f.yaraSources[ysrc] = map[string]any{"id": ysrc, "name": "lab-yara", "enabled": true, "namespace": "lab", "fileID": f.addFile("lab.yar", []byte("rule x { condition: true }"))}
	yrs := f.id()
	f.yaraRules[yrs] = map[string]any{"id": yrs, "name": "lab-ruleset", "sources": []int64{ysrc}}
	conn := f.id()
	f.connectors[conn] = map[string]any{"appConnectorID": "crowdstrike-v1", "name": "CrowdStrike OEM"}
	up := f.id()
	f.sources[up] = map[string]any{"id": up, "alias": "Corelight-update", "name": "intel.dat", "enabled": true, "type": "INTEL", "fileId": f.addFile("intel.dat", []byte("#fields\tindicator\n1.2.3.4\n"))}
	cs := f.id()
	f.sources[cs] = map[string]any{"id": cs, "alias": "CRWD", "name": "bro_intel.dat", "enabled": true, "type": "INTEL", "fileId": f.addFile("bro_intel.dat", []byte("#fields\tindicator\n5.6.7.8\n")), "connectorID": conn}
	coll := f.id()
	f.collections[coll] = map[string]any{"id": coll, "name": "lab-intel", "type": "INTEL", "sources": []int64{up, cs}}
	bid := f.id()
	f.bundles[bid] = map[string]any{"id": bid, "name": "lab.bundle", "description": "bundle"}
	f.bundleData[bid] = []byte("\x1f\x8bBUNDLE")
	pid := f.id()
	f.policies[pid] = map[string]any{
		"id": pid, "name": "lab-policy", "description": "the lab",
		"configuration": map[string]any{
			"suricata.enable": true, "bro.analyzers.mqtt.enable": true, "bro.export.splunk.index": "corelight",
			"bro.exporters.instances": "abcdefghij", "bro.exporters.abcdefghij.type": "hec",
			"bro.exporters.abcdefghij.name": "Splunk", "bro.exporters.abcdefghij.hec_endpoint": "https://splunk.example:8088",
			"bro.exporters.abcdefghij.hec_token":                    true,
			"smartpcap.object_store.provider.s3.kms_encryption_key": "SECRETKMS",
		},
		"packages.enabled": map[string]any{"pkg-a": true, "pkg-b": false},
		"bundle.id":        float64(bid), "suricataPolicyID": float64(sid), "yaraRulesetID": float64(yrs), "intelCollectionID": float64(coll),
	}
	return f, pid
}

// licensedSensor is a catalog entry licensed for the given features.
func licensedSensor(features ...string) any {
	var ls []any
	for _, n := range []string{"sensor", "suricata", "yara", "smartpcap"} {
		active := n == "sensor"
		for _, f := range features {
			active = active || f == n
		}
		ls = append(ls, map[string]any{"name": n, "active": active})
	}
	return map[string]any{"name": "s1", "licenses": ls}
}
