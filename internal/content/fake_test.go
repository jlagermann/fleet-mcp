package content_test

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

// fakeFM is an in-memory Fleet Manager with the parts content uses.
type fakeFM struct {
	*fleettest.Server
	client *fleet.Client

	next        int64
	files       map[int64][]byte
	policies    map[int64]map[string]any
	suricata    map[int64]map[string]any
	bundles     map[int64]map[string]any
	sources     map[int64]map[string]any // file sources
	collections map[int64]map[string]any
	yara        map[int64]map[string]any
	rulesets    map[int64]map[string]any
	sensors     []any
	validation  map[string]any
	failOn      string
	deleted     []string
}

func newFake(t *testing.T) *fakeFM {
	t.Helper()
	f := &fakeFM{Server: fleettest.New(t), next: 100, files: map[int64][]byte{}, policies: map[int64]map[string]any{},
		suricata: map[int64]map[string]any{}, bundles: map[int64]map[string]any{}, sources: map[int64]map[string]any{},
		collections: map[int64]map[string]any{}, yara: map[int64]map[string]any{}, rulesets: map[int64]map[string]any{},
		validation: map[string]any{"ruleCount": 2, "enabledRuleCount": 2, "disabledRuleCount": 0, "errorCount": 0}}
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		f.Handle(m+" /fleet/v1/", f.rest)
	}
	f.Handle("POST /graph/query", f.graphql)
	c, err := fleet.New(fleet.Options{BaseURL: f.URL, Username: fleettest.Username, PasswordFile: f.PasswordFile, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	f.client = c
	return f
}

func (f *fakeFM) id() int64 { f.next++; return f.next }

func (f *fakeFM) addFile(b []byte) int64 {
	id := f.id()
	f.files[id] = b
	return id
}

func hashOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (f *fakeFM) fileObj(id int64) any {
	b, ok := f.files[id]
	if !ok {
		return nil
	}
	return map[string]any{"id": fmt.Sprint(id), "name": "f", "hash": hashOf(b), "sizeBytes": len(b)}
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ordered(m map[int64]map[string]any) []any {
	out := []any{}
	for i := int64(0); i <= 1000 && len(out) < len(m); i++ {
		if v, ok := m[i]; ok {
			out = append(out, v)
		}
	}
	return out
}

func (f *fakeFM) rest(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/fleet/v1")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	id, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	var body map[string]any
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	readUpload := func(field string) []byte {
		_ = r.ParseMultipartForm(8 << 20)
		file, _, err := r.FormFile(field)
		if err != nil {
			return nil
		}
		b, _ := io.ReadAll(file)
		return b
	}
	switch m := r.Method; {
	case m == "GET" && p == "/sensor/policy/list":
		reply(w, 200, ordered(f.policies))
	case m == "GET" && p == "/sensor/catalog":
		reply(w, 200, map[string]any{"list": f.sensors})
	case strings.HasPrefix(p, "/sensor/policy/") && id > 0:
		pol := f.policies[id]
		if m == "PUT" {
			for k, v := range body {
				pol[k] = v
			}
			pol["record.updated-at"] = "now"
		}
		reply(w, 200, pol)
	case strings.HasPrefix(p, "/suricata/") && strings.HasSuffix(p, "/modifiers") && p != "/suricata/validate/modifiers":
		sid, _ := strconv.ParseInt(parts[1], 10, 64)
		f.srmModifiers(w, m, sid, body, r)
	case m == "GET" && strings.HasPrefix(p, "/suricata/") && strings.HasSuffix(p, "/rules"):
		sid, _ := strconv.ParseInt(parts[1], 10, 64)
		var q map[string][]string
		_ = json.Unmarshal([]byte(r.URL.Query().Get("searchParams")), &q)
		items := []any{}
		for _, s := range q["sid"] {
			if rule := f.effectiveRule(sid, s); rule != nil {
				items = append(items, rule)
			}
		}
		reply(w, 200, map[string]any{"items": items, "totalItemCount": len(items)})
	case m == "POST" && p == "/suricata/validate/modifiers":
		var mods []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&mods)
		msgs, bad := []string{}, false
		for _, x := range mods {
			ck := strings.ToLower(fmt.Sprint(x["change"].(map[string]any)["key"]))
			if ck == "msg" {
				msgs, bad = append(msgs, `invalid change key "msg"`), true
			} else {
				msgs = append(msgs, "")
			}
		}
		if bad {
			reply(w, 400, msgs)
			return
		}
		reply(w, 200, msgs)
	case m == "GET" && strings.HasSuffix(p, "/status") && strings.HasPrefix(p, "/suricata/"):
		reply(w, 200, map[string]any{"processing": false, "errors": map[string]any{"sources": map[string]any{}, "modifiers": map[string]any{}, "output": nil}})
	case m == "GET" && p == "/suricata/policies":
		reply(w, 200, ordered(f.suricata))
	case m == "POST" && p == "/suricata/validate/rules":
		if readUpload("content") == nil {
			reply(w, 400, map[string]any{"message": "no content"})
			return
		}
		reply(w, 200, f.validation)
	case strings.HasPrefix(p, "/suricata/") && id > 0:
		sp := f.suricata[id]
		if m == "PUT" {
			for k, v := range body {
				sp[k] = v
				if strings.HasSuffix(k, "-file-id") {
					fi, _ := sp["fileInfo"].(map[string]any)
					if fi == nil {
						fi = map[string]any{}
						sp["fileInfo"] = fi
					}
					fi[k] = map[string]any{"id": v, "loaded-by": "claude"}
				}
			}
		}
		reply(w, 200, sp)
	case m == "POST" && strings.HasPrefix(p, "/filemgr/stores/"):
		reply(w, 201, map[string]any{"id": f.addFile(readUpload("content"))})
	case m == "GET" && strings.HasPrefix(p, "/filemgr/files/"):
		fid, _ := strconv.ParseInt(parts[2], 10, 64)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(f.files[fid])
	case m == "PUT" && p == "/sensor/bundle":
		bid := f.id()
		_ = r.ParseMultipartForm(8 << 20)
		f.bundles[bid] = map[string]any{"id": bid, "name": r.FormValue("name"), "description": r.FormValue("description")}
		reply(w, 200, map[string]any{"id": bid})
	case strings.HasPrefix(p, "/sensor/bundle/") && id > 0:
		if m == "DELETE" {
			f.deleted = append(f.deleted, fmt.Sprintf("bundle %d", id))
			delete(f.bundles, id)
		}
		reply(w, 200, f.bundles[id])
	default:
		reply(w, 404, map[string]any{"message": "no route " + m + " " + p})
	}
}

func (f *fakeFM) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	var upload []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		_ = r.ParseMultipartForm(8 << 20)
		_ = json.Unmarshal([]byte(r.FormValue("operations")), &req)
		if file, _, err := r.FormFile("1"); err == nil {
			upload, _ = io.ReadAll(file)
		}
	} else {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	q := req.Query
	in, _ := req.Variables["input"].(map[string]any)
	data := func(k string, v any) { reply(w, 200, map[string]any{"data": map[string]any{k: v}}) }
	if f.failOn != "" && strings.Contains(q, f.failOn) {
		reply(w, 200, map[string]any{"errors": []any{map[string]any{"message": "fake failure"}}})
		return
	}
	num := func(v any) int64 { n, _ := strconv.ParseInt(fmt.Sprint(v), 10, 64); return n }
	srcOut := func(s map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range s {
			out[k] = v
		}
		out["file"] = f.fileObj(num(s["fileId"]))
		return out
	}
	switch {
	case strings.Contains(q, "fileSources("):
		var list []any
		for _, s := range ordered(f.sources) {
			if s.(map[string]any)["type"] == in["type"] {
				list = append(list, srcOut(s.(map[string]any)))
			}
		}
		data("fileSources", map[string]any{"sources": list})
	case strings.Contains(q, "fileSource(id"):
		data("fileSource", srcOut(f.sources[num(req.Variables["id"])]))
	case strings.Contains(q, "fileCollections("):
		var list []any
		for _, c := range ordered(f.collections) {
			cm := c.(map[string]any)
			var srcs []any
			for _, sid := range cm["ids"].([]int64) {
				srcs = append(srcs, map[string]any{"id": fmt.Sprint(sid)})
			}
			list = append(list, map[string]any{"id": fmt.Sprint(cm["id"]), "name": cm["name"], "type": cm["type"], "sources": srcs})
		}
		data("fileCollections", map[string]any{"collections": list})
	case strings.Contains(q, "createFileSource"):
		nid := f.id()
		s := map[string]any{"id": fmt.Sprint(nid), "fileId": f.addFile(upload)}
		for k, v := range in {
			if k != "file" {
				s[k] = v
			}
		}
		f.sources[nid] = s
		data("createFileSource", map[string]any{"id": fmt.Sprint(nid)})
	case strings.Contains(q, "updateFileSource"):
		s := f.sources[num(in["id"])]
		s["fileId"] = f.addFile(upload)
		for _, k := range []string{"alias", "name"} {
			s[k] = in[k]
		}
		data("updateFileSource", map[string]any{"id": in["id"]})
	case strings.Contains(q, "createFileCollection"):
		nid := f.id()
		f.collections[nid] = map[string]any{"id": nid, "name": in["name"], "type": in["type"], "ids": []int64{}}
		data("createFileCollection", map[string]any{"id": fmt.Sprint(nid)})
	case strings.Contains(q, "associateFileCollectionToSources"):
		c := f.collections[num(in["collectionID"])]
		for _, s := range in["sourceIDs"].([]any) {
			c["ids"] = append(c["ids"].([]int64), num(s))
		}
		data("associateFileCollectionToSources", map[string]any{"message": "ok"})
	case strings.Contains(q, "deleteFileSources"), strings.Contains(q, "deleteFileCollections"),
		strings.Contains(q, "deleteYaraSources"), strings.Contains(q, "deleteYaraRulesets"):
		for _, v := range req.Variables["ids"].([]any) {
			f.deleted = append(f.deleted, fmt.Sprintf("%s %v", strings.Fields(strings.SplitN(q, "{", 3)[1])[0], v))
		}
		data("deleted", map[string]any{"message": "ok"})
	case strings.Contains(q, "validateYaraFile"):
		data("validateYaraFile", map[string]any{"isValid": strings.Contains(string(upload), "condition")})
	case strings.Contains(q, "yaraSources"):
		var list []any
		for _, s := range ordered(f.yara) {
			list = append(list, srcOut(s.(map[string]any)))
		}
		data("yaraSources", map[string]any{"sources": list})
	case strings.Contains(q, "yaraSource(id"):
		data("yaraSource", srcOut(f.yara[num(req.Variables["id"])]))
	case strings.Contains(q, "yaraRulesets"):
		var list []any
		for _, rs := range ordered(f.rulesets) {
			m := rs.(map[string]any)
			var srcs []any
			for _, sid := range m["ids"].([]int64) {
				srcs = append(srcs, map[string]any{"id": fmt.Sprint(sid)})
			}
			list = append(list, map[string]any{"id": fmt.Sprint(m["id"]), "name": m["name"], "sources": srcs})
		}
		data("yaraRulesets", map[string]any{"rulesets": list})
	case strings.Contains(q, "yaraRuleset(id"):
		data("yaraRuleset", map[string]any{"id": req.Variables["id"], "isProcessing": false, "processingError": ""})
	case strings.Contains(q, "createYaraSource"):
		nid := f.id()
		f.yara[nid] = map[string]any{"id": fmt.Sprint(nid), "name": in["name"], "description": in["description"], "fileId": f.addFile(upload)}
		data("createYaraSource", map[string]any{"id": fmt.Sprint(nid)})
	case strings.Contains(q, "createYaraRuleset"):
		nid := f.id()
		f.rulesets[nid] = map[string]any{"id": nid, "name": in["name"], "ids": []int64{}}
		data("createYaraRuleset", map[string]any{"id": fmt.Sprint(nid)})
	case strings.Contains(q, "associateYaraRulesetToSources"):
		rs := f.rulesets[num(in["rulesetID"])]
		for _, s := range in["sourceIDs"].([]any) {
			rs["ids"] = append(rs["ids"].([]int64), num(s))
		}
		data("associateYaraRulesetToSources", map[string]any{"message": "ok"})
	default:
		reply(w, 200, map[string]any{"errors": []any{map[string]any{"message": "fake: unknown query " + q}}})
	}
}

// srmModifiers keeps per-rule modifiers in sp["mods"] ([]map) and the
// policy's base rules in sp["rules"] (sid -> map like the rules API).
func (f *fakeFM) srmModifiers(w http.ResponseWriter, m string, id int64, body map[string]any, r *http.Request) {
	sp := f.suricata[id]
	mods, _ := sp["mods"].([]any)
	switch m {
	case "GET":
		reply(w, 200, append([]any{}, mods...))
	case "POST":
		for _, x := range body["modifications"].([]any) {
			mm := x.(map[string]any)
			mm["id"] = float64(f.id())
			mods = append(mods, mm)
		}
		sp["mods"] = mods
		w.WriteHeader(204)
	case "PUT":
		for i, x := range mods {
			if x.(map[string]any)["id"] == body["id"] {
				mods[i] = body
			}
		}
		w.WriteHeader(204)
	case "DELETE":
		del := map[float64]bool{}
		for _, x := range body["modifications"].([]any) {
			del[x.(float64)] = true
		}
		var keep []any
		for _, x := range mods {
			if !del[x.(map[string]any)["id"].(float64)] {
				keep = append(keep, x)
			}
		}
		sp["mods"] = keep
		f.deleted = append(f.deleted, fmt.Sprintf("modifiers %v", body["modifications"]))
		w.WriteHeader(204)
	}
}

// effectiveRule applies the policy's SID modifiers to a base rule.
func (f *fakeFM) effectiveRule(id int64, sid string) map[string]any {
	sp := f.suricata[id]
	base, _ := sp["rules"].(map[string]any)[sid].(map[string]any)
	if base == nil {
		return nil
	}
	rule := map[string]any{}
	for k, v := range base {
		rule[k] = v
	}
	mods, _ := sp["mods"].([]any)
	for _, x := range mods {
		mm := x.(map[string]any)
		match := mm["match"].(map[string]any)
		if match["key"] != "sid" || match["value"] != sid {
			continue
		}
		switch mm["action"] {
		case "disable":
			rule["disabled"] = true
		case "enable":
			rule["disabled"] = false
		case "modify":
			ch := mm["change"].(map[string]any)
			field := map[string]string{"srcaddress": "srcAddress", "destaddress": "destAddress", "srcport": "srcPort", "destport": "destPort", "action": "action", "protocol": "protocol", "ruleoptions": "rawOptions"}[fmt.Sprint(ch["key"])]
			rule[field] = ch["value"]
		}
	}
	return rule
}
