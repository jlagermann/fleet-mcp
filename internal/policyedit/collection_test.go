package policyedit_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/policyedit"
)

// collectionOp answers the GraphQL operations fm_collection_manage uses and
// reports whether it handled the query.
func (f *fakeFM) collectionOp(q string, vars map[string]any, data func(string, any)) bool {
	in, _ := vars["input"].(map[string]any)
	num := func(v any) int64 { n, _ := strconv.ParseInt(fmt.Sprint(v), 10, 64); return n }
	srcIDs := func() []int64 {
		var out []int64
		for _, v := range in["sourceIDs"].([]any) {
			out = append(out, num(v))
		}
		return out
	}
	collSources := func(c map[string]any) []int64 {
		var out []int64
		for _, s := range c["sources"].([]any) {
			out = append(out, num(s.(map[string]any)["id"]))
		}
		return out
	}
	setColl := func(c map[string]any, ids []int64) {
		srcs := []any{}
		for _, id := range ids {
			srcs = append(srcs, map[string]any{"id": id})
		}
		c["sources"] = srcs
	}
	without := func(l, drop []int64) []int64 {
		var out []int64
		for _, v := range l {
			keep := true
			for _, d := range drop {
				if v == d {
					keep = false
				}
			}
			if keep {
				out = append(out, v)
			}
		}
		return out
	}
	record := func(op string) { f.mutations = append(f.mutations, op) }
	switch {
	case strings.Contains(q, "fileSources("):
		var list []any
		for _, s := range f.fileSources {
			if s["type"] == in["type"] {
				list = append(list, s)
			}
		}
		data("fileSources", map[string]any{"sources": list})
	case strings.Contains(q, "yaraSources"):
		var list []any
		for _, s := range f.yaraSources {
			list = append(list, s)
		}
		data("yaraSources", map[string]any{"sources": list})
	case strings.Contains(q, "createFileCollection"):
		id := f.id()
		c := map[string]any{"id": id, "name": in["name"], "type": in["type"]}
		setColl(c, nil)
		f.collections[id] = c
		record(fmt.Sprintf("createFileCollection %v %v", in["name"], in["type"]))
		data("createFileCollection", map[string]any{"id": fmt.Sprint(id)})
	case strings.Contains(q, "updateFileCollection"):
		c := f.collections[num(in["id"])]
		if n, ok := in["name"]; ok {
			c["name"] = n
		}
		record("updateFileCollection")
		data("updateFileCollection", map[string]any{"id": in["id"]})
	case strings.Contains(q, "unassociateFileCollectionFromSources"):
		c := f.collections[num(in["collectionID"])]
		setColl(c, without(collSources(c), srcIDs()))
		record(fmt.Sprintf("unassociate %v %v", in["collectionID"], srcIDs()))
		data("x", map[string]any{"message": "ok"})
	case strings.Contains(q, "associateFileCollectionToSources"):
		c := f.collections[num(in["collectionID"])]
		setColl(c, append(collSources(c), srcIDs()...))
		record(fmt.Sprintf("associate %v %v", in["collectionID"], srcIDs()))
		data("x", map[string]any{"message": "ok"})
	case strings.Contains(q, "createYaraRuleset"):
		id := f.id()
		f.rulesets[id] = fmt.Sprint(in["name"])
		record(fmt.Sprintf("createYaraRuleset %v", in["name"]))
		data("createYaraRuleset", map[string]any{"id": fmt.Sprint(id)})
	case strings.Contains(q, "updateYaraRuleset"):
		if n, ok := in["name"]; ok {
			f.rulesets[num(in["id"])] = fmt.Sprint(n)
		}
		record("updateYaraRuleset")
		data("updateYaraRuleset", map[string]any{"id": in["id"]})
	case strings.Contains(q, "unassociateYaraRulesetFromSources"):
		id := num(in["rulesetID"])
		f.rulesetSrc[id] = without(f.rulesetSrc[id], srcIDs())
		record(fmt.Sprintf("unassociateYara %d %v", id, srcIDs()))
		data("x", map[string]any{"message": "ok"})
	case strings.Contains(q, "associateYaraRulesetToSources"):
		id := num(in["rulesetID"])
		f.rulesetSrc[id] = append(f.rulesetSrc[id], srcIDs()...)
		record(fmt.Sprintf("associateYara %d %v", id, srcIDs()))
		data("x", map[string]any{"message": "ok"})
	case strings.Contains(q, "yaraRuleset("):
		data("yaraRuleset", map[string]any{"id": vars["id"], "isProcessing": false, "processingError": nil})
	default:
		return false
	}
	return true
}

// collectionFake is an FM with two input collections (one used by
// defaultPolicy), an intel collection with the same name as one of them,
// input sources (one from Corelight-update, one disabled, two with the same
// file name) and a connected sensor whose dns-bypass package reads its file.
func collectionFake(t *testing.T) *fakeFM {
	f := newFake(t)
	f.policies[17] = map[string]any{"id": int64(17), "name": "defaultPolicy", "inputCollectionID": int64(1), "intelCollectionID": int64(3)}
	f.policies[18] = map[string]any{"id": int64(18), "name": "edge", "inputCollectionID": int64(2)}
	f.groups[5] = map[string]any{"id": int64(5), "name": "lab", "policy.id": int64(17)}
	f.sensors = []map[string]any{{"uid": "s1", "name": "sensor-1", "group.id": int64(5), "fleet.connected": true,
		"bro.inputs": []any{map[string]any{"name": "dns_bypass_authorized.tsv", "package": "dns-bypass"}}}}
	f.collections[1] = map[string]any{"id": int64(1), "name": "default", "type": "INPUT", "sources": []any{map[string]any{"id": int64(59)}}}
	f.collections[2] = map[string]any{"id": int64(2), "name": "edge-inputs", "type": "INPUT", "sources": []any{}}
	f.collections[3] = map[string]any{"id": int64(3), "name": "default", "type": "INTEL", "sources": []any{}}
	f.fileSources = []map[string]any{
		{"id": int64(59), "type": "INPUT", "alias": "defaultPolicy_dns_bypass_authorized.tsv", "name": "dns_bypass_authorized.tsv", "description": "Created by Corelight Update", "createdBy": "Corelight-update", "enabled": true},
		{"id": int64(70), "type": "INPUT", "alias": "defaultPolicy_registry_fetch_hosts.tsv", "name": "registry_fetch_hosts.tsv", "description": "Created by Corelight Update", "createdBy": "Corelight-update", "enabled": true},
		{"id": int64(71), "type": "INPUT", "alias": "old hosts", "name": "hosts_data.tsv", "createdBy": "admin", "enabled": false},
		{"id": int64(72), "type": "INPUT", "alias": "EDR hosts", "name": "dns_bypass_authorized.tsv", "createdBy": "admin", "enabled": true},
		{"id": int64(80), "type": "INTEL", "alias": "intel feed", "name": "intel.dat", "createdBy": "admin", "enabled": true},
	}
	f.next = 200
	return f
}

func prepare(t *testing.T, f *fakeFM, r policyedit.CollectionRequest) *policyedit.CollectionPlan {
	t.Helper()
	p, err := policyedit.PrepareCollection(context.Background(), f.client, r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func apply(t *testing.T, f *fakeFM, p *policyedit.CollectionPlan) *policyedit.CollectionResult {
	t.Helper()
	res, err := policyedit.ApplyCollection(context.Background(), f.client, p)
	if err != nil {
		t.Fatalf("apply: %v (done %v)", err, res)
	}
	if len(res.Verification) > 0 {
		t.Fatalf("verification: %v", res.Verification)
	}
	return res
}

func has(l []string, sub string) bool {
	for _, s := range l {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestCollectionAddExistingSource(t *testing.T) {
	f := collectionFake(t)
	p := prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "default",
		AddSources: []string{"defaultPolicy_registry_fetch_hosts.tsv"}})
	if !p.Ready() || len(p.Blockers) > 0 {
		t.Fatalf("not ready: %+v", p)
	}
	if p.Collection.ID != 1 || p.Kind != "input" {
		t.Fatalf("wrong collection %v %s", p.Collection, p.Kind)
	}
	if !has(p.Notes, "managed by Corelight-update") {
		t.Errorf("no Corelight-update note: %v", p.Notes)
	}
	if len(p.Groups) != 1 || p.Groups[0].Name != "lab" {
		t.Errorf("groups %v", p.Groups)
	}
	if !has(p.Enrichment, "registry_fetch_hosts.tsv: it does nothing") || !has(p.Enrichment, "dns_bypass_authorized.tsv is read by dns-bypass") {
		t.Errorf("enrichment %v", p.Enrichment)
	}
	apply(t, f, p)
	if fmt.Sprint(f.mutations) != "[associate 1 [70]]" {
		t.Errorf("mutations %v", f.mutations)
	}
	// Same request again: nothing to do.
	p = prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "default",
		AddSources: []string{"70"}})
	if p.Ready() || !has(p.Notes, "already in the collection") {
		t.Errorf("second add: ready=%v notes=%v", p.Ready(), p.Notes)
	}
}

func TestCollectionCreateAndLink(t *testing.T) {
	f := collectionFake(t)
	desc := "lab inputs"
	p := prepare(t, f, policyedit.CollectionRequest{Action: "create", Kind: "input", Collection: "lab-inputs", Description: &desc,
		AddSources: []string{"dns_bypass_authorized.tsv", "EDR hosts", "old hosts"}, LinkPolicies: []string{"edge"}})
	// The file name matches two sources (59 by file, 72 by file); "EDR hosts"
	// is the alias of 72.
	if !has(p.Blockers, "matches 2 sources") {
		t.Fatalf("ambiguous file name not blocked: %v", p.Blockers)
	}
	p = prepare(t, f, policyedit.CollectionRequest{Action: "create", Kind: "input", Collection: "lab-inputs", Description: &desc,
		AddSources: []string{"59", "EDR hosts", "old hosts"}, LinkPolicies: []string{"edge"}})
	if len(p.Blockers) > 0 {
		t.Fatalf("blockers %v", p.Blockers)
	}
	if !has(p.Warnings, "is disabled") || !has(p.Warnings, "have the file name dns_bypass_authorized.tsv") || !has(p.Warnings, "linking replaces it") {
		t.Errorf("warnings %v", p.Warnings)
	}
	res := apply(t, f, p)
	if res.ID == 0 {
		t.Fatal("no id")
	}
	want := fmt.Sprintf("[createFileCollection lab-inputs INPUT associate %d [59 72 71]]", res.ID)
	if fmt.Sprint(f.mutations) != want {
		t.Errorf("mutations %v, want %s", f.mutations, want)
	}
	if got := f.policies[18]["inputCollectionID"]; fmt.Sprint(got) != fmt.Sprint(res.ID) {
		t.Errorf("edge inputCollectionID %v", got)
	}
}

func TestCollectionExistingClashIsANote(t *testing.T) {
	f := collectionFake(t)
	// Collection 1 already has two enabled sources for one file name, and
	// a disabled source with another file name that is not counted.
	f.collections[1]["sources"] = []any{map[string]any{"id": int64(59)}, map[string]any{"id": int64(72)}, map[string]any{"id": int64(71)}}
	f.fileSources = append(f.fileSources, map[string]any{"id": int64(73), "type": "INPUT", "alias": "new hosts", "name": "hosts_data.tsv", "enabled": true})
	p := prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "1", AddSources: []string{"70"}})
	if len(p.Warnings) > 0 || !has(p.Notes, "already so: 2 enabled sources") {
		t.Errorf("existing clash: warnings %v notes %v", p.Warnings, p.Notes)
	}
	// 73 is enabled and shares hosts_data.tsv with the disabled 71 only:
	// no clash.
	p = prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "1", AddSources: []string{"73"}})
	if has(p.Warnings, "hosts_data.tsv") || has(p.Notes, "hosts_data.tsv") {
		t.Errorf("disabled source counted: warnings %v notes %v", p.Warnings, p.Notes)
	}
}

func TestCollectionCreateExistingBlocked(t *testing.T) {
	f := collectionFake(t)
	p := prepare(t, f, policyedit.CollectionRequest{Action: "create", Kind: "input", Collection: "default"})
	if p.Ready() || !has(p.Blockers, "already exists") {
		t.Errorf("not blocked: %v", p.Blockers)
	}
	if _, err := policyedit.PrepareCollection(context.Background(), f.client, policyedit.CollectionRequest{Action: "create", Collection: "x"}); err == nil {
		t.Error("create without kind accepted")
	}
}

func TestCollectionAmbiguousName(t *testing.T) {
	f := collectionFake(t)
	_, err := policyedit.PrepareCollection(context.Background(), f.client, policyedit.CollectionRequest{Action: "update", Collection: "default", NewName: "x"})
	if err == nil || !strings.Contains(err.Error(), "pass kind") {
		t.Fatalf("ambiguous name: %v", err)
	}
	p := prepare(t, f, policyedit.CollectionRequest{Action: "update", Collection: "default", Kind: "intel", NewName: "intel-default"})
	if p.Collection.ID != 3 || !p.Ready() {
		t.Fatalf("kind did not narrow: %+v", p)
	}
	apply(t, f, p)
	if f.collections[3]["name"] != "intel-default" {
		t.Errorf("not renamed: %v", f.collections[3])
	}
}

func TestCollectionDelete(t *testing.T) {
	f := collectionFake(t)
	p := prepare(t, f, policyedit.CollectionRequest{Action: "delete", Collection: "edge-inputs"})
	if p.Ready() || !has(p.Blockers, "still use") {
		t.Fatalf("delete of a used collection not blocked: %v", p.Blockers)
	}
	p = prepare(t, f, policyedit.CollectionRequest{Action: "delete", Collection: "edge-inputs", UnlinkPolicies: []string{"18"}})
	if !p.Ready() {
		t.Fatalf("not ready: %v", p.Blockers)
	}
	if !has(p.Warnings, "left with no input collection") {
		t.Errorf("warnings %v", p.Warnings)
	}
	apply(t, f, p)
	if _, ok := f.collections[2]; ok {
		t.Error("collection 2 still there")
	}
	if v := f.policies[18]["inputCollectionID"]; v != nil {
		t.Errorf("edge still links %v", v)
	}
	if p := prepare(t, f, policyedit.CollectionRequest{Action: "delete", Collection: "default", Kind: "intel", AddSources: []string{"80"}}); !has(p.Blockers, "delete only takes unlink_policies") {
		t.Errorf("delete with sources not blocked: %v", p.Blockers)
	}
}

func TestCollectionRemoveAndUnknownSource(t *testing.T) {
	f := collectionFake(t)
	p := prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "default",
		RemoveSources: []string{"59"}, AddSources: []string{"nope"}})
	if !has(p.Blockers, `no source "nope"`) {
		t.Fatalf("unknown source not blocked: %v", p.Blockers)
	}
	p = prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "default", RemoveSources: []string{"59"}})
	apply(t, f, p)
	if fmt.Sprint(f.mutations) != "[unassociate 1 [59]]" {
		t.Errorf("mutations %v", f.mutations)
	}
	// An intel source is not an input source.
	p = prepare(t, f, policyedit.CollectionRequest{Action: "update", Kind: "input", Collection: "default", AddSources: []string{"80"}})
	if !has(p.Blockers, "no source") {
		t.Errorf("intel source accepted for an input collection: %v", p.Blockers)
	}
}

func TestCollectionYara(t *testing.T) {
	f := collectionFake(t)
	f.yaraSources = []map[string]any{{"id": int64(90), "name": "Corelight-update-yara", "enabled": true}, {"id": int64(91), "name": "lab rules", "enabled": true}}
	p := prepare(t, f, policyedit.CollectionRequest{Action: "create", Kind: "yara", Collection: "lab-yara",
		AddSources: []string{"lab rules", "Corelight-update-yara"}, LinkPolicies: []string{"defaultPolicy"}})
	if len(p.Blockers) > 0 || p.What != "YARA ruleset" {
		t.Fatalf("plan %+v", p)
	}
	res := apply(t, f, p)
	if got := fmt.Sprint(f.rulesetSrc[res.ID]); got != "[91 90]" {
		t.Errorf("ruleset sources %s", got)
	}
	if fmt.Sprint(f.policies[17]["yaraRulesetID"]) != fmt.Sprint(res.ID) {
		t.Errorf("policy yaraRulesetID %v", f.policies[17]["yaraRulesetID"])
	}
	p = prepare(t, f, policyedit.CollectionRequest{Action: "delete", Kind: "yara", Collection: "lab-yara", UnlinkPolicies: []string{"defaultPolicy"}})
	apply(t, f, p)
	if _, ok := f.rulesets[res.ID]; ok {
		t.Error("ruleset still there")
	}
}
