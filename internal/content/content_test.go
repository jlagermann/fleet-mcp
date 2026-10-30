package content_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/content"
)

func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func preview(t *testing.T, p any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(p)
	return buf.String()
}

const intelV1 = "#fields\tindicator\tindicator_type\tmeta.source\n1.2.3.4\tIntel::ADDR\ta\nevil.example\tIntel::DOMAIN\ta\n"
const intelV2 = "#fields\tindicator\tindicator_type\tmeta.source\n1.2.3.4\tIntel::ADDR\ta\n5.6.7.8\tIntel::ADDR\tb\n"

func TestIntelCreateAndLink(t *testing.T) {
	fm := newFake(t)
	fm.policies[1] = map[string]any{"id": 1, "name": "Edge", "description": "d", "packages.enabled": map[string]any{"x": true}, "configuration": map[string]any{"a": 1}}
	ctx := context.Background()
	req := content.Request{Kind: content.Intel, File: writeFile(t, "intel.dat", []byte(intelV1)), Policy: "Edge"}
	p, err := content.Prepare(ctx, fm.client, req)
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	if !p.Ready() || p.Target.Exists || !strings.Contains(out, `create intel file source \"fleet-mcp\"`) ||
		!strings.Contains(out, `create intel collection \"Edge\"`) || !strings.Contains(out, `"indicators":2`) {
		t.Fatalf("plan: %s", out)
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err != nil {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if len(res.Verification) > 0 {
		t.Fatalf("verification: %v", res.Verification)
	}
	pol := fm.policies[1]
	if content := pol["intelCollectionID"]; content == nil || pol["name"] != "Edge" || pol["configuration"].(map[string]any)["a"] != float64(1) && pol["configuration"].(map[string]any)["a"] != 1 {
		t.Fatalf("policy after: %v", pol)
	}

	// The same file again: nothing to do.
	p, err = content.Prepare(ctx, fm.client, req)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Unchanged || p.Ready() {
		t.Fatalf("same file should be unchanged: %s", preview(t, p))
	}

	// A new version updates the source in place and shows the diff.
	req.File = writeFile(t, "intel.dat", []byte(intelV2))
	p, err = content.Prepare(ctx, fm.client, req)
	if err != nil {
		t.Fatal(err)
	}
	out = preview(t, p)
	if !p.Ready() || !p.Target.Exists || !strings.Contains(out, "5.6.7.8 Intel::ADDR") || !strings.Contains(out, "evil.example Intel::DOMAIN") ||
		!strings.Contains(out, "already in intel collection") {
		t.Fatalf("update plan: %s", out)
	}
	if res, err = content.Apply(ctx, fm.client, p); err != nil || len(res.Verification) > 0 {
		t.Fatalf("update: %v %v", err, res)
	}
	if n := len(fm.sources); n != 1 {
		t.Fatalf("%d sources, want 1", n)
	}
}

func TestIntelWithoutHeaderIsBlocked(t *testing.T) {
	fm := newFake(t)
	p, err := content.Prepare(context.Background(), fm.client, content.Request{Kind: content.Intel, File: writeFile(t, "i.dat", []byte("1.2.3.4\tIntel::ADDR\ta\n"))})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() || !strings.Contains(preview(t, p), "#fields") {
		t.Fatalf("plan: %s", preview(t, p))
	}
}

func TestInputManagedByCorelightUpdateAndReaders(t *testing.T) {
	fm := newFake(t)
	old := fm.addFile([]byte("#fields\thost\nold\n"))
	fm.sources[5] = map[string]any{"id": "5", "alias": "defaultPolicy_hosts.tsv", "name": "hosts.tsv", "type": "INPUT", "enabled": true,
		"description": "Created by Corelight Update", "fileId": old}
	fm.sensors = []any{map[string]any{"fleet.connected": true, "bro.inputs": []any{map[string]any{"name": "hosts.tsv", "package": "customer:endpoint"}}}}
	p, err := content.Prepare(context.Background(), fm.client, content.Request{Kind: content.Input,
		File: writeFile(t, "hosts.tsv", []byte("#fields\thost\nnew\n")), Source: "defaultPolicy_hosts.tsv"})
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	if !p.Ready() || p.Target.ManagedBy != "Corelight-update" || !strings.Contains(out, "next push overwrites") ||
		!strings.Contains(out, "read by: customer:endpoint") || !strings.Contains(out, "no sensor policy uses") {
		t.Fatalf("plan: %s", out)
	}
}

func TestRollbackOnLinkFailure(t *testing.T) {
	fm := newFake(t)
	fm.policies[1] = map[string]any{"id": 1, "name": "Edge"}
	fm.failOn = "associateFileCollectionToSources"
	ctx := context.Background()
	p, err := content.Prepare(ctx, fm.client, content.Request{Kind: content.Intel, File: writeFile(t, "intel.dat", []byte(intelV1)), Policy: "1"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err == nil {
		t.Fatal("apply should fail")
	}
	if len(fm.deleted) != 2 || len(res.RolledBack) != 2 || fm.policies[1]["intelCollectionID"] != nil {
		t.Fatalf("rollback: deleted %v, result %v, policy %v", fm.deleted, res.RolledBack, fm.policies[1])
	}
}

const rulesOld = `alert tcp any any -> any any (msg:"a"; sid:1; rev:1;)
alert tcp any any -> any any (msg:"b"; sid:2; rev:1;)
# alert tcp any any -> any any (msg:"c"; sid:3; rev:1;)
`
const rulesNew = `alert tcp any any -> any any (msg:"a"; sid:1; rev:2;)
alert tcp any any -> any any (msg:"c"; sid:3; rev:1;)
alert tcp any any -> any any (msg:"d"; sid:4; rev:1;)
`

func TestSuricataRulesAutomation(t *testing.T) {
	fm := newFake(t)
	old := fm.addFile([]byte(rulesOld))
	fm.suricata[7] = map[string]any{"id": 7, "name": "Lab", "rulesAutomation": true, "sources": []any{
		map[string]any{"id": 11, "name": "ET Pro", "entityType": "url", "enabled": true, "url": "https://rules.example/secret/x.tar.gz"},
		map[string]any{"id": 12, "name": "Corelight-update", "entityType": "file", "enabled": true, "fileId": old, "created_by": "Corelight-update"},
	}}
	fm.policies[1] = map[string]any{"id": 1, "name": "Edge", "suricataPolicyID": 7}
	ctx := context.Background()
	p, err := content.Prepare(ctx, fm.client, content.Request{Kind: content.SuricataRules, File: writeFile(t, "suricata.rules", []byte(rulesNew)),
		Policy: "Edge", Source: "Corelight-update"})
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	for _, want := range []string{`"added_sids":{"count":1,"sample":["4"]}`, `"removed_sids":{"count":1,"sample":["2"]}`,
		`"changed_sids":{"count":1,"sample":["1"]}`, `"newly_enabled_sids":{"count":1,"sample":["3"]}`, `"by":"Fleet Manager rule parser`, "Corelight-update", `"used_by_sensor_policies":["Edge (1)"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %s: %s", want, out)
		}
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	srcs := fm.suricata[7]["sources"].([]any)
	if len(srcs) != 2 || srcs[0].(map[string]any)["url"] != "https://rules.example/secret/x.tar.gz" ||
		int64(srcs[1].(map[string]any)["fileId"].(float64)) != res.FileID {
		t.Fatalf("sources after: %v", srcs)
	}
}

func TestSuricataYAMLNeedsHeader(t *testing.T) {
	fm := newFake(t)
	fm.suricata[7] = map[string]any{"id": 7, "name": "Lab"}
	p, err := content.Prepare(context.Background(), fm.client, content.Request{Kind: content.SuricataYAML,
		File: writeFile(t, "suricata.yaml", []byte("vars:\n  address-groups: {}\n")), SuricataPolicy: "Lab"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() || !strings.Contains(preview(t, p), "%YAML 1.1") {
		t.Fatalf("plan: %s", preview(t, p))
	}
}

func bundleFile(t *testing.T, manifest string, revs map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	add("./manifest.txt", manifest)
	// One package on a branch, the others detached; .git/shallow lists
	// other commits first, as real shallow clones do.
	for dir, rev := range revs {
		add("./"+dir+"/.git/shallow", "ffffffffffff\n"+rev+"\n")
		if dir == "ExtendIntel" {
			add("./"+dir+"/.git/HEAD", "ref: refs/heads/main\n")
			add("./"+dir+"/.git/refs/heads/main", rev+"\n")
		} else {
			add("./"+dir+"/.git/HEAD", rev+"\n")
		}
		add("./"+dir+"/zkg.meta", "[package]\n")
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestBundle(t *testing.T) {
	fm := newFake(t)
	fm.bundles[50] = map[string]any{"id": 50, "name": "old", "description": "Package created and managed by Corelight-update", "info": map[string]any{"packages": map[string]any{
		"https:github.com:corelight:ExtendIntel": map[string]any{"version": "v4.0", "revision": "aaaa"},
		":home:u:gone":                           map[string]any{"version": "main", "revision": "bbbb"},
	}}}
	fm.policies[1] = map[string]any{"id": 1, "name": "Edge", "bundle.id": 50, "description": "",
		"packages.enabled": map[string]any{"https:github.com:corelight:ExtendIntel": true, ":home:u:gone": true}}
	b := bundleFile(t, "[bundle]\nhttps://github.com/corelight/ExtendIntel = v4.1\n/home/u/new = main\n",
		map[string]string{"ExtendIntel": "cccc", "new": "dddd"})
	ctx := context.Background()
	p, err := content.Prepare(ctx, fm.client, content.Request{Kind: content.Bundle, File: writeFile(t, "corelight.bundle", b), Policy: "Edge"})
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	for _, want := range []string{`:home:u:new = main`, `v4.0 aaaa -> v4.1 cccc`, `"removed":[":home:u:gone"]`,
		"arrive disabled", "is enabled in the policy but is not in the new bundle"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %s: %s", want, out)
		}
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if got := fm.policies[1]; int64(got["bundle.id"].(float64)) != res.BundleID || got["packages.enabled"].(map[string]any)[":home:u:gone"] != true {
		t.Fatalf("policy after: %v", got)
	}
}

func TestBundleWithoutManifestIsBlocked(t *testing.T) {
	fm := newFake(t)
	fm.policies[1] = map[string]any{"id": 1, "name": "Edge"}
	p, err := content.Prepare(context.Background(), fm.client, content.Request{Kind: content.Bundle, File: writeFile(t, "x.bundle", []byte("not gzip")), Policy: "Edge"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() {
		t.Fatalf("plan: %s", preview(t, p))
	}
}

func TestYaraCreateLinkAndValidate(t *testing.T) {
	fm := newFake(t)
	fm.policies[1] = map[string]any{"id": 1, "name": "Edge"}
	ctx := context.Background()
	p, err := content.Prepare(ctx, fm.client, content.Request{Kind: content.Yara, File: writeFile(t, "r.yar", []byte("rule a { condition: true }\nprivate rule b { condition: false }\n")), Policy: "Edge"})
	if err != nil {
		t.Fatal(err)
	}
	if out := preview(t, p); !p.Ready() || !strings.Contains(out, `"rules":2`) || !strings.Contains(out, `"valid":true`) {
		t.Fatalf("plan: %s", out)
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if fm.policies[1]["yaraRulesetID"] == nil {
		t.Fatalf("policy not linked: %v", fm.policies[1])
	}

	p, err = content.Prepare(ctx, fm.client, content.Request{Kind: content.Yara, File: writeFile(t, "bad.yar", []byte("rule c { strings: $a = \"x\" }\n"))})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() {
		t.Fatalf("invalid YARA should block: %s", preview(t, p))
	}
}

func TestPackageKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/corelight/ExtendIntel": "https:github.com:corelight:ExtendIntel",
		"/home/user/zeek-packages/dns-bypass":      ":home:user:zeek-packages:dns-bypass",
	} {
		if got := content.PackageKey(in); got != want {
			t.Errorf("PackageKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLintModifier(t *testing.T) {
	// Corelight-update syntax (lines 5-10) is left to the conversion; only
	// lines neither tool understands are problems.
	modify := strings.Join([]string{
		"# comment",
		`2620092 SrcAddress:![192.0.2.32, 192.0.2.33]`,
		`re:/deployment SSLDecrypt/ DestAddress:![$HOME_NET]`,
		`2101616 RuleOptions:(msg:"GPL DNS named version returned"; sid:2101616; rev:10;)`,
		`8001666 Msg:"Some message"`,
		`2038967 GID:3`,
		`2011768 MetadataAppend:followup watch`,
		`re:(mitre_technique_id\sT1190|tag\sExploit\b) "^(alert \S+) any " "$1 !$$SCANNERS "`,
		`re:classtype:(web-application-attack); "^(alert \S+) any " "$1 x "`,
		`Metadata:"deployment SSLDecrypt" Action:drop`,
		`2000001 Priority:1`,
		`2000002 Bogus:1`,
		`Nope:1 Action:drop`,
		`2000003`,
	}, "\n")
	errs, _ := content.LintModifier(content.SuricataModify, []byte(modify))
	for _, want := range []string{`line 12: change key "bogus"`, `line 13: unknown match key "Nope"`, "line 14: no change"} {
		if !strings.Contains(strings.Join(errs, "\n"), want) {
			t.Errorf("missing %q in %v", want, errs)
		}
	}
	if len(errs) != 3 {
		t.Errorf("%d problems, want 3: %v", len(errs), errs)
	}

	disable := "2033683 # a comment\n1:2035465\nsid:2053281\nre:/x y/\nMetadata:\"deployment SSLDecrypt\"\nBogus:1\n2069171 Action:drop\n"
	errs, _ = content.LintModifier(content.SuricataDisable, []byte(disable))
	if len(errs) != 2 || !strings.Contains(errs[0], "line 6") || !strings.Contains(errs[1], "line 7") {
		t.Errorf("disable: errs %v", errs)
	}
}

func TestSuricataModifierPush(t *testing.T) {
	fm := newFake(t)
	fm.suricata[7] = map[string]any{"id": 7, "name": "Lab", "rulesAutomation": true, "useModifierFiles": false,
		"config": map[string]any{"srmEnableFlowBits": true}, "modifierFiles": []any{
			map[string]any{"id": 1, "name": "disable.conf", "fileId": 0, "enabled": false, "status": "empty"},
			map[string]any{"id": 2, "name": "enable.conf", "fileId": 0, "enabled": false, "status": "empty"},
			map[string]any{"id": 3, "name": "modify.conf", "fileId": 0, "enabled": false, "status": "empty"},
		}}
	ctx := context.Background()
	req := content.Request{Kind: content.SuricataDisable, File: writeFile(t, "disable.conf", []byte("2000328\nsid:2001219\n")), SuricataPolicy: "Lab"}
	p, err := content.Prepare(ctx, fm.client, req)
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	for _, want := range []string{`switch Suricata policy \"Lab\" to \"Use configuration files\"`, "rule modifiers made in the rules manager stop applying",
		`"flowbit_dependencies":true`, "even rules disable.conf turned off"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %s: %s", want, out)
		}
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	sp := fm.suricata[7]
	mods := sp["modifierFiles"].([]any)
	if sp["useModifierFiles"] != true || len(mods) != 3 || mods[0].(map[string]any)["enabled"] != true ||
		int64(mods[0].(map[string]any)["fileId"].(float64)) != res.FileID || mods[1].(map[string]any)["enabled"] != false {
		t.Fatalf("policy after: %v", sp)
	}
	if !strings.Contains(strings.Join(res.Done, "\n"), "rebuilt the ruleset without errors") {
		t.Fatalf("done: %v", res.Done)
	}

	// A policy without automation cannot take configuration files.
	fm.suricata[8] = map[string]any{"id": 8, "name": "Plain", "rulesAutomation": false}
	req.SuricataPolicy = "Plain"
	if p, err = content.Prepare(ctx, fm.client, req); err != nil || p.Ready() {
		t.Fatalf("no automation: %v %s", err, preview(t, p))
	}
}

func srmPolicy(fm *fakeFM) {
	rule := func(sid string, disabled bool) map[string]any {
		return map[string]any{"sid": sid, "message": `"r` + sid + `"`, "disabled": disabled, "action": "alert", "protocol": "http",
			"srcAddress": "any", "srcPort": "any", "destAddress": "any", "destPort": "any", "rawOptions": "(msg:\"r\"; sid:" + sid + ";)"}
	}
	fm.suricata[13] = map[string]any{"id": 13, "name": "SRM", "rulesAutomation": true, "useModifierFiles": false,
		"config": map[string]any{"srmEnableFlowBits": true},
		"rules":  map[string]any{"100": rule("100", false), "200": rule("200", true), "300": rule("300", false)},
		"mods": []any{
			map[string]any{"id": float64(1), "action": "disable", "match": map[string]any{"key": "sid", "value": "300"}, "change": map[string]any{"key": "", "value": ""}, "comment": "old"},
			map[string]any{"id": float64(2), "action": "modify", "match": map[string]any{"key": "sid", "value": "100"}, "change": map[string]any{"key": "srcaddress", "value": "!10.0.0.1"}, "comment": "old"},
		}}
}

func TestSRMModify(t *testing.T) {
	fm := newFake(t)
	srmPolicy(fm)
	ctx := context.Background()
	req := content.SRMRequest{SuricataPolicy: "SRM", Changes: []content.RuleChange{
		{SID: "100", Action: "disable", Comment: "noisy"},
		{SID: "100", Action: "modify", ChangeKey: "SrcAddress", ChangeValue: "!10.0.0.2"},
		{SID: "200", Action: "enable"},
		{SID: "300", Action: "enable"},
		{SID: "300", Action: "enable", Comment: "dup"},
	}}
	p, err := content.PrepareSRM(ctx, fm.client, req)
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	if !p.Ready() || len(p.Add) != 3 || len(p.Update) != 1 || len(p.Remove) != 1 || !strings.Contains(preview(t, p), "change 5 repeats") {
		t.Fatalf("plan: add %d update %d remove %d unchanged %d: %s", len(p.Add), len(p.Update), len(p.Remove), len(p.Unchanged), out)
	}
	for _, want := range []string{`update modifier 2: sid:100 srcaddress \"!10.0.0.1\" -> \"!10.0.0.2\"`, "remove modifier 1 (disable sid:300): replaced by enable",
		`"200":"enabled"`, "re-enables a disabled rule"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %s: %s", want, out)
		}
	}
	res, err := content.ApplySRM(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	after := res.RulesAfter
	if after["100"].Enabled || after["100"].Src != "!10.0.0.2" || !after["200"].Enabled || !after["300"].Enabled {
		t.Fatalf("after: %+v", after)
	}

	// The same request again: nothing to do.
	p, _ = content.PrepareSRM(ctx, fm.client, req)
	if p.Ready() || len(p.Blockers) > 0 {
		t.Fatalf("second run should be a no-op: %s", preview(t, p))
	}

	// Remove by SID.
	p, err = content.PrepareSRM(ctx, fm.client, content.SRMRequest{SuricataPolicy: "13", Remove: []string{"sid:100"}})
	if err != nil || len(p.Remove) != 2 {
		t.Fatalf("remove plan: %v %s", err, preview(t, p))
	}
}

func TestSRMBlockers(t *testing.T) {
	fm := newFake(t)
	srmPolicy(fm)
	ctx := context.Background()
	p, err := content.PrepareSRM(ctx, fm.client, content.SRMRequest{SuricataPolicy: "SRM", Changes: []content.RuleChange{
		{SID: "100", Action: "modify", ChangeKey: "msg", ChangeValue: "x"},
		{SID: "abc", Action: "disable"},
		{MatchKey: "re", MatchValue: "no slashes", Action: "disable"},
		{SID: "100", Action: "drop"},
		{SID: "999", Action: "disable"},
	}, Remove: []string{"77"}})
	if err != nil {
		t.Fatal(err)
	}
	out := preview(t, p)
	if p.Ready() || len(p.Blockers) != 5 || !strings.Contains(out, "no rule with SID 999") {
		t.Fatalf("%d blockers: %s", len(p.Blockers), out)
	}

	fm.suricata[13]["useModifierFiles"] = true
	p, _ = content.PrepareSRM(ctx, fm.client, content.SRMRequest{SuricataPolicy: "SRM", Changes: []content.RuleChange{{SID: "100", Action: "disable"}}})
	if p.Ready() || !strings.Contains(preview(t, p), "uses configuration files") {
		t.Fatalf("config-files mode: %s", preview(t, p))
	}
}

func TestSRMClash(t *testing.T) {
	fm := newFake(t)
	srmPolicy(fm)
	p, err := content.PrepareSRM(context.Background(), fm.client, content.SRMRequest{SuricataPolicy: "SRM", Changes: []content.RuleChange{
		{SID: "200", Action: "enable"}, {SID: "200", Action: "disable"},
	}})
	if err != nil || p.Ready() || !strings.Contains(preview(t, p), "both enable and disable requested for sid:200") {
		t.Fatalf("%v %s", err, preview(t, p))
	}
}

func TestModifyConversionPush(t *testing.T) {
	fm := newFake(t)
	src := "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"A\"; content:\"a\"; metadata:created_at 2026; sid:100; rev:1;)\n" +
		"alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"B\"; content:\"b\"; sid:200; rev:1;)\n"
	srcID := fm.addFile([]byte(src))
	// The modify.conf Fleet Manager applies now changed 100 (a local file
	// source) and 300 (from a URL source), so the rules API shows them changed.
	applied := "~ 100 RuleOptions:(msg:\"A\"; content:\"a\"; metadata:created_at 2026, followup watch; sid:100; rev:1;)\n~ 300 SrcAddress:10.0.0.1\n"
	curID := fm.addFile([]byte(applied))
	rule := func(sid, file, srcAddr, opts string) map[string]any {
		return map[string]any{"sid": sid, "action": "alert", "protocol": "http", "srcAddress": srcAddr, "srcPort": "any", "direction": "->",
			"destAddress": "$HOME_NET", "destPort": "any", "rawOptions": opts, "filename": file, "disabled": false}
	}
	fm.suricata[9] = map[string]any{"id": 9, "name": "Edge", "rulesAutomation": true, "useModifierFiles": true, "config": map[string]any{},
		"sources": []any{
			map[string]any{"id": 1, "name": "local", "entityType": "file", "enabled": true, "fileId": srcID, "filename": "local.rules"},
			map[string]any{"id": 2, "name": "ET", "entityType": "url", "enabled": true, "url": "https://example.com/emerging.rules.tar.gz"},
		},
		"modifierFiles": []any{
			map[string]any{"id": 1, "name": "disable.conf", "fileId": 0, "enabled": false},
			map[string]any{"id": 2, "name": "enable.conf", "fileId": 0, "enabled": false},
			map[string]any{"id": 3, "name": "modify.conf", "fileId": curID, "enabled": true},
		},
		"rules": map[string]any{
			"100": rule("100", "local.rules", "$EXTERNAL_NET", `(msg:"A"; content:"a"; metadata:created_at 2026, followup watch; sid:100; rev:1;)`),
			"200": rule("200", "local.rules", "$EXTERNAL_NET", `(msg:"B"; content:"b"; sid:200; rev:1;)`),
			"300": rule("300", "emerging.rules", "10.0.0.1", `(msg:"C"; sid:300; rev:1;)`),
		}}
	ctx := context.Background()
	file := writeFile(t, "modify.conf", []byte("100 MetadataAppend:followup watch\n300 Msg:\"C2\"\n200 SrcAddress:1.2.3.4\n"))
	outPath := filepath.Join(filepath.Dir(file), "modify.fm.conf")
	req := content.Request{Kind: content.SuricataModify, File: file, SuricataPolicy: "Edge"}

	// Without an answer: a decision, a preview of each line, nothing written.
	p, err := content.Prepare(ctx, fm.client, req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() || len(p.Decisions) != 1 || p.Decisions[0].ID != "cu_modifiers" || p.Conversion == nil || p.Conversion.Count != 2 {
		t.Fatalf("preview: %s", preview(t, p))
	}
	c := p.Conversion
	for _, l := range c.Lines {
		if l.Action != "converted if you choose convert" || l.Result != nil {
			t.Errorf("before the answer, lines that need rule text are only listed: %s", preview(t, l))
		}
	}
	if fm.rulesReads != 0 {
		t.Errorf("the preview without an answer read the policy's rules %d time(s)", fm.rulesReads)
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Errorf("preview without an answer wrote %s", outPath)
	}

	// convert: the rules are read, the file is written next to the user's
	// and pushed.
	req.CUModifiers = content.CUConvert
	if p, err = content.Prepare(ctx, fm.client, req); err != nil || !p.Ready() {
		t.Fatalf("convert: %v %s", err, preview(t, p))
	}
	c = p.Conversion
	if fm.rulesReads != 1 || len(c.Lines) != 2 || len(c.Lines[0].Result) != 1 ||
		c.Lines[0].Result[0] != `100 RuleOptions:(msg:"A"; content:"a"; metadata:created_at 2026, followup watch; sid:100; rev:1;)` {
		t.Errorf("line 1 (appended once, from the file source; %d rule reads): %s", fm.rulesReads, preview(t, c.Lines))
	}
	if c.Lines[1].Action != "commented out" || !strings.Contains(c.Lines[1].Reason, "give rules_file") || len(c.NeedRulesFile) != 1 || c.NeedRulesFile[0] != 2 {
		t.Errorf("line 2 (URL source): %s", preview(t, c))
	}

	// comment_out never reads the rules.
	reads := fm.rulesReads
	req.CUModifiers = content.CUCommentOut
	if p, err = content.Prepare(ctx, fm.client, req); err != nil || !p.Ready() || fm.rulesReads != reads {
		t.Fatalf("comment_out: %v reads %d→%d %s", err, reads, fm.rulesReads, preview(t, p))
	}
	req.CUModifiers = content.CUConvert
	if p, err = content.Prepare(ctx, fm.client, req); err != nil || !p.Ready() {
		t.Fatalf("convert again: %v %s", err, preview(t, p))
	}
	written, err := os.ReadFile(outPath)
	if err != nil || p.Conversion.Output != outPath || !strings.Contains(string(written), "\n200 SrcAddress:1.2.3.4\n") ||
		!strings.Contains(string(written), "# fleet-mcp: commented out (the current modify.conf") {
		t.Fatalf("written %s: %v\n%s", outPath, err, written)
	}
	res, err := content.Apply(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if string(fm.files[res.FileID]) != string(written) {
		t.Errorf("uploaded file differs from %s", outPath)
	}

	// rules_file supplies the URL source's original text.
	req.RulesFile = writeFile(t, "emerging.rules", []byte("alert http any any -> $HOME_NET any (msg:\"C\"; sid:300; rev:1;)\n"))
	if p, err = content.Prepare(ctx, fm.client, req); err != nil || !p.Ready() {
		t.Fatalf("rules_file: %v %s", err, preview(t, p))
	}
	if got := strings.Join(p.Conversion.Lines[1].Result, "\n"); got != `300 RuleOptions:(msg:"C2"; sid:300; rev:1;)` {
		t.Errorf("rules_file line 2: %q", got)
	}
	if p.Conversion.Lines[0].Action != "converted" || len(p.Conversion.NeedRulesFile) != 0 {
		t.Errorf("rules_file only fills in missing rules: %s", preview(t, p.Conversion))
	}
}
