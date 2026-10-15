package policyedit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/policyedit"
)

func preview(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return buf.String()
}

func setup(t *testing.T) *fakeFM {
	fm := newFake(t)
	fm.bundles[50] = map[string]any{"id": int64(50), "name": "edge.bundle", "info": map[string]any{"packages": map[string]any{
		"https:github.com:corelight:ExtendIntel": map[string]any{}, ":home:u:dns-bypass": map[string]any{}}}}
	fm.bundles[51] = map[string]any{"id": int64(51), "name": "other.bundle"}
	fm.suricata[7] = map[string]any{"id": int64(7), "name": "Lab"}
	fm.suricata[8] = map[string]any{"id": int64(8), "name": "Shared"}
	fm.rulesets[9] = "Edge YARA"
	fm.collections[20] = map[string]any{"id": "20", "name": "Edge intel", "type": "INTEL", "sources": []any{
		map[string]any{"id": "1", "alias": "feed", "name": "bro_intel.dat", "enabled": true, "file": map[string]any{"id": "5"}}}}
	fm.collections[21] = map[string]any{"id": "21", "name": "Empty input", "type": "INPUT", "sources": []any{}}
	fm.policies[1] = map[string]any{"id": int64(1), "name": "Edge", "description": "edge", "configuration": map[string]any{"bro.analyzers.mqtt.enable": true, "bro.site.local_nets": "10.0.0.0/8"},
		"packages.enabled": map[string]any{"https:github.com:corelight:ExtendIntel": true}, "bundle.id": int64(50), "suricataPolicyID": int64(7),
		"yaraRulesetID": int64(9), "intelCollectionID": int64(20), "record.updated-at": "t0"}
	fm.policies[2] = map[string]any{"id": int64(2), "name": "Core", "configuration": map[string]any{"corelight.yara.enable": true}, "suricataPolicyID": int64(8)}
	fm.policies[3] = map[string]any{"id": int64(3), "name": "Other", "configuration": map[string]any{}, "suricataPolicyID": int64(8), "bundle.id": int64(51)}
	fm.groups[1] = map[string]any{"id": int64(1), "name": "border", "policy.id": int64(1)}
	fm.groups[2] = map[string]any{"id": int64(2), "name": "core", "policy.id": int64(2)}
	fm.sensors = []map[string]any{
		{"uid": "aa", "name": "Lab-Sensor1", "group.id": int64(1), "fleet.connected": true, "licenses": []any{
			map[string]any{"name": "suricata", "active": true}, map[string]any{"name": "yara", "active": false}}},
		{"uid": "bb", "name": "Lab-Sensor2", "group.id": int64(0), "fleet.connected": false, "licenses": []any{
			map[string]any{"name": "suricata", "active": true}, map[string]any{"name": "yara", "active": true}}},
	}
	return fm
}

func TestUpdate(t *testing.T) {
	fm := setup(t)
	ctx := context.Background()
	req := policyedit.UpdateRequest{Policy: "Edge", Description: "edge sensors",
		Settings: map[string]any{
			"bro.analyzers.modbus.enable": false,
			"bro.analyzers.mqtt.enable":   nil,
			"bro.site.local_nets":         []any{"10.0.0.0/8", "172.16.0.0/12"},
			"corelight.yara.enable":       "true",
		},
		SecretSettings:  []string{"proxy.password"},
		EnablePackages:  []string{"JA4", "dns-bypass"},
		DisablePackages: []string{"corelight:dga-detector"},
		SuricataPolicy:  "Shared", YaraRuleset: "none", InputCollection: "Empty input", Bundle: "edge.bundle",
	}
	p, err := policyedit.PrepareUpdate(ctx, fm.client, req, map[string]string{"proxy.password": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	out := preview(p)
	if !p.Ready() || strings.Contains(out, "s3cret") {
		t.Fatalf("plan: %s", out)
	}
	for _, want := range []string{`"item":"bro.analyzers.mqtt.enable","from":"true","to":"default \"0\""`, `"to":"\"10.0.0.0/8,172.16.0.0/12\""`,
		"needs the yara license", "(secret from fleet-mcp's store)", `"item":"bro.pkgs.corelight.ja4.loaded"`, `"item":":home:u:dns-bypass","from":"disabled","to":"enabled"`,
		`"item":"bro.pkgs.corelight.dga_detector.loaded","from":"default \"1\"","to":"false"`, `"item":"yaraRulesetID"`, `"to":"Suricata policy \"Shared\" (8)"`,
		`package bundle \"edge.bundle\" (50) is already linked`, `Empty input\" has no sources`, "1 sensor(s) in 1 group(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %s", want)
		}
	}
	res, err := policyedit.ApplyUpdate(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	pol := fm.policies[1]
	cfg := pol["configuration"].(map[string]any)
	if _, ok := cfg["bro.analyzers.mqtt.enable"]; ok || cfg["proxy.password"] != "s3cret" || cfg["bro.analyzers.modbus.enable"] != false ||
		pol["yaraRulesetID"] != nil || pol["suricataPolicyID"] != float64(8) || pol["packages.enabled"].(map[string]any)[":home:u:dns-bypass"] != true {
		t.Fatalf("policy after: %v", pol)
	}

	// The same request again changes nothing.
	p, _ = policyedit.PrepareUpdate(ctx, fm.client, req, map[string]string{"proxy.password": "s3cret"})
	for _, c := range p.Changes {
		if c.Kind != "secret setting" {
			t.Errorf("second run still changes %s", c.Key)
		}
	}
}

func TestUpdateBlockers(t *testing.T) {
	fm := setup(t)
	p, err := policyedit.PrepareUpdate(context.Background(), fm.client, policyedit.UpdateRequest{Policy: "1",
		Settings:       map[string]any{"nope.key": 1, "proxy.password": "typed in chat", "bro.site.local_nets": "10.0.0.0/8, notacidr", "bro.analyzers.mqtt.enable": "maybe"},
		SecretSettings: []string{"proxy.password"},
		EnablePackages: []string{"no-such-package"},
		SuricataPolicy: "Missing",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := preview(p)
	if p.Ready() {
		t.Fatalf("should block: %s", out)
	}
	for _, want := range []string{`unknown setting \"nope.key\"`, "never in the chat", `\"notacidr\" is not an IP address`, "expects true or false",
		"no value stored for secret setting", `no package \"no-such-package\"`, `no Suricata policy \"Missing\"`} {
		if !strings.Contains(out, want) {
			t.Errorf("blockers lack %s: %s", want, out)
		}
	}
}

func TestDelete(t *testing.T) {
	fm := setup(t)
	ctx := context.Background()
	// Edge is used by a group: blocked.
	p, err := policyedit.PrepareDelete(ctx, fm.client, policyedit.DeleteRequest{Policy: "Edge"})
	if err != nil || p.Ready() || !strings.Contains(preview(p), `sensor group \"border\"`) {
		t.Fatalf("in use: %v %s", err, preview(p))
	}
	// Other: its Suricata policy is shared with Core, its bundle is its own.
	p, err = policyedit.PrepareDelete(ctx, fm.client, policyedit.DeleteRequest{Policy: "Other", RemoveUnused: []string{"all"}})
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %s", err, preview(p))
	}
	out := preview(p)
	if !strings.Contains(out, `"also_used_by":["Core (2)"]`) || !strings.Contains(out, `delete package bundle \"other.bundle\" (51)`) ||
		!strings.Contains(out, "is kept: other policies use it") {
		t.Fatalf("plan: %s", out)
	}
	res, err := policyedit.ApplyDelete(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if fm.policies[3] != nil || fm.bundles[51] != nil || fm.suricata[8] == nil {
		t.Fatalf("after: policies %v bundles %v suricata %v", fm.policies, fm.bundles, fm.suricata)
	}
	if p, _ := policyedit.PrepareDelete(ctx, fm.client, policyedit.DeleteRequest{Policy: "Core", RemoveUnused: []string{"bundle"}}); p.Ready() {
		t.Fatalf("Core has no bundle and is used by a group: %s", preview(p))
	}
}

func TestGroup(t *testing.T) {
	fm := setup(t)
	ctx := context.Background()
	// Create a group with the Core policy (YARA on) and move both sensors in.
	p, err := policyedit.PrepareGroup(ctx, fm.client, policyedit.GroupRequest{Action: "create", Group: "dmz", Policy: "Core", AddSensors: []string{"Lab-Sensor1", "bb"}})
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %s", err, preview(p))
	}
	out := preview(p)
	if !strings.Contains(out, `Lab-Sensor1 has no active license for yara`) || strings.Contains(out, "Lab-Sensor2 has no active license") ||
		!strings.Contains(out, "Lab-Sensor2 is not connected") {
		t.Fatalf("plan: %s", out)
	}
	res, err := policyedit.ApplyGroup(ctx, fm.client, p)
	if err != nil || len(res.Verification) > 0 || res.GroupID == 0 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	for _, s := range fm.sensors {
		if s["group.id"] != res.GroupID {
			t.Errorf("%s in group %v", s["name"], s["group.id"])
		}
	}
	// Update: rename, unassign the policy, take a sensor out.
	p, err = policyedit.PrepareGroup(ctx, fm.client, policyedit.GroupRequest{Action: "update", Group: "dmz", NewName: "dmz2", Policy: "none", RemoveSensors: []string{"bb"}})
	if err != nil || !p.Ready() {
		t.Fatalf("update plan: %v %s", err, preview(p))
	}
	if res, err = policyedit.ApplyGroup(ctx, fm.client, p); err != nil || len(res.Verification) > 0 {
		t.Fatalf("update: %v %+v", err, res)
	}
	if fm.groups[res.GroupID]["name"] != "dmz2" || fm.sensors[1]["group.id"] != int64(0) {
		t.Fatalf("after update: %v %v", fm.groups[res.GroupID], fm.sensors)
	}
	// Delete warns about the remaining sensor.
	p, _ = policyedit.PrepareGroup(ctx, fm.client, policyedit.GroupRequest{Action: "delete", Group: "dmz2"})
	if !p.Ready() || !strings.Contains(preview(p), "become unassigned") {
		t.Fatalf("delete plan: %s", preview(p))
	}
	if res, err = policyedit.ApplyGroup(ctx, fm.client, p); err != nil || len(res.Verification) > 0 {
		t.Fatalf("delete: %v %+v", err, res)
	}
	// Creating an existing name is blocked.
	if p, _ := policyedit.PrepareGroup(ctx, fm.client, policyedit.GroupRequest{Action: "create", Group: "border"}); p.Ready() {
		t.Fatal("duplicate group name should block")
	}
}
