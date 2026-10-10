package migrate_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/migrate"
)

var testSecrets = map[string]string{
	"bro.exporters.abcdefghij.hec_token":                    "TOKEN-123",
	"smartpcap.object_store.provider.s3.kms_encryption_key": "KMS-456",
}

func exportPackage(t *testing.T, snapshot bool) (string, *migrate.Manifest) {
	t.Helper()
	src, pid := seedSource(t)
	dir := filepath.Join(t.TempDir(), "pkg")
	m, err := migrate.Export(context.Background(), src.client, migrate.ExportOptions{
		Fleet: "src", Policy: "lab-policy", Dir: dir, SnapshotConnectorSources: snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Source.PolicyID != pid {
		t.Fatalf("policy id %d, want %d", m.Source.PolicyID, pid)
	}
	// The secrets the user would supply (from the database or a prompt).
	if err := migrate.AddSecrets(dir, testSecrets); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func TestExportOmitsSecrets(t *testing.T) {
	dir, m := exportPackage(t, false)

	cfg := m.Policy.Configuration
	if _, ok := cfg["bro.exporters.abcdefghij.hec_token"]; ok {
		t.Error("hec_token placeholder was exported")
	}
	if _, ok := cfg["smartpcap.object_store.provider.s3.kms_encryption_key"]; ok {
		t.Error("password setting was exported")
	}
	if cfg["bro.exporters.abcdefghij.hec_endpoint"] != "https://splunk.example:8088" || cfg["suricata.enable"] != true {
		t.Errorf("configuration lost settings: %v", cfg)
	}
	if strings.Join(m.Features.Licensed, ",") != "suricata" || strings.Join(m.Features.Exporters, ",") != "hec" {
		t.Errorf("features %+v", m.Features)
	}

	// Licensed feed URL is left out; the public feed and the file source stay.
	var names []string
	for _, s := range m.Suricata.Sources {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "local,Corelight Feed" {
		t.Errorf("suricata sources %v", names)
	}
	if len(m.Suricata.ModifierFiles) != 1 || m.Suricata.ModifierFiles[0].File == nil || m.Suricata.Files["yaml"] == nil {
		t.Errorf("suricata files %+v %+v", m.Suricata.ModifierFiles, m.Suricata.Files)
	}
	// The connector-fed source is omitted without snapshot.
	if c := m.Collections["intel"]; c == nil || len(c.Sources) != 1 || c.Sources[0].Alias != "Corelight-update" {
		t.Errorf("intel collection %+v", m.Collections["intel"])
	}
	want := map[string]bool{"hec_token": false, "kms_encryption_key": false, "ET Pro": false, "CRWD": false}
	for _, o := range m.Omitted {
		for k := range want {
			if strings.Contains(o.Item, k) {
				want[k] = true
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("omission for %s not reported: %+v", k, m.Omitted)
		}
	}

	// No secret value is anywhere in the package.
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, s := range []string{"SECRETCODE123", "SECRETKMS"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s contains %s", p, s)
			}
		}
		return nil
	})

	got, _, err := migrate.ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.VerifyFiles(dir, got); err != nil {
		t.Fatal(err)
	}
	if m.TotalBytes() == 0 {
		t.Error("no files")
	}
}

func TestExportSnapshotsConnectorSources(t *testing.T) {
	_, m := exportPackage(t, true)
	c := m.Collections["intel"]
	if c == nil || len(c.Sources) != 2 {
		t.Fatalf("intel collection %+v", c)
	}
	if !c.Sources[1].Snapshot || c.Sources[1].Connector.AppConnectorID != "crowdstrike-v1" {
		t.Errorf("snapshot source %+v", c.Sources[1])
	}
}

func TestPlanBlocksVersionMismatch(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.3.0-1")
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() || !strings.Contains(strings.Join(p.Blockers, "\n"), "version mismatch") {
		t.Fatalf("blockers %v", p.Blockers)
	}
}

func TestPlanPatchVersionsMatch(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.5-7")
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ready() {
		t.Fatalf("blockers %v", p.Blockers)
	}
	// Sensors never matter for an import: no sensors, no warning.
	if len(p.Licenses) != 1 || p.Licenses[0].Status != "no sensors" || strings.Contains(strings.Join(p.Warnings, " "), "licens") {
		t.Errorf("licenses %+v warnings %v", p.Licenses, p.Warnings)
	}
}

func TestPlanLicenses(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.sensors = []any{licensedSensor("yara")}
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Unlicensed sensors are reported but neither block nor warn.
	if !p.Ready() || strings.Contains(strings.Join(p.Warnings, " "), "licens") || p.Licenses[0].Status != "unlicensed" {
		t.Fatalf("unlicensed: %v %v %+v", p.Blockers, p.Warnings, p.Licenses)
	}
	tgt.sensors = []any{licensedSensor("suricata"), licensedSensor()}
	p, _ = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if !p.Ready() || p.Licenses[0].Status != "partial" || p.Licenses[0].Licensed != 1 {
		t.Fatalf("partial: %v %+v", p.Blockers, p.Licenses)
	}
}

func TestPlanExportersAndSettings(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.exporters = map[string]any{}
	delete(tgt.props, "bro.export.splunk.index")
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Missing exporter types are a question for the user, not a blocker.
	if len(p.Decisions) != 1 || p.Decisions[0].ID != "exporters" || !strings.Contains(p.Decisions[0].Question, "Splunk (hec)") || p.Ready() {
		t.Fatalf("decisions %+v", p.Decisions)
	}
	if b := strings.Join(p.Blockers, "\n"); strings.Contains(b, "exporter") || !strings.Contains(b, "bro.export.splunk.index") {
		t.Fatalf("blockers %v", p.Blockers)
	}
	tgt.props["bro.export.splunk.index"] = map[string]any{"cl:type": "Text"}
	p, err = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{Exclude: []string{"exporters"}})
	if err != nil || !p.Ready() || len(p.Decisions) != 0 {
		t.Fatalf("exclude exporters: %v %v %v", err, p.Blockers, p.Decisions)
	}
	found := false
	for _, o := range p.FollowUp {
		found = found || (o.Part == "exporters" && strings.Contains(o.Item, "Splunk"))
	}
	if !found {
		t.Errorf("excluded exporter not listed for follow-up: %+v", p.FollowUp)
	}
	if _, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{Exclude: []string{"nope"}}); err == nil {
		t.Error("unknown part accepted")
	}
}

func TestPlanNameClash(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.policies[1] = map[string]any{"id": 1, "name": "lab-policy"}
	ctx := context.Background()
	p, _ := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if p.Ready() {
		t.Fatal("name clash not blocked")
	}
	p, _ = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{NameSuffix: "-copy"})
	if !p.Ready() || p.PolicyName != "lab-policy-copy" {
		t.Fatalf("suffix: %v %s", p.Blockers, p.PolicyName)
	}
}

func TestApplyCopiesEverything(t *testing.T) {
	dir, m := exportPackage(t, true)
	tgt := newFakeFM(t, "29.2.2-100")
	ctx := context.Background()
	opts := migrate.ImportOptions{Name: "copied"}
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, opts)
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %v", err, p.Blockers)
	}
	res, err := migrate.Apply(ctx, tgt.client, dir, m, p, opts)
	if err != nil {
		t.Fatalf("apply: %v (%+v)", err, res)
	}
	if len(res.Verification) > 0 {
		t.Errorf("verification: %v", res.Verification)
	}
	pol := tgt.policies[res.PolicyID]
	if pol["name"] != "copied" {
		t.Fatalf("policy %v", pol)
	}
	cfg := pol["configuration"].(map[string]any)
	if cfg["bro.exporters.abcdefghij.hec_token"] != "TOKEN-123" {
		t.Error("exporter token not sent to the target")
	}
	if _, err := os.Stat(filepath.Join(dir, migrate.SecretsFile)); !os.IsNotExist(err) {
		t.Error("secrets file kept after a complete import")
	}
	sp := tgt.suricata[int64(pol["suricataPolicyID"].(float64))]
	if sp == nil || len(sp["sources"].([]any)) != 2 || sp["homeNet"] != "[10.0.0.0/8]" || sp["modifierFiles"] == nil || sp["suricata-yaml-file-id"] == nil {
		t.Fatalf("suricata policy %v", sp)
	}
	for _, s := range sp["sources"].([]any) {
		if src := s.(map[string]any); src["entityType"] == "file" {
			if string(tgt.files[int64(src["fileId"].(float64))].content) != "alert ip any any -> any any (msg:\"x\"; sid:1;)\n" {
				t.Error("rule file content differs")
			}
		}
	}
	if mods := tgt.mods[int64(pol["suricataPolicyID"].(float64))]; len(mods) != 1 || mods[0].(map[string]any)["comment"] != "noisy" {
		t.Errorf("rule modifiers %v", mods)
	}
	rs := tgt.yaraRules[int64(pol["yaraRulesetID"].(float64))]
	if rs == nil || len(rs["sources"].([]int64)) != 1 {
		t.Fatalf("yara ruleset %v", rs)
	}
	coll := tgt.collections[int64(pol["intelCollectionID"].(float64))]
	if coll == nil || len(coll["sources"].([]int64)) != 2 {
		t.Fatalf("intel collection %v", coll)
	}
	if string(tgt.bundleData[int64(pol["bundle.id"].(float64))]) != "\x1f\x8bBUNDLE" {
		t.Error("bundle content differs")
	}
	if pe := pol["packages.enabled"].(map[string]any); pe["pkg-a"] != true || pe["pkg-b"] != false {
		t.Errorf("packages.enabled %v", pe)
	}
	// bundle, Suricata policy, YARA source and ruleset, two file sources,
	// the collection and the sensor policy.
	if len(res.Created) != 8 {
		t.Errorf("created %+v", res.Created)
	}
}

func TestApplyRollsBack(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.failOn = "createFileCollection"
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %v", err, p.Blockers)
	}
	res, err := migrate.Apply(ctx, tgt.client, dir, m, p, migrate.ImportOptions{})
	if err == nil {
		t.Fatal("apply succeeded despite failure")
	}
	if !res.RolledBack || len(res.RollbackErrors) > 0 {
		t.Fatalf("rollback %+v", res)
	}
	if len(tgt.policies)+len(tgt.suricata)+len(tgt.bundles)+len(tgt.yaraRules)+len(tgt.yaraSources)+len(tgt.sources)+len(tgt.collections) != 0 {
		t.Fatalf("objects left behind; deleted %v", tgt.deleted)
	}
}

func TestApplyRefusesTamperedPackage(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	ctx := context.Background()
	p, _ := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(m.Bundle.File.Path)), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, tgt.client, dir, m, p, migrate.ImportOptions{}); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err %v", err)
	}
}

func TestReuseIdenticalSource(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	src := m.Collections["intel"].Sources[0]
	content, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(src.File.Path)))
	tgt.sources[5] = map[string]any{"id": int64(5), "alias": src.Alias, "name": src.Name, "type": "INTEL", "fileId": tgt.addFile(src.Name, content)}
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil || !p.Ready() || len(p.Reuses) != 1 || p.Reuses[0].ID != 5 {
		t.Fatalf("plan %v %+v %v", err, p.Reuses, p.Blockers)
	}
	tgt.files[tgt.sources[5]["fileId"].(int64)] = fakeFileFor(src.Name, "different")
	p, _ = migrate.BuildPlan(context.Background(), tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if p.Ready() {
		t.Fatal("different content with the same alias/name was not blocked")
	}
}

func fakeFileFor(name, content string) fakeFile {
	return fakeFile{name: name, content: []byte(content)}
}

func TestUnknownSuricataSettingsReported(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %v", err, p.Blockers)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "suricata.profiling.enable") {
		t.Errorf("unknown Suricata setting not warned: %v", p.Warnings)
	}
	res, err := migrate.Apply(ctx, tgt.client, dir, m, p, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verification) > 0 {
		t.Errorf("verification: %v", res.Verification)
	}
	for _, sp := range tgt.suricata {
		settings := sp["settings"].(map[string]any)
		if _, sent := settings["suricata.profiling.enable"]; sent {
			t.Error("unknown setting was sent")
		}
		if settings["suricata.address_groups.dns_servers"] != "[10.0.0.53]" {
			t.Errorf("settings %v", settings)
		}
	}
}

func TestDeferAndCompleteExporters(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	hec := tgt.exporters
	tgt.exporters = map[string]any{} // no sensor attached yet
	ctx := context.Background()

	// Continue without the exporters.
	opts := migrate.ImportOptions{Exclude: []string{"exporters"}}
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, opts)
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %v %v", err, p.Blockers, p.Decisions)
	}
	res, err := migrate.Apply(ctx, tgt.client, dir, m, p, opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tgt.policies[res.PolicyID]["configuration"].(map[string]any)
	if _, ok := cfg["bro.exporters.instances"]; ok {
		t.Fatal("exporters sent although excluded")
	}
	recs, _ := migrate.ReadImports(dir)
	if len(recs) != 1 || recs[0].PolicyID != res.PolicyID || strings.Join(recs[0].Deferred, ",") != "exporters" {
		t.Fatalf("records %+v", recs)
	}
	if s, _ := migrate.ReadSecrets(dir); s["bro.exporters.abcdefghij.hec_token"] == "" {
		t.Fatal("the deferred exporter's token was dropped before completion")
	}

	complete := migrate.ImportOptions{Complete: true}
	// Still no sensor: completion is blocked.
	p, err = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, complete)
	if err != nil || p.Ready() || !strings.Contains(strings.Join(p.Blockers, " "), "attach a sensor") {
		t.Fatalf("completion without exporter types: %v %v", err, p.Blockers)
	}

	// A sensor is attached: the exporter types appear.
	tgt.exporters = hec
	p, err = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, complete)
	if err != nil || !p.Ready() || len(p.Creates) != 1 || p.Creates[0].Name != "Splunk (hec)" {
		t.Fatalf("completion plan: %v %v %+v", err, p.Blockers, p.Creates)
	}
	if p.PolicyName != "lab-policy" {
		t.Errorf("policy name %q", p.PolicyName)
	}
	res2, err := migrate.Apply(ctx, tgt.client, dir, m, p, complete)
	if err != nil || len(res2.Verification) > 0 || res2.PolicyID != res.PolicyID {
		t.Fatalf("completion: %v %+v", err, res2)
	}
	if len(tgt.policies) != 1 {
		t.Fatal("completion created a policy")
	}
	cfg = tgt.policies[res.PolicyID]["configuration"].(map[string]any)
	if cfg["bro.exporters.instances"] != "abcdefghij" || cfg["bro.exporters.abcdefghij.type"] != "hec" || cfg["bro.analyzers.mqtt.enable"] != true {
		t.Fatalf("configuration %v", cfg)
	}
	if cfg["bro.exporters.abcdefghij.hec_token"] != "TOKEN-123" {
		t.Error("exporter token not sent on completion")
	}
	for _, o := range res2.FollowUp {
		if strings.Contains(o.Item, "hec_token") {
			t.Errorf("token follow-up kept although the token was sent: %+v", o)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, migrate.SecretsFile)); !os.IsNotExist(err) {
		t.Error("secrets file kept after completion")
	}
	recs, _ = migrate.ReadImports(dir)
	if len(recs) != 1 || len(recs[0].Deferred) != 0 || recs[0].CompletedAt == nil {
		t.Fatalf("records after completion %+v", recs)
	}
	if _, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, complete); err == nil || !strings.Contains(err.Error(), "nothing to complete") {
		t.Errorf("second completion: %v", err)
	}
	if _, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{Complete: true, NameSuffix: "x"}); err == nil {
		t.Error("complete with name_suffix accepted")
	}
}

func TestExporterTokenQuestion(t *testing.T) {
	dir, m := exportPackage(t, false)
	if err := migrate.RemoveSecrets(dir); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeFM(t, "29.2.2-100")
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() || len(p.Decisions) != 1 || p.Decisions[0].ID != "exporter_tokens" || !strings.Contains(p.Decisions[0].Question, "Splunk (hec) hec_token") {
		t.Fatalf("decisions %+v blockers %v", p.Decisions, p.Blockers)
	}
	for _, ts := range p.Tokens {
		if ts.Provided {
			t.Errorf("token marked provided: %+v", ts)
		}
	}
	p, _ = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{ExporterTokens: "prompt"})
	if p.Ready() || !strings.Contains(strings.Join(p.Blockers, " "), "fleet-mcp policy tokens pkg") {
		t.Fatalf("prompt: %v", p.Blockers)
	}
	if _, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{ExporterTokens: "carrier-pigeon"}); err == nil {
		t.Error("bad exporter_tokens accepted")
	}
	// The user enters them; the plan is ready and never shows the values.
	if err := migrate.AddSecrets(dir, testSecrets); err != nil {
		t.Fatal(err)
	}
	p, err = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{ExporterTokens: "prompt"})
	if err != nil || !p.Ready() {
		t.Fatalf("after tokens: %v %v %v", err, p.Blockers, p.Decisions)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "TOKEN-123") || strings.Contains(string(b), "KMS-456") {
		t.Fatal("plan output contains a secret value")
	}
}

// fakeRunner answers the database query like sqlite3 -json.
type fakeRunner struct{ script string }

func (f *fakeRunner) Name() string { return "fm-host" }
func (f *fakeRunner) Run(_ context.Context, script string, _ ...string) (*host.Result, error) {
	f.script = script
	return &host.Result{Stdout: `[{"Key":"bro.exporters.abcdefghij.hec_token","Value":"TOKEN-123"}]`}, nil
}

func TestReadDatabaseSecrets(t *testing.T) {
	r := &fakeRunner{}
	got, err := migrate.ReadDatabaseSecrets(context.Background(), r, 17, []string{"bro.exporters.abcdefghij.hec_token"})
	if err != nil || got["bro.exporters.abcdefghij.hec_token"] != "TOKEN-123" {
		t.Fatalf("%v %v", got, err)
	}
	if !strings.Contains(r.script, "mode=ro") || !strings.Contains(r.script, "ParentID = 17") {
		t.Errorf("script %s", r.script)
	}
	if _, err := migrate.ReadDatabaseSecrets(context.Background(), r, 17, []string{"x'; DROP TABLE Policy; --"}); err == nil {
		t.Error("unsafe key accepted")
	}
}

func TestSecretsFromOlderManifest(t *testing.T) {
	m := &migrate.Manifest{
		Policy: migrate.Policy{Configuration: map[string]any{
			"bro.exporters.q1w2e3r4t5.name": "Splunk Enterprise", "bro.exporters.q1w2e3r4t5.type": "hec",
		}},
		// Recorded before omissions carried their setting key.
		Omitted: []migrate.Omission{{Part: "exporters", Item: "Splunk Enterprise (hec) hec_token"}, {Part: "input", Item: "CRWD/x"}},
	}
	s := m.Secrets()
	if len(s) != 1 || s[0].Key != "bro.exporters.q1w2e3r4t5.hec_token" {
		t.Fatalf("secrets %+v", s)
	}
}

// importOnce imports the package into tgt and returns the result.
func importOnce(t *testing.T, tgt *fakeFM, dir string, m *migrate.Manifest, opts migrate.ImportOptions) *migrate.Result {
	t.Helper()
	if err := migrate.AddSecrets(dir, testSecrets); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, opts)
	if err != nil || !p.Ready() {
		t.Fatalf("plan: %v %v %+v", err, p.Blockers, p.Decisions)
	}
	res, err := migrate.Apply(ctx, tgt.client, dir, m, p, opts)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return res
}

func TestConflicts(t *testing.T) {
	dir, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	first := importOnce(t, tgt, dir, m, migrate.ImportOptions{})
	pol := tgt.policies[first.PolicyID]
	surID := int64(pol["suricataPolicyID"].(float64))
	bundleID := int64(pol["bundle.id"].(float64))
	// Someone changes the Suricata policy on the target.
	tgt.suricata[surID]["homeNet"] = "[172.16.0.0/12]"

	if err := migrate.AddSecrets(dir, testSecrets); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, d := range p.Decisions {
		ids[d.ID] = d.Question
	}
	surQ, ok := ids["conflict:suricata policy:lab-suricata"]
	if !ok || !strings.Contains(surQ, "HOME_NET differs") {
		t.Fatalf("no Suricata conflict question: %+v", p.Decisions)
	}
	if _, ok := ids["conflict:sensor policy:lab-policy"]; !ok {
		t.Fatalf("no sensor policy question: %+v", p.Decisions)
	}
	// Identical objects are reused without a question.
	for _, k := range []string{"conflict:bundle:lab.bundle", "conflict:YARA ruleset:lab-ruleset", "conflict:collection:lab-intel"} {
		if _, asked := ids[k]; asked {
			t.Errorf("asked about identical %s", k)
		}
	}
	if p.Ready() {
		t.Fatal("ready with open questions")
	}

	// Keep the target's Suricata policy; import the sensor policy renamed.
	opts := migrate.ImportOptions{Resolve: map[string]string{
		"conflict:suricata policy:lab-suricata": migrate.UseExisting,
		"conflict:sensor policy:lab-policy":     migrate.Rename,
	}}
	nPolicies, nSur, nBundles := len(tgt.policies), len(tgt.suricata), len(tgt.bundles)
	res := importOnce(t, tgt, dir, m, opts)
	np := tgt.policies[res.PolicyID]
	if np["name"] != "lab-policy (from src)" || len(tgt.policies) != nPolicies+1 {
		t.Fatalf("renamed policy %v", np)
	}
	if int64(np["suricataPolicyID"].(float64)) != surID || int64(np["bundle.id"].(float64)) != bundleID {
		t.Errorf("existing objects not linked: %v", np)
	}
	if len(tgt.suricata) != nSur || len(tgt.bundles) != nBundles {
		t.Error("an existing object was created again")
	}
	if tgt.suricata[surID]["homeNet"] != "[172.16.0.0/12]" {
		t.Error("the existing Suricata policy was changed")
	}

	// update_existing changes the existing sensor policy in place.
	tgt.policies[first.PolicyID]["configuration"].(map[string]any)["bro.export.splunk.index"] = "changed"
	opts.Resolve["conflict:sensor policy:lab-policy"] = migrate.UpdateExisting
	res = importOnce(t, tgt, dir, m, opts)
	if res.PolicyID != first.PolicyID || len(tgt.policies) != nPolicies+1 {
		t.Fatalf("update_existing created a policy: %d", res.PolicyID)
	}
	if tgt.policies[first.PolicyID]["configuration"].(map[string]any)["bro.export.splunk.index"] != "corelight" {
		t.Error("existing policy not updated")
	}

	// A bad answer blocks.
	opts.Resolve["conflict:sensor policy:lab-policy"] = "shrug"
	if err := migrate.AddSecrets(dir, testSecrets); err != nil {
		t.Fatal(err)
	}
	p, _ = migrate.BuildPlan(ctx, tgt.client, "tgt", dir, m, opts)
	if p.Ready() {
		t.Error("bad answer accepted")
	}
}

func TestCorelightUpdateWarning(t *testing.T) {
	dir, m := exportPackage(t, false)
	m.Suricata.Sources[0].Name = "Corelight-update"
	m.Collections["intel"].Sources[0].Description = "Created by Corelight Update"
	tgt := newFakeFM(t, "29.2.2-100")
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", dir, m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "2 copied items were pushed by Corelight-update") {
		t.Errorf("warnings %v", p.Warnings)
	}
	n := 0
	for _, o := range p.FollowUp {
		if strings.Contains(o.Reason, "Corelight-update") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("follow-up items %+v", p.FollowUp)
	}
}
