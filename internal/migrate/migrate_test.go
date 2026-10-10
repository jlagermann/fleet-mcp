package migrate_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/migrate"
)

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
	_, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.3.0-1")
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready() || !strings.Contains(strings.Join(p.Blockers, "\n"), "version mismatch") {
		t.Fatalf("blockers %v", p.Blockers)
	}
}

func TestPlanPatchVersionsMatch(t *testing.T) {
	_, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.5-7")
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", m, migrate.ImportOptions{})
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
	_, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.sensors = []any{licensedSensor("yara")}
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Unlicensed sensors are reported but neither block nor warn.
	if !p.Ready() || strings.Contains(strings.Join(p.Warnings, " "), "licens") || p.Licenses[0].Status != "unlicensed" {
		t.Fatalf("unlicensed: %v %v %+v", p.Blockers, p.Warnings, p.Licenses)
	}
	tgt.sensors = []any{licensedSensor("suricata"), licensedSensor()}
	p, _ = migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
	if !p.Ready() || p.Licenses[0].Status != "partial" || p.Licenses[0].Licensed != 1 {
		t.Fatalf("partial: %v %+v", p.Blockers, p.Licenses)
	}
}

func TestPlanExportersAndSettings(t *testing.T) {
	_, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.exporters = map[string]any{}
	delete(tgt.props, "bro.export.splunk.index")
	ctx := context.Background()
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := strings.Join(p.Blockers, "\n")
	if !strings.Contains(b, "no hec exporter") || !strings.Contains(b, "bro.export.splunk.index") {
		t.Fatalf("blockers %v", p.Blockers)
	}
	tgt.props["bro.export.splunk.index"] = map[string]any{"cl:type": "Text"}
	p, err = migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{Exclude: []string{"exporters"}})
	if err != nil || !p.Ready() {
		t.Fatalf("exclude exporters: %v %v", err, p.Blockers)
	}
	for _, o := range p.FollowUp {
		if strings.Contains(o.Item, "hec_token") {
			t.Errorf("token follow-up kept although the exporter is excluded: %+v", o)
		}
	}
	found := false
	for _, o := range p.FollowUp {
		found = found || (o.Part == "exporters" && strings.Contains(o.Item, "Splunk"))
	}
	if !found {
		t.Errorf("excluded exporter not listed for follow-up: %+v", p.FollowUp)
	}
	if _, err := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{Exclude: []string{"nope"}}); err == nil {
		t.Error("unknown part accepted")
	}
}

func TestPlanNameClash(t *testing.T) {
	_, m := exportPackage(t, false)
	tgt := newFakeFM(t, "29.2.2-100")
	tgt.policies[1] = map[string]any{"id": 1, "name": "lab-policy"}
	ctx := context.Background()
	p, _ := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
	if p.Ready() {
		t.Fatal("name clash not blocked")
	}
	p, _ = migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{NameSuffix: "-copy"})
	if !p.Ready() || p.PolicyName != "lab-policy-copy" {
		t.Fatalf("suffix: %v %s", p.Blockers, p.PolicyName)
	}
}

func TestApplyCopiesEverything(t *testing.T) {
	dir, m := exportPackage(t, true)
	tgt := newFakeFM(t, "29.2.2-100")
	ctx := context.Background()
	opts := migrate.ImportOptions{Name: "copied"}
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", m, opts)
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
	if _, ok := cfg["bro.exporters.abcdefghij.hec_token"]; ok {
		t.Error("secret placeholder sent to the target")
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
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
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
	p, _ := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
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
	p, err := migrate.BuildPlan(context.Background(), tgt.client, "tgt", m, migrate.ImportOptions{})
	if err != nil || !p.Ready() || len(p.Reuses) != 1 || p.Reuses[0].ID != 5 {
		t.Fatalf("plan %v %+v %v", err, p.Reuses, p.Blockers)
	}
	tgt.files[tgt.sources[5]["fileId"].(int64)] = fakeFileFor(src.Name, "different")
	p, _ = migrate.BuildPlan(context.Background(), tgt.client, "tgt", m, migrate.ImportOptions{})
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
	p, err := migrate.BuildPlan(ctx, tgt.client, "tgt", m, migrate.ImportOptions{})
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
