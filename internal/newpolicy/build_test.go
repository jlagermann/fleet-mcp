package newpolicy

import (
	"strings"
	"testing"
)

// props makes a settings schema that knows every package and setting.
func props() map[string]any {
	p := map[string]any{}
	for _, pk := range Packages {
		p[pk.Key] = map[string]any{}
	}
	for _, k := range []string{"security.ssh.enable", "security.ssh.networks", "security.http.enable", "security.http.networks",
		"corelight.ml.enable", "bro.pkgs.corelight.ml_package.loaded", "corelight.anomaly_detection.enable",
		"bro.site.local_nets", "bro.site.ignore_bpf", "network.management.ntp.server", "network.management.syslog.server",
		"network.management.proxy.server", "network.management.proxy.username", "network.management.proxy.password",
		"bro.export.s3.log.enable", "bro.export.s3.log.bucket", "bro.export.s3.region", "bro.export.s3.access_key", "bro.export.s3.secret_access_key",
		"bro.export.logs.enable", "bro.export.sftp.log.server", "bro.export.sftp.log.user",
		"metrics.bro.enable", "fleet.updates.enable", "updates.no_impact", "updates.service_restart", "updates.visible_change", "updates.reboot", "updates.all",
		"suricata.enable", "corelight.yara.enable"} {
		p[k] = map[string]any{}
	}
	return p
}

var hec = map[string]any{"hec": map[string]any{"elements": []any{
	map[string]any{"fieldProperties": map[string]any{"fieldName": "hec_endpoint", "validators": []any{map[string]any{"type": "required"}}}},
	map[string]any{"fieldProperties": map[string]any{"fieldName": "hec_token", "noLog": true}},
	map[string]any{"fieldProperties": map[string]any{"fieldName": "hec_index"}},
	map[string]any{"fieldProperties": map[string]any{"fieldName": "hec_fields", "defaultValue": "", "validators": []any{map[string]any{"type": "required"}}}},
}}}

func TestDefaults(t *testing.T) {
	b := Build(Spec{Name: "edge", Profile: NorthSouth}, props(), nil)
	if len(b.Errors) > 0 {
		t.Fatal(b.Errors)
	}
	c := b.Configuration
	for _, k := range []string{"security.ssh.enable", "security.http.enable", "corelight.ml.enable", "bro.pkgs.corelight.ml_package.loaded", "corelight.anomaly_detection.enable"} {
		if c[k] != true {
			t.Errorf("%s = %v, want true by default", k, c[k])
		}
	}
	// North-south: SMTP Links and Sliver yes, MAC Addresses and BZAR no,
	// ICS/OT never.
	for k, want := range map[string]bool{"smtp_links": true, "sliver": true, "mac_logging": false, "bzar": false, "zeek_plugin_modbus": false, "corelight_shunting": false} {
		if got := c["bro.pkgs.corelight."+k+".loaded"] == true; got != want {
			t.Errorf("%s enabled = %v, want %v", k, got, want)
		}
	}
	if !strings.Contains(strings.Join(b.Warnings, " "), "32 GB RAM") {
		t.Errorf("no resource warning: %v", b.Warnings)
	}
	if !strings.Contains(strings.Join(b.Defaults, " "), "local network blocks") {
		t.Errorf("defaults %v", b.Defaults)
	}
	// Turning them off is shown too.
	off := false
	b = Build(Spec{Name: "edge", Profile: EastWest, SSH: &off, MachineLearning: &off, AnomalyDetection: &off}, props(), nil)
	if b.Configuration["security.ssh.enable"] != false || b.Configuration["corelight.ml.enable"] != false || b.Configuration["bro.pkgs.corelight.mac_logging.loaded"] != true {
		t.Errorf("config %v", b.Configuration)
	}
}

func TestAddRemoveAndUnavailable(t *testing.T) {
	p := props()
	delete(p, "bro.pkgs.corelight.ja3.loaded") // an older target
	b := Build(Spec{Name: "x", Profile: NorthSouth, AddPackages: []string{"modbus", "Stepping Stones"}, RemovePackages: []string{"sliver"}}, p, nil)
	c := b.Configuration
	if c["bro.pkgs.corelight.zeek_plugin_modbus.loaded"] != true || c["bro.pkgs.corelight.stepping_stones.loaded"] != true {
		t.Error("added packages missing")
	}
	if _, on := c["bro.pkgs.corelight.sliver.loaded"]; on {
		t.Error("removed package enabled")
	}
	if !strings.Contains(strings.Join(b.Unavailable, ","), "JA3") {
		t.Errorf("unavailable %v", b.Unavailable)
	}
	b = Build(Spec{Name: "x", Profile: "sideways", AddPackages: []string{"nope"}}, p, nil)
	if len(b.Errors) != 2 {
		t.Errorf("errors %v", b.Errors)
	}
}

func TestExportsSecretsAndUpdates(t *testing.T) {
	s := Spec{Name: "x", Profile: NoProfile,
		ProxyServer: "http://proxy:3128", ProxyUsername: "u",
		BatchExport: &BatchExport{Type: "s3", Bucket: "logs", AccessKey: "AKIA"},
		Exporters:   []Exporter{{Type: "hec", Name: "Splunk", Settings: map[string]any{"hec_endpoint": "https://splunk:8088"}}},
		Updates:     &Updates{ViaFleet: true, Apply: "service_restart"},
	}
	b := Build(s, props(), hec)
	if len(b.Errors) > 0 {
		t.Fatal(b.Errors)
	}
	got := b.SecretSettings()
	if got["network.management.proxy.password"] != "network.management.proxy.password" || got["bro.export.s3.secret_access_key"] == "" {
		t.Errorf("secrets %v", got)
	}
	tok := got[ExporterSecretKey("Splunk", "hec_token")]
	if !strings.HasPrefix(tok, "bro.exporters.") || !strings.HasSuffix(tok, ".hec_token") {
		t.Errorf("exporter secret target %q", tok)
	}
	if !hasPrefixKeyValue(b.Configuration, ".hec_fields", "") {
		t.Error("required field with a default not filled")
	}
	c := b.Configuration
	if c["updates.no_impact"] != true || c["updates.service_restart"] != true || c["updates.reboot"] != nil || c["fleet.updates.enable"] != true {
		t.Errorf("updates %v", c)
	}
	// Missing a required exporter field, a secret given in the clear, an
	// unknown exporter type.
	b = Build(Spec{Name: "x", Profile: NoProfile, Exporters: []Exporter{
		{Type: "hec", Name: "A", Settings: map[string]any{"hec_token": "leak"}},
		{Type: "kafka", Name: "B"},
	}}, props(), hec)
	e := strings.Join(b.Errors, "\n")
	for _, want := range []string{"needs field hec_endpoint", "hec_token is a secret", "no kafka exporter"} {
		if !strings.Contains(e, want) {
			t.Errorf("errors lack %q:\n%s", want, e)
		}
	}
}

func TestEveryPackageKeyOnce(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Packages {
		if seen[p.Key] {
			t.Errorf("duplicate %s", p.Key)
		}
		seen[p.Key] = true
		if p.Why == "" || p.Source == "" {
			t.Errorf("%s lacks a reason or source", p.Key)
		}
	}
}

func hasPrefixKeyValue(m map[string]any, suffix string, want any) bool {
	for k, v := range m {
		if strings.HasSuffix(k, suffix) && v == want {
			return true
		}
	}
	return false
}
