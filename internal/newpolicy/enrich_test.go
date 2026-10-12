package newpolicy

import (
	"strings"
	"testing"
)

func TestCheckEnrichment(t *testing.T) {
	src := func(alias, file string, extra ...any) map[string]any {
		m := map[string]any{"alias": alias, "name": file, "enabled": true, "fileId": 1.0}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i].(string)] = extra[i+1]
		}
		return m
	}
	input := map[string]any{"name": "lab", "sources": []any{
		src("a", "cert-hygiene-server-wl.txt"),
		src("b", "datared-http-uri-wl.txt"),
		src("Tenable hosts", "hosts_data.tsv", "connector", map[string]any{"name": "tenable"}),
		src("d", "dns_bypass_authorized.tsv"),
		src("e", "custom.tsv", "enabled", false),
		src("f", "cve_data.tsv", "processingError", "401 Unauthorized"),
		src("g", "my_allow.tsv"),
	}}
	// Cert Hygiene is on in north-south, Data Reduction is not. The user
	// says a custom package reads my_allow.tsv.
	b := Build(Spec{Name: "x", Profile: NorthSouth}, props(), nil)
	p := &Plan{Built: b, Spec: Spec{InputReaders: map[string]string{"my_allow.tsv": "my-allowlist"}},
		BundlePackages: []string{":home:james:my-allowlist"}}
	p.checkEnrichment("input", input)
	q := strings.Join(p.Questions, "\n")
	for _, want := range []string{
		"Which package reads datared-http-uri-wl.txt", "usually Data Reduction", "can stop using an input file",
		"Which package reads hosts_data.tsv", "endpoint enrichment package",
		"Which packages read dns_bypass_authorized.tsv", // unknown to fleet-mcp: a custom package
	} {
		if !strings.Contains(q, want) {
			t.Errorf("questions lack %q:\n%s", want, q)
		}
	}
	w := strings.Join(b.Warnings, "\n")
	for _, want := range []string{"source e is disabled", "source f failed to fetch: 401"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if strings.Contains(q+w, "cert-hygiene") || strings.Contains(q+w, "my_allow") {
		t.Errorf("a file with an enabled reader was asked about:\n%s\n%s", q, w)
	}
	c := p.Enrichments[0]
	if c.Sources[0].ReadBy != "Cert Hygiene" || c.Sources[2].Connector != "tenable" || !strings.Contains(c.Sources[6].ReadBy, "as the user said") {
		t.Errorf("check %+v", c)
	}

	// A named reader that is not enabled is warned about.
	p = &Plan{Built: Build(Spec{Name: "x", Profile: NoProfile}, props(), nil), Spec: Spec{InputReaders: map[string]string{"my_allow.tsv": "my-allowlist"}}}
	p.checkEnrichment("input", map[string]any{"name": "lab", "sources": []any{src("g", "my_allow.tsv")}})
	if !strings.Contains(strings.Join(p.Built.Warnings, "\n"), "not among this policy's enabled packages") {
		t.Errorf("unenabled named reader: %v", p.Built.Warnings)
	}

	// icannTLD needs its four files; endpoint enrichment needs host or CVE data.
	p = &Plan{Built: Build(Spec{Name: "x", Profile: NoProfile}, props(), nil),
		BundlePackages: []string{"https:github.com:corelight:icannTLD", "https:github.com:corelight:Zeek-Endpoint-Enrichment"}}
	p.checkPackageInputs(map[string]any{"sources": []any{src("i1", "1st_level_public_icann.dat"), src("i2", "2nd_level_public_icann.dat")}})
	w = strings.Join(p.Built.Warnings, "\n")
	if !strings.Contains(w, "missing: 3rd_level_public_icann.dat, 4th_level_public_icann.dat") || !strings.Contains(w, "has none of hosts_data.tsv, cve_data.tsv") {
		t.Errorf("package inputs:\n%s", w)
	}
	p.checkEnrichment("input", map[string]any{"name": "lab", "sources": []any{src("t", "trusted_domains.dat"), src("i3", "3rd_level_public_icann.dat")}})
	if len(p.Questions) > 0 {
		t.Errorf("icannTLD files asked about although icannTLD is enabled: %v", p.Questions)
	}

	// Intel above the indicator limit.
	p = &Plan{Built: Build(Spec{Name: "x", Profile: NoProfile}, props(), nil)}
	p.checkEnrichment("intel", map[string]any{"name": "ti", "sources": []any{
		src("feed", "bro_intel.dat", "metadata", map[string]any{"numberOfIndicators": 150000.0}),
	}})
	if !strings.Contains(strings.Join(p.Built.Warnings, "\n"), "150000 indicators") {
		t.Errorf("indicator limit: %v", p.Built.Warnings)
	}
}
