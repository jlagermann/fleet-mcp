package newpolicy

import (
	"strings"
	"testing"
)

func TestCheckEnrichment(t *testing.T) {
	b := Build(Spec{Name: "x", Profile: NorthSouth}, props(), nil) // Cert Hygiene on, Data Reduction off
	p := &Plan{Built: b, BundlePackages: []string{":home:james:ExtendIntel"}}
	input := map[string]any{"name": "lab", "sources": []any{
		map[string]any{"alias": "a", "name": "cert-hygiene-server-wl.txt", "enabled": true, "fileId": 1.0},
		map[string]any{"alias": "b", "name": "datared-http-uri-wl.txt", "enabled": true, "fileId": 2.0},
		map[string]any{"alias": "Tenable hosts", "name": "hosts_data.tsv", "enabled": true, "fileId": 3.0, "connector": map[string]any{"name": "tenable"}},
		map[string]any{"alias": "d", "name": "custom.tsv", "enabled": false},
		map[string]any{"alias": "e", "name": "cve_data.tsv", "enabled": true, "processingError": "401 Unauthorized"},
	}}
	p.checkEnrichment("input", input)
	w := strings.Join(b.Warnings, "\n")
	for _, want := range []string{
		"nothing in this policy reads datared-http-uri-wl.txt", "enable Data Reduction",
		"nothing in this policy reads hosts_data.tsv", "source d is disabled", "source e failed to fetch: 401",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "cert-hygiene") {
		t.Errorf("Cert Hygiene is on, yet warned:\n%s", w)
	}
	c := p.Enrichments[0]
	if c.Sources[0].ReadBy != "Cert Hygiene" || c.Sources[2].Connector != "tenable" || !strings.Contains(strings.Join(c.Notes, " "), "custom.tsv") {
		t.Errorf("check %+v", c)
	}

	// An endpoint enrichment package in the bundle reads hosts_data.tsv;
	// without host data it warns the other way round.
	p = &Plan{Built: Build(Spec{Name: "x", Profile: NoProfile}, props(), nil), BundlePackages: []string{"https:github.com:corelight:Zeek-Endpoint-Enrichment"}}
	p.checkEnrichment("input", input)
	if strings.Contains(strings.Join(p.Built.Warnings, "\n"), "reads hosts_data.tsv") {
		t.Error("the bundle's endpoint enrichment package was not seen as the reader")
	}
	p.checkEndpointEnrichment(map[string]any{"sources": []any{}})
	if !strings.Contains(strings.Join(p.Built.Warnings, "\n"), "has no data") {
		t.Error("endpoint enrichment without host data not warned")
	}

	// Intel above the indicator limit.
	p = &Plan{Built: Build(Spec{Name: "x", Profile: NoProfile}, props(), nil)}
	p.checkEnrichment("intel", map[string]any{"name": "ti", "sources": []any{
		map[string]any{"alias": "feed", "name": "bro_intel.dat", "enabled": true, "fileId": 1.0, "metadata": map[string]any{"numberOfIndicators": 150000.0}},
	}})
	if !strings.Contains(strings.Join(p.Built.Warnings, "\n"), "150000 indicators") {
		t.Errorf("indicator limit: %v", p.Built.Warnings)
	}
}
