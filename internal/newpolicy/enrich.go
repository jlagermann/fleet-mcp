package newpolicy

import (
	"fmt"
	"strconv"
	"strings"
)

// Connector-fed enrichments work only when the whole chain is in place
// (Fleet Manager docs, Connectors): a connector (authentication) feeds a
// source (one file), sources are grouped in a collection, the collection is
// linked to the sensor policy, and - for input files - a Zeek package in
// the same policy reads the file. Without that package the file reaches
// the sensor and nothing uses it. Intel files are read by the Zeek intel
// framework itself; asset classification needs asset_classification.enable.

// EnrichmentCheck is the preview of one linked collection.
type EnrichmentCheck struct {
	Kind       string         `json:"kind"` // input, intel or asset classification
	Collection string         `json:"collection"`
	Sources    []SourceStatus `json:"sources"`
	Notes      []string       `json:"notes,omitempty"`
}

// SourceStatus is one source of a linked collection.
type SourceStatus struct {
	Alias     string `json:"alias"`
	File      string `json:"file"`
	Connector string `json:"connector,omitempty"` // empty: an uploaded file
	Status    string `json:"status"`
	ReadBy    string `json:"read_by,omitempty"`
}

// inputReader names the package that reads an input file: a Corelight
// package key, or a word that a custom bundle package's name contains.
type inputReader struct {
	name   string
	key    string // bro.pkgs.corelight.<key>.loaded
	bundle []string
}

// inputReaders maps input file names (or name prefixes ending in "-") to
// the package that reads them, from the sensor docs ("Zeek packages that
// support input files") and the connector docs (host and CVE data for the
// endpoint enrichment packages).
var inputReaders = map[string]inputReader{
	"cert-hygiene-server-wl.txt":         {name: "Cert Hygiene", key: "cert_hygiene"},
	"cert-hygiene-sni-wl.txt":            {name: "Cert Hygiene", key: "cert_hygiene"},
	"datared-":                           {name: "Data Reduction", key: "datared"},
	"encryption-detection-server-wl.txt": {name: "Encryption Detection", key: "encryption_detection"},
	"rdp-inference-server-wl.txt":        {name: "RDP Inference", key: "rdp_inference"},
	"stepping-stone-server-wl.txt":       {name: "Stepping Stones", key: "stepping_stones"},
	"hosts_data.tsv":                     {name: "an endpoint enrichment package (custom bundle)", bundle: []string{"endpoint-enrichment"}},
	"cve_data.tsv":                       {name: "an endpoint or CVE enrichment package (custom bundle)", bundle: []string{"endpoint-enrichment", "cve-enrichment"}},
}

func readerFor(file string) (inputReader, bool) {
	if r, ok := inputReaders[file]; ok {
		return r, true
	}
	for prefix, r := range inputReaders {
		if strings.HasSuffix(prefix, "-") && strings.HasPrefix(file, prefix) {
			return r, true
		}
	}
	return inputReader{}, false
}

// enabledReader returns the enabled package that reads file, if any.
func (p *Plan) enabledReader(r inputReader) string {
	if r.key != "" && p.Built.Configuration["bro.pkgs.corelight."+r.key+".loaded"] == true {
		return r.name
	}
	for _, bp := range p.BundlePackages {
		for _, w := range r.bundle {
			if strings.Contains(strings.ToLower(bp), w) {
				return bp
			}
		}
	}
	return ""
}

// checkEnrichment follows a linked collection down to its sources and the
// packages that read them, and records warnings for broken links.
func (p *Plan) checkEnrichment(kind string, coll map[string]any) {
	c := EnrichmentCheck{Kind: kind, Collection: str(coll["name"])}
	warn := func(format string, a ...any) {
		p.Built.Warnings = append(p.Built.Warnings, fmt.Sprintf("%s collection %s: ", kind, c.Collection)+fmt.Sprintf(format, a...))
	}
	sources, _ := coll["sources"].([]any)
	if len(sources) == 0 {
		warn("it has no sources, so nothing is sent to the sensors")
	}
	indicators := 0
	var unknown []string // input files with no known reader
	defer func() {
		if len(unknown) > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("fleet-mcp does not know which package reads %s: make sure a package in this policy (usually from the custom bundle) does", strings.Join(unknown, ", ")))
		}
		p.Enrichments = append(p.Enrichments, c)
	}()
	for _, el := range sources {
		s := obj(el)
		st := SourceStatus{Alias: str(s["alias"]), File: str(s["name"]), Connector: str(obj(s["connector"])["name"])}
		switch {
		case s["enabled"] == false:
			st.Status = "disabled"
			warn("source %s is disabled", st.Alias)
		case str(s["processingError"]) != "":
			st.Status = "error: " + str(s["processingError"])
			warn("source %s failed to fetch: %s (check its connector)", st.Alias, str(s["processingError"]))
		case s["isProcessing"] == true:
			st.Status = "fetching"
		case s["fileId"] == nil:
			st.Status = "no file yet"
			warn("source %s has no file yet", st.Alias)
		default:
			st.Status = "ready"
		}
		indicators += int(idOf(obj(s["metadata"])["numberOfIndicators"]))
		if kind == "input" {
			if r, known := readerFor(st.File); known {
				if st.ReadBy = p.enabledReader(r); st.ReadBy == "" {
					warn("nothing in this policy reads %s (source %s): enable %s, or the file reaches the sensors and nothing uses it", st.File, st.Alias, r.name)
				}
			} else {
				unknown = append(unknown, st.File)
			}
		}
		c.Sources = append(c.Sources, st)
	}
	switch kind {
	case "intel":
		c.Notes = append(c.Notes, "intel files are read by the Zeek intel framework itself; the ExtendIntel package (custom bundle) adds the intel metadata to the logs")
		limit := 100000
		if v, ok := p.Spec.Settings["bro.intel.max_indicators"]; ok {
			if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
				limit = n
			}
		}
		if indicators > limit {
			warn("its sources hold %d indicators, more than the sensor's limit of %d (bro.intel.max_indicators)", indicators, limit)
		}
	case "asset classification":
		c.Notes = append(c.Notes, "asset_classification.enable is turned on with it (Early Access; appliances that meet the requirements, with an asset classification license)")
	}
}

// checkEndpointEnrichment warns when an endpoint enrichment package is
// enabled but no linked input collection gives it host data.
func (p *Plan) checkEndpointEnrichment(input map[string]any) {
	for _, bp := range p.BundlePackages {
		if !strings.Contains(strings.ToLower(bp), "endpoint-enrichment") {
			continue
		}
		found := false
		for _, el := range anySlice(input["sources"]) {
			if f := str(obj(el)["name"]); f == "hosts_data.tsv" || f == "cve_data.tsv" {
				found = true
			}
		}
		if !found {
			p.Built.Warnings = append(p.Built.Warnings, fmt.Sprintf("package %s is enabled but no linked input collection has hosts_data.tsv or cve_data.tsv, so it has no data: set up a connector, an input source and an input collection for it", bp))
		}
	}
}

func anySlice(v any) []any {
	s, _ := v.([]any)
	return s
}
